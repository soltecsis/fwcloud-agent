/*
    Copyright 2026 SOLTECSIS SOLUCIONES TECNOLOGICAS, SLU
    https://soltecsis.com
    info@soltecsis.com


    This file is part of FWCloud (https://fwcloud.net).

    FWCloud is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    FWCloud is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with FWCloud.  If not, see <https://www.gnu.org/licenses/>.
*/

use serde_json::Value;

use crate::{
    crowdsec::{
        command::CrowdSecCommand,
        errors::{ALERTS_INVALID, COMMAND_FAILED},
        models::{CrowdSecAlert, CrowdSecAlertsQuery, CrowdSecAlertsResponse},
    },
    errors::{FwcError, Result},
};

const DEFAULT_LIST_LIMIT: u32 = 50;
const MAXIMUM_LIST_LIMIT: u32 = 100;

pub async fn list(query: &CrowdSecAlertsQuery) -> Result<CrowdSecAlertsResponse> {
    let limit = list_limit(query.limit)?;
    let limit_argument = limit.to_string();
    let arguments = list_arguments(query, &limit_argument)?;
    let output = CrowdSecCommand::cscli(&arguments)?.execute().await?;
    let value = serde_json::from_str::<Value>(output.stdout())
        .map_err(|_| FwcError::crowdsec(COMMAND_FAILED, "Unable to read CrowdSec alert list"))?;

    Ok(CrowdSecAlertsResponse {
        alerts: alerts_from_json(&value)
            .into_iter()
            .take(limit as usize)
            .collect(),
    })
}

fn list_arguments<'a>(query: &'a CrowdSecAlertsQuery, limit: &'a str) -> Result<Vec<&'a str>> {
    validate_filters(query)?;
    let mut arguments = vec!["alerts", "list", "--limit", limit];

    append_filter(&mut arguments, "--since", query.since.as_deref());
    append_filter(&mut arguments, "--until", query.until.as_deref());
    append_filter(&mut arguments, "--scenario", query.scenario.as_deref());
    append_filter(&mut arguments, "--type", query.decision_type.as_deref());
    append_filter(&mut arguments, "--scope", query.scope.as_deref());
    append_filter(&mut arguments, "--value", query.value.as_deref());
    append_filter(&mut arguments, "--ip", query.ip.as_deref());
    append_filter(&mut arguments, "--range", query.range.as_deref());
    arguments.extend(["-o", "json"]);

    Ok(arguments)
}

fn append_filter<'a>(arguments: &mut Vec<&'a str>, option: &'a str, value: Option<&'a str>) {
    if let Some(value) = value {
        arguments.extend([option, value]);
    }
}

fn validate_filters(query: &CrowdSecAlertsQuery) -> Result<()> {
    validate_optional_duration(query.since.as_deref())?;
    validate_optional_duration(query.until.as_deref())?;
    validate_optional_scenario(query.scenario.as_deref())?;
    validate_optional_token(query.decision_type.as_deref())?;
    validate_optional_token(query.scope.as_deref())?;
    validate_optional_value(query.value.as_deref())?;
    validate_optional_value(query.ip.as_deref())?;
    validate_optional_value(query.range.as_deref())
}

fn list_limit(requested_limit: Option<u32>) -> Result<u32> {
    let limit = requested_limit.unwrap_or(DEFAULT_LIST_LIMIT);

    if (1..=MAXIMUM_LIST_LIMIT).contains(&limit) {
        Ok(limit)
    } else {
        Err(invalid_filter())
    }
}

fn validate_optional_duration(value: Option<&str>) -> Result<()> {
    if value.is_none_or(|value| {
        !value.is_empty()
            && value.len() <= 64
            && value
                .chars()
                .all(|character| character.is_ascii_alphanumeric())
    }) {
        Ok(())
    } else {
        Err(invalid_filter())
    }
}

fn validate_optional_scenario(value: Option<&str>) -> Result<()> {
    if value.is_none_or(|value| {
        !value.is_empty()
            && value.len() <= 128
            && value.chars().all(|character| {
                character.is_ascii_alphanumeric()
                    || matches!(character, ':' | '/' | '_' | '-' | '.')
            })
    }) {
        Ok(())
    } else {
        Err(invalid_filter())
    }
}

fn validate_optional_token(value: Option<&str>) -> Result<()> {
    if value.is_none_or(|value| {
        !value.is_empty()
            && value.len() <= 64
            && value.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
            })
    }) {
        Ok(())
    } else {
        Err(invalid_filter())
    }
}

fn validate_optional_value(value: Option<&str>) -> Result<()> {
    if value.is_none_or(|value| {
        !value.trim().is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
    }) {
        Ok(())
    } else {
        Err(invalid_filter())
    }
}

fn invalid_filter() -> FwcError {
    FwcError::crowdsec(ALERTS_INVALID, "Invalid CrowdSec alert filter")
}

fn alerts_from_json(value: &Value) -> Vec<CrowdSecAlert> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(alert_from_json)
        .collect()
}

fn alert_from_json(value: &Value) -> Option<CrowdSecAlert> {
    let id = value_as_string(value.get("id"))?;
    let source = value.get("source");
    let decision_type = value
        .get("decisions")
        .and_then(Value::as_array)
        .and_then(|decisions| decisions.first())
        .and_then(|decision| value_as_string(decision.get("type")));

    Some(CrowdSecAlert {
        id,
        created_at: value_as_string(value.get("created_at")),
        source_ip: first_string(&[
            source.and_then(|source| source.get("ip")),
            source.and_then(|source| source.get("value")),
        ]),
        scenario: value_as_string(value.get("scenario")),
        decision_type,
    })
}

fn first_string(values: &[Option<&Value>]) -> Option<String> {
    values.iter().find_map(|value| value_as_string(*value))
}

fn value_as_string(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{list_limit, validate_optional_duration, validate_optional_scenario};
    use crate::{crowdsec::errors::ALERTS_INVALID, errors::FwcError};

    #[test]
    fn alert_list_limit_is_bounded() {
        assert_eq!(list_limit(None).unwrap(), 50);
        assert_eq!(list_limit(Some(1)).unwrap(), 1);
        assert_eq!(list_limit(Some(100)).unwrap(), 100);

        let error = list_limit(Some(101)).unwrap_err();
        assert!(matches!(
            error,
            FwcError::CrowdSec {
                code: ALERTS_INVALID,
                ..
            }
        ));
    }

    #[test]
    fn alert_filters_reject_control_characters() {
        assert!(validate_optional_duration(Some("4h")).is_ok());
        assert!(validate_optional_duration(Some("4h\n")).is_err());
        assert!(validate_optional_scenario(Some("crowdsecurity/ssh-bf")).is_ok());
        assert!(validate_optional_scenario(Some("ssh\n-bf")).is_err());
    }
}
