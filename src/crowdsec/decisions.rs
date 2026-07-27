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
        errors::{COMMAND_FAILED, DECISIONS_CONFIRMATION_REQUIRED, DECISIONS_INVALID},
        models::{
            CrowdSecDecision, CrowdSecDecisionOperation, CrowdSecDecisionOperationResponse,
            CrowdSecDecisionsQuery, CrowdSecDecisionsResponse,
        },
    },
    errors::{FwcError, Result},
};

const DEFAULT_LIST_LIMIT: u32 = 50;
const MAXIMUM_LIST_LIMIT: u32 = 100;

pub async fn list(query: &CrowdSecDecisionsQuery) -> Result<CrowdSecDecisionsResponse> {
    let limit = list_limit(query.limit)?;
    let limit_argument = limit.to_string();
    let arguments = list_arguments(query, &limit_argument)?;
    let output = CrowdSecCommand::cscli(&arguments)?.execute().await?;
    let value = serde_json::from_str::<Value>(output.stdout())
        .map_err(|_| FwcError::crowdsec(COMMAND_FAILED, "Unable to read CrowdSec decision list"))?;

    Ok(CrowdSecDecisionsResponse {
        decisions: filter_decisions(decisions_from_json(&value), query)
            .into_iter()
            .take(limit as usize)
            .collect(),
    })
}

pub async fn delete(id: &str) -> Result<CrowdSecDecisionOperationResponse> {
    validate_decision_id(id)?;
    let deleted_count = if decision_exists(id).await? {
        execute_delete_command(&["decisions", "delete", "--id", id]).await?;
        1
    } else {
        0
    };

    Ok(CrowdSecDecisionOperationResponse {
        operation: CrowdSecDecisionOperation::Delete,
        decision_id: Some(id.to_string()),
        deleted_count,
        message: if deleted_count > 0 {
            "CrowdSec decision is deleted".to_string()
        } else {
            "CrowdSec decision was not found".to_string()
        },
    })
}

pub fn require_flush_confirmation(confirm: bool) -> Result<()> {
    if confirm {
        Ok(())
    } else {
        Err(FwcError::crowdsec(
            DECISIONS_CONFIRMATION_REQUIRED,
            "CrowdSec decision flush requires confirm: true",
        ))
    }
}

pub async fn flush() -> Result<CrowdSecDecisionOperationResponse> {
    let deleted_count = all_decisions().await?.len() as u64;
    execute_delete_command(&["decisions", "delete", "--all"]).await?;

    Ok(CrowdSecDecisionOperationResponse {
        operation: CrowdSecDecisionOperation::Flush,
        decision_id: None,
        deleted_count,
        message: "All CrowdSec decisions are deleted".to_string(),
    })
}

async fn execute_delete_command(arguments: &[&str]) -> Result<()> {
    CrowdSecCommand::cscli(arguments)?.execute().await?;
    Ok(())
}

async fn decision_exists(id: &str) -> Result<bool> {
    Ok(all_decisions()
        .await?
        .into_iter()
        .any(|decision| decision.id == id))
}

async fn all_decisions() -> Result<Vec<CrowdSecDecision>> {
    let output = CrowdSecCommand::cscli(&["decisions", "list", "--all", "-o", "json"])?
        .execute()
        .await?;
    let value = serde_json::from_str::<Value>(output.stdout())
        .map_err(|_| FwcError::crowdsec(COMMAND_FAILED, "Unable to read CrowdSec decision list"))?;

    Ok(decisions_from_json(&value))
}

fn list_arguments<'a>(query: &'a CrowdSecDecisionsQuery, limit: &'a str) -> Result<Vec<&'a str>> {
    validate_filters(query)?;
    let include_capi = query.origin.as_deref().is_some_and(|origin| {
        origin.eq_ignore_ascii_case("all") || origin.eq_ignore_ascii_case("capi")
    });
    let use_unbounded_command = include_capi || filter_count(query) > 1;
    let command_limit = if use_unbounded_command { "0" } else { limit };
    let mut arguments = vec!["decisions", "list", "--limit", command_limit];

    if include_capi {
        arguments.push("--all");
    } else {
        if let Some(origin) = query.origin.as_deref() {
            if !origin.eq_ignore_ascii_case("local") {
                arguments.extend(["--origin", origin]);
            }
        }

        if !use_unbounded_command {
            append_supported_filters(&mut arguments, query);
        }
    }

    arguments.extend(["-o", "json"]);
    Ok(arguments)
}

fn validate_filters(query: &CrowdSecDecisionsQuery) -> Result<()> {
    if let Some(scope) = query.scope.as_deref() {
        validate_token(scope, "scope")?;
    }

    if let Some(value) = query.value.as_deref() {
        validate_value(value)?;
    }

    if let Some(decision_type) = query.decision_type.as_deref() {
        validate_token(decision_type, "decision type")?;
    }

    if let Some(origin) = query.origin.as_deref() {
        validate_token(origin, "origin")?;
    }

    if let Some(scenario) = query.scenario.as_deref() {
        validate_scenario(scenario)?;
    }

    Ok(())
}

fn append_supported_filters<'a>(arguments: &mut Vec<&'a str>, query: &'a CrowdSecDecisionsQuery) {
    if let Some(scope) = query.scope.as_deref() {
        arguments.extend(["--scope", scope]);
    }

    if let Some(value) = query.value.as_deref() {
        arguments.extend(["--value", value]);
    }

    if let Some(decision_type) = query.decision_type.as_deref() {
        arguments.extend(["--type", decision_type]);
    }

    if let Some(scenario) = query.scenario.as_deref() {
        arguments.extend(["--scenario", scenario]);
    }
}

fn filter_count(query: &CrowdSecDecisionsQuery) -> usize {
    [
        query.scope.is_some(),
        query.value.is_some(),
        query.decision_type.is_some(),
        query.origin.is_some(),
        query.scenario.is_some(),
    ]
    .iter()
    .filter(|present| **present)
    .count()
}

fn filter_decisions(
    decisions: Vec<CrowdSecDecision>,
    query: &CrowdSecDecisionsQuery,
) -> Vec<CrowdSecDecision> {
    decisions
        .into_iter()
        .filter(|decision| {
            query
                .scope
                .as_deref()
                .is_none_or(|scope| decision.scope == scope)
        })
        .filter(|decision| {
            query
                .value
                .as_deref()
                .is_none_or(|value| decision.value == value)
        })
        .filter(|decision| {
            query
                .decision_type
                .as_deref()
                .is_none_or(|decision_type| decision.decision_type == decision_type)
        })
        .filter(|decision| {
            query.origin.as_deref().is_none_or(|origin| {
                if origin.eq_ignore_ascii_case("all") {
                    true
                } else if origin.eq_ignore_ascii_case("local") {
                    !decision
                        .origin
                        .as_deref()
                        .is_some_and(|origin| origin.eq_ignore_ascii_case("capi"))
                } else {
                    decision
                        .origin
                        .as_deref()
                        .is_some_and(|decision_origin| decision_origin == origin)
                }
            })
        })
        .filter(|decision| {
            query
                .scenario
                .as_deref()
                .is_none_or(|scenario| decision.scenario.as_deref() == Some(scenario))
        })
        .collect()
}

fn list_limit(requested_limit: Option<u32>) -> Result<u32> {
    let limit = requested_limit.unwrap_or(DEFAULT_LIST_LIMIT);

    if (1..=MAXIMUM_LIST_LIMIT).contains(&limit) {
        Ok(limit)
    } else {
        Err(FwcError::crowdsec(
            DECISIONS_INVALID,
            "CrowdSec decision limit must be between 1 and 100",
        ))
    }
}

fn validate_decision_id(id: &str) -> Result<()> {
    let valid = !id.is_empty()
        && id.len() <= 19
        && id.bytes().all(|character| character.is_ascii_digit())
        && id.parse::<u64>().is_ok();

    if valid {
        Ok(())
    } else {
        Err(FwcError::crowdsec(
            DECISIONS_INVALID,
            "Invalid CrowdSec decision ID",
        ))
    }
}

fn validate_token(value: &str, field: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
        });

    if valid {
        Ok(())
    } else {
        Err(invalid_filter(field))
    }
}

fn validate_value(value: &str) -> Result<()> {
    if !value.trim().is_empty() && value.len() <= 256 && !value.chars().any(char::is_control) {
        Ok(())
    } else {
        Err(invalid_filter("value"))
    }
}

fn validate_scenario(value: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, ':' | '/' | '_' | '-' | '.')
        });

    if valid {
        Ok(())
    } else {
        Err(invalid_filter("scenario"))
    }
}

fn invalid_filter(_field: &str) -> FwcError {
    FwcError::crowdsec(DECISIONS_INVALID, "Invalid CrowdSec decision filter")
}

fn decisions_from_json(value: &Value) -> Vec<CrowdSecDecision> {
    match value {
        Value::Array(values) => values.iter().flat_map(decisions_from_item).collect(),
        Value::Object(_) => decisions_from_item(value),
        _ => vec![],
    }
}

fn decisions_from_item(value: &Value) -> Vec<CrowdSecDecision> {
    let Some(object) = value.as_object() else {
        return vec![];
    };

    if let Some(decisions) = object.get("decisions").and_then(Value::as_array) {
        decisions
            .iter()
            .filter_map(|decision| decision_from_json(decision, Some(value)))
            .collect()
    } else {
        decision_from_json(value, None).into_iter().collect()
    }
}

fn decision_from_json(decision: &Value, alert: Option<&Value>) -> Option<CrowdSecDecision> {
    let id = value_as_string(decision.get("id"))?;
    let source = decision
        .get("source")
        .or_else(|| alert.and_then(|value| value.get("source")));

    Some(CrowdSecDecision {
        id,
        scope: first_string(&[
            decision.get("scope"),
            source.and_then(|value| value.get("scope")),
        ])
        .unwrap_or_default(),
        value: first_string(&[
            decision.get("value"),
            source.and_then(|value| value.get("value")),
            source.and_then(|value| value.get("ip")),
        ])
        .unwrap_or_default(),
        decision_type: first_string(&[decision.get("type"), decision.get("decision_type")])
            .unwrap_or_default(),
        origin: first_string(&[decision.get("origin")]),
        scenario: first_string(&[
            decision.get("scenario"),
            alert.and_then(|value| value.get("scenario")),
        ]),
        expires_at: first_string(&[
            decision.get("until"),
            decision.get("expires_at"),
            decision.get("expiration"),
            decision.get("stop_at"),
        ]),
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
