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
        errors::{COMMAND_FAILED, DECISIONS_INVALID},
        models::{CrowdSecDecision, CrowdSecDecisionsResponse},
    },
    errors::{FwcError, Result},
};

const DEFAULT_LIST_LIMIT: u32 = 50;
const MAXIMUM_LIST_LIMIT: u32 = 100;

pub async fn list(requested_limit: Option<u32>) -> Result<CrowdSecDecisionsResponse> {
    let limit = list_limit(requested_limit)?;
    let limit = limit.to_string();
    let output = CrowdSecCommand::cscli(&[
        "decisions",
        "list",
        "--all",
        "--limit",
        &limit,
        "-o",
        "json",
    ])?
    .execute()
    .await?;
    let value = serde_json::from_str::<Value>(output.stdout())
        .map_err(|_| FwcError::crowdsec(COMMAND_FAILED, "Unable to read CrowdSec decision list"))?;

    Ok(CrowdSecDecisionsResponse {
        decisions: decisions_from_json(&value),
    })
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
