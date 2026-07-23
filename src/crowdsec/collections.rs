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

use crate::{
    crowdsec::{
        command::CrowdSecCommand,
        errors::COMMAND_FAILED,
        models::{CrowdSecCollection, CrowdSecCollectionState, CrowdSecCollectionsResponse},
    },
    errors::{FwcError, Result},
};

pub async fn list() -> Result<CrowdSecCollectionsResponse> {
    let output = CrowdSecCommand::cscli(&["collections", "list", "--all", "-o", "json"])?
        .execute()
        .await?;
    let value = serde_json::from_str::<serde_json::Value>(output.stdout()).map_err(|_| {
        FwcError::crowdsec(COMMAND_FAILED, "Unable to read CrowdSec collection list")
    })?;

    Ok(CrowdSecCollectionsResponse {
        collections: collections_from_json(&value),
    })
}

fn collections_from_json(value: &serde_json::Value) -> Vec<CrowdSecCollection> {
    let values = match value {
        serde_json::Value::Array(values) => values,
        serde_json::Value::Object(values) => values
            .get("collections")
            .and_then(serde_json::Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default(),
        _ => &[],
    };

    let mut collections = values
        .iter()
        .filter_map(collection_from_json)
        .collect::<Vec<_>>();
    collections.sort_by(|left, right| left.name.cmp(&right.name));
    collections
}

fn collection_from_json(value: &serde_json::Value) -> Option<CrowdSecCollection> {
    let values = value.as_object()?;
    let name = values.get("name")?.as_str()?.to_string();
    let status = values.get("status").and_then(serde_json::Value::as_str);
    let installed = values
        .get("installed")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or_else(|| status.is_some_and(|status| status.contains("enabled")));
    let tainted = values
        .get("tainted")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or_else(|| status.is_some_and(|status| status.contains("tainted")));
    let disabled = status.is_some_and(|status| status.contains("disabled"));

    Some(CrowdSecCollection {
        name,
        version: string_value(values, "version")
            .or_else(|| string_value(values, "local_version"))
            .or_else(|| string_value(values, "localversion")),
        state: if tainted {
            CrowdSecCollectionState::Tainted
        } else if installed {
            CrowdSecCollectionState::Installed
        } else if disabled {
            CrowdSecCollectionState::Disabled
        } else {
            CrowdSecCollectionState::Available
        },
        available: true,
        path: string_value(values, "local_path")
            .or_else(|| string_value(values, "path"))
            .or_else(|| string_value(values, "remote_path")),
    })
}

fn string_value(values: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<String> {
    values
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}
