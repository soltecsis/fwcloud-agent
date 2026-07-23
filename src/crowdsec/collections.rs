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

use std::time::Duration;

use tokio::{process::Command, time::timeout};

use crate::{
    crowdsec::{
        command::CrowdSecCommand,
        errors::{COMMAND_FAILED, INVALID_COMMAND, OPERATION_TIMEOUT},
        models::{
            CrowdSecCollection, CrowdSecCollectionOperation, CrowdSecCollectionOperationResponse,
            CrowdSecCollectionState, CrowdSecCollectionsResponse,
        },
    },
    errors::{FwcError, Result},
};

const SERVICE_COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
const SYSTEMCTL_COMMAND: &str = "/usr/bin/systemctl";

pub async fn list(installed_only: bool) -> Result<CrowdSecCollectionsResponse> {
    let arguments: &[&str] = if installed_only {
        &["collections", "list", "-o", "json"]
    } else {
        &["collections", "list", "--all", "-o", "json"]
    };
    let output = CrowdSecCommand::cscli(arguments)?.execute().await?;
    let value = serde_json::from_str::<serde_json::Value>(output.stdout()).map_err(|_| {
        FwcError::crowdsec(COMMAND_FAILED, "Unable to read CrowdSec collection list")
    })?;

    Ok(CrowdSecCollectionsResponse {
        collections: collections_from_json(&value),
    })
}

pub async fn install(name: &str) -> Result<CrowdSecCollectionOperationResponse> {
    validate_collection_name(name)?;

    if !collection_exists(name).await? {
        return Err(FwcError::crowdsec(
            INVALID_COMMAND,
            "CrowdSec collection is not available in the installed Hub",
        ));
    }

    CrowdSecCommand::cscli(&["collections", "install", name])?
        .execute()
        .await?;
    reload_crowdsec_service().await?;

    Ok(CrowdSecCollectionOperationResponse {
        operation: CrowdSecCollectionOperation::Install,
        collection: Some(name.to_string()),
        processed_collections: vec![name.to_string()],
        skipped_collections: vec![],
        message: "CrowdSec collection is installed and CrowdSec service is reloaded".to_string(),
    })
}

pub async fn remove(name: &str) -> Result<CrowdSecCollectionOperationResponse> {
    validate_collection_name(name)?;

    let collection = list(false)
        .await?
        .collections
        .into_iter()
        .find(|collection| collection.name == name)
        .ok_or_else(|| {
            FwcError::crowdsec(
                INVALID_COMMAND,
                "CrowdSec collection is not available in the installed Hub",
            )
        })?;

    if !matches!(
        collection.state,
        CrowdSecCollectionState::Installed | CrowdSecCollectionState::Tainted
    ) {
        return Err(FwcError::crowdsec(
            INVALID_COMMAND,
            "CrowdSec collection is not installed",
        ));
    }

    CrowdSecCommand::cscli(&["collections", "remove", name])?
        .execute()
        .await?;
    reload_crowdsec_service().await?;

    Ok(CrowdSecCollectionOperationResponse {
        operation: CrowdSecCollectionOperation::Remove,
        collection: Some(name.to_string()),
        processed_collections: vec![name.to_string()],
        skipped_collections: vec![],
        message: "CrowdSec collection is removed and CrowdSec service is reloaded".to_string(),
    })
}

pub async fn update() -> Result<CrowdSecCollectionOperationResponse> {
    CrowdSecCommand::cscli(&["hub", "update"])?
        .execute()
        .await?;

    let collections = list(true).await?.collections;
    let mut processed_collections = Vec::new();
    let mut skipped_collections = Vec::new();

    for collection in collections {
        match collection.state {
            CrowdSecCollectionState::Installed => {
                validate_collection_name(&collection.name)?;
                CrowdSecCommand::cscli(&["collections", "upgrade", &collection.name])?
                    .execute()
                    .await?;
                processed_collections.push(collection.name);
            }
            CrowdSecCollectionState::Tainted => skipped_collections.push(collection.name),
            _ => {}
        }
    }

    if !processed_collections.is_empty() {
        reload_crowdsec_service().await?;
    }

    Ok(CrowdSecCollectionOperationResponse {
        operation: CrowdSecCollectionOperation::Update,
        collection: None,
        processed_collections,
        skipped_collections,
        message: "CrowdSec Hub index and installed collections are updated".to_string(),
    })
}

fn validate_collection_name(name: &str) -> Result<()> {
    let valid_segment = |segment: &str| {
        !segment.is_empty()
            && segment.len() <= 64
            && segment.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
            })
    };
    let mut segments = name.split('/');
    let valid = name.len() <= 129
        && segments.next().is_some_and(valid_segment)
        && segments.next().is_some_and(valid_segment)
        && segments.next().is_none();

    if valid {
        Ok(())
    } else {
        Err(FwcError::crowdsec(
            INVALID_COMMAND,
            "Invalid CrowdSec collection name",
        ))
    }
}

async fn collection_exists(name: &str) -> Result<bool> {
    Ok(list(false)
        .await?
        .collections
        .iter()
        .any(|collection| collection.name == name))
}

async fn reload_crowdsec_service() -> Result<()> {
    let output = timeout(
        SERVICE_COMMAND_TIMEOUT,
        Command::new(SYSTEMCTL_COMMAND)
            .args(["reload", "crowdsec.service"])
            .output(),
    )
    .await
    .map_err(|_| FwcError::crowdsec(OPERATION_TIMEOUT, "CrowdSec service command timed out"))?
    .map_err(|_| FwcError::crowdsec(COMMAND_FAILED, "Unable to run CrowdSec service command"))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(FwcError::crowdsec(
            COMMAND_FAILED,
            "CrowdSec service command failed",
        ))
    }
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
