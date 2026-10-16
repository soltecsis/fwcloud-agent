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
        errors::{
            COLLECTION_CONFLICT, COLLECTION_INVALID, COLLECTION_TAINTED, COMMAND_FAILED,
            OPERATION_TIMEOUT,
        },
        models::{
            CrowdSecCollection, CrowdSecCollectionOperation, CrowdSecCollectionOperationResponse,
            CrowdSecCollectionServiceReloadState, CrowdSecCollectionState,
            CrowdSecCollectionsResponse,
        },
    },
    errors::{FwcError, Result},
};

const SERVICE_COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
const SYSTEMCTL_COMMAND: &str = "/usr/bin/systemctl";

pub async fn list(installed_only: bool) -> Result<CrowdSecCollectionsResponse> {
    let arguments = list_arguments(installed_only);
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
    let collection = collection_by_name(name).await?;

    reject_tainted_collection(&collection)?;
    if collection.state == CrowdSecCollectionState::Installed {
        return Ok(CrowdSecCollectionOperationResponse {
            operation: CrowdSecCollectionOperation::Install,
            collection: Some(name.to_string()),
            processed_collections: vec![],
            skipped_collections: vec![name.to_string()],
            service_reload: CrowdSecCollectionServiceReloadState::Reloaded,
            message: "CrowdSec collection is already installed".to_string(),
        });
    }

    execute_collection_command(&["collections", "install", name]).await?;
    let service_reload = collection_service_reload_state().await;

    Ok(CrowdSecCollectionOperationResponse {
        operation: CrowdSecCollectionOperation::Install,
        collection: Some(name.to_string()),
        processed_collections: vec![name.to_string()],
        skipped_collections: vec![],
        message: collection_operation_message("CrowdSec collection is installed", &service_reload),
        service_reload,
    })
}

pub async fn remove(name: &str) -> Result<CrowdSecCollectionOperationResponse> {
    validate_collection_name(name)?;

    let collection = collection_by_name(name).await?;
    reject_tainted_collection(&collection)?;

    if collection.state == CrowdSecCollectionState::Available {
        return Ok(CrowdSecCollectionOperationResponse {
            operation: CrowdSecCollectionOperation::Remove,
            collection: Some(name.to_string()),
            processed_collections: vec![],
            skipped_collections: vec![name.to_string()],
            service_reload: CrowdSecCollectionServiceReloadState::Reloaded,
            message: "CrowdSec collection is already absent".to_string(),
        });
    }

    execute_collection_command(&["collections", "remove", name]).await?;
    let service_reload = collection_service_reload_state().await;

    Ok(CrowdSecCollectionOperationResponse {
        operation: CrowdSecCollectionOperation::Remove,
        collection: Some(name.to_string()),
        processed_collections: vec![name.to_string()],
        skipped_collections: vec![],
        message: collection_operation_message("CrowdSec collection is removed", &service_reload),
        service_reload,
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
                execute_collection_command(&["collections", "upgrade", &collection.name]).await?;
                processed_collections.push(collection.name);
            }
            CrowdSecCollectionState::Tainted => skipped_collections.push(collection.name),
            _ => {}
        }
    }

    if !processed_collections.is_empty() {
        let service_reload = collection_service_reload_state().await;
        return Ok(collection_operation_response(
            CrowdSecCollectionOperation::Update,
            None,
            processed_collections,
            skipped_collections,
            service_reload,
            "CrowdSec Hub index and installed collections are updated",
        ));
    }

    Ok(CrowdSecCollectionOperationResponse {
        operation: CrowdSecCollectionOperation::Update,
        collection: None,
        processed_collections,
        skipped_collections,
        service_reload: CrowdSecCollectionServiceReloadState::Reloaded,
        message: "CrowdSec Hub index and installed collections are updated".to_string(),
    })
}

fn collection_operation_response(
    operation: CrowdSecCollectionOperation,
    collection: Option<String>,
    processed_collections: Vec<String>,
    skipped_collections: Vec<String>,
    service_reload: CrowdSecCollectionServiceReloadState,
    completed_mutation: &str,
) -> CrowdSecCollectionOperationResponse {
    CrowdSecCollectionOperationResponse {
        operation,
        collection,
        processed_collections,
        skipped_collections,
        message: collection_operation_message(completed_mutation, &service_reload),
        service_reload,
    }
}

fn list_arguments(installed_only: bool) -> &'static [&'static str] {
    if installed_only {
        &["collections", "list", "-o", "json"]
    } else {
        &["collections", "list", "--all", "-o", "json"]
    }
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
            COLLECTION_INVALID,
            "Invalid CrowdSec collection name",
        ))
    }
}

async fn collection_by_name(name: &str) -> Result<CrowdSecCollection> {
    list(false)
        .await?
        .collections
        .into_iter()
        .find(|collection| collection.name == name)
        .ok_or_else(|| {
            FwcError::crowdsec(
                COLLECTION_INVALID,
                "CrowdSec collection is not available in the installed Hub",
            )
        })
}

fn reject_tainted_collection(collection: &CrowdSecCollection) -> Result<()> {
    if collection.state == CrowdSecCollectionState::Tainted {
        Err(FwcError::crowdsec(
            COLLECTION_TAINTED,
            "CrowdSec collection has local changes",
        ))
    } else {
        Ok(())
    }
}

async fn execute_collection_command(arguments: &[&str]) -> Result<()> {
    let output = CrowdSecCommand::cscli(arguments)?
        .execute_allow_failure()
        .await?;

    if output.succeeded() {
        Ok(())
    } else {
        Err(collection_command_error(output.stderr()))
    }
}

fn collection_command_error(diagnostics: &str) -> FwcError {
    let diagnostics = diagnostics.to_ascii_lowercase();

    if diagnostics.contains("tainted") {
        FwcError::crowdsec(COLLECTION_TAINTED, "CrowdSec collection has local changes")
    } else if diagnostics.contains("dependency")
        || diagnostics.contains("conflict")
        || diagnostics.contains("required by")
    {
        FwcError::crowdsec(
            COLLECTION_CONFLICT,
            "CrowdSec collection dependency conflict",
        )
    } else {
        FwcError::crowdsec(COMMAND_FAILED, "CrowdSec collection command failed")
    }
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

async fn collection_service_reload_state() -> CrowdSecCollectionServiceReloadState {
    collection_service_reload_state_from_result(reload_crowdsec_service().await)
}

fn collection_service_reload_state_from_result(
    result: Result<()>,
) -> CrowdSecCollectionServiceReloadState {
    match result {
        Ok(()) => CrowdSecCollectionServiceReloadState::Reloaded,
        Err(_) => CrowdSecCollectionServiceReloadState::Failed,
    }
}

fn collection_operation_message(
    completed_mutation: &str,
    service_reload: &CrowdSecCollectionServiceReloadState,
) -> String {
    match service_reload {
        CrowdSecCollectionServiceReloadState::Reloaded => {
            format!("{completed_mutation} and CrowdSec service is reloaded")
        }
        CrowdSecCollectionServiceReloadState::Failed => {
            format!("{completed_mutation}, but CrowdSec service reload failed")
        }
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

    let local_version =
        string_value(values, "local_version").or_else(|| string_value(values, "localversion"));
    let state = if tainted {
        CrowdSecCollectionState::Tainted
    } else if installed {
        CrowdSecCollectionState::Installed
    } else if disabled {
        CrowdSecCollectionState::Disabled
    } else {
        CrowdSecCollectionState::Available
    };

    Some(CrowdSecCollection {
        name,
        version: if state == CrowdSecCollectionState::Installed {
            local_version.or_else(|| string_value(values, "version"))
        } else {
            None
        },
        state,
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        collection_command_error, collection_from_json, collection_operation_response,
        collection_service_reload_state_from_result, list_arguments, validate_collection_name,
    };
    use crate::{
        crowdsec::{
            errors::{COLLECTION_CONFLICT, COLLECTION_INVALID, COLLECTION_TAINTED},
            models::{
                CrowdSecCollectionOperation, CrowdSecCollectionOperationResponse,
                CrowdSecCollectionServiceReloadState, CrowdSecCollectionState,
            },
        },
        errors::FwcError,
    };

    #[test]
    fn accepts_only_safe_two_segment_collection_names() {
        assert!(validate_collection_name("crowdsecurity/sshd").is_ok());

        for name in [
            "crowdsecurity",
            "crowdsecurity/sshd/extra",
            "crowdsecurity/ssh d",
            "crowdsecurity/../sshd",
            "crowdsecurity/sshd\n",
        ] {
            let error = validate_collection_name(name).unwrap_err();
            assert!(matches!(
                error,
                FwcError::CrowdSec {
                    code: COLLECTION_INVALID,
                    ..
                }
            ));
        }
    }

    #[test]
    fn omits_remote_version_for_available_collections() {
        let collection = collection_from_json(&json!({
            "name": "crowdsecurity/sshd",
            "version": "0.2"
        }))
        .unwrap();

        assert_eq!(collection.version, None);
        assert_eq!(collection.state, CrowdSecCollectionState::Available);
    }

    #[test]
    fn omits_stale_local_version_for_uninstalled_collections() {
        for value in [
            json!({
                "name": "crowdsecurity/sshd",
                "local_version": "0.2"
            }),
            json!({
                "name": "crowdsecurity/sshd",
                "local_version": "0.2",
                "status": "disabled"
            }),
            json!({
                "name": "crowdsecurity/sshd",
                "local_version": "0.2",
                "status": "tainted"
            }),
        ] {
            let collection = collection_from_json(&value).unwrap();

            assert_ne!(collection.state, CrowdSecCollectionState::Installed);
            assert_eq!(collection.version, None);
        }
    }

    #[test]
    fn normalizes_cscli_collection_output() {
        let collection = collection_from_json(&json!({
            "name": "crowdsecurity/sshd",
            "local_version": "0.2",
            "local_path": "/etc/crowdsec/collections/sshd.yaml",
            "status": "enabled"
        }))
        .unwrap();

        assert_eq!(collection.name, "crowdsecurity/sshd");
        assert_eq!(collection.version.as_deref(), Some("0.2"));
        assert_eq!(collection.state, CrowdSecCollectionState::Installed);
        assert!(collection.available);
        assert_eq!(
            collection.path.as_deref(),
            Some("/etc/crowdsec/collections/sshd.yaml")
        );
    }

    #[test]
    fn maps_tainted_and_dependency_diagnostics_to_stable_errors() {
        let tainted = collection_command_error("collection is tainted");
        let conflict = collection_command_error("required by another collection");

        assert!(matches!(
            tainted,
            FwcError::CrowdSec {
                code: COLLECTION_TAINTED,
                ..
            }
        ));
        assert!(matches!(
            conflict,
            FwcError::CrowdSec {
                code: COLLECTION_CONFLICT,
                ..
            }
        ));
    }

    #[test]
    fn uses_fixed_arguments_for_collection_lists() {
        assert_eq!(
            list_arguments(false),
            ["collections", "list", "--all", "-o", "json"]
        );
        assert_eq!(list_arguments(true), ["collections", "list", "-o", "json"]);
    }

    #[test]
    fn omits_absent_collection_and_sensitive_fields_from_update_response() {
        let response = CrowdSecCollectionOperationResponse {
            operation: CrowdSecCollectionOperation::Update,
            collection: None,
            processed_collections: vec!["crowdsecurity/sshd".to_string()],
            skipped_collections: vec![],
            service_reload: CrowdSecCollectionServiceReloadState::Reloaded,
            message: "CrowdSec Hub index and installed collections are updated".to_string(),
        };
        let response = serde_json::to_value(response).unwrap();

        assert!(response.get("collection").is_none());
        assert_eq!(
            response["processed_collections"],
            json!(["crowdsecurity/sshd"])
        );
        assert_eq!(response["service_reload"], json!("reloaded"));
        assert!(response.get("api_key").is_none());
        assert!(response.get("enrollment_key").is_none());
    }

    #[test]
    fn reports_completed_collection_mutations_when_service_reload_fails() {
        for (operation, collection, processed_collections) in [
            (
                CrowdSecCollectionOperation::Install,
                Some("crowdsecurity/sshd".to_string()),
                vec!["crowdsecurity/sshd".to_string()],
            ),
            (
                CrowdSecCollectionOperation::Remove,
                Some("crowdsecurity/nginx".to_string()),
                vec!["crowdsecurity/nginx".to_string()],
            ),
            (
                CrowdSecCollectionOperation::Update,
                None,
                vec!["crowdsecurity/linux".to_string()],
            ),
        ] {
            let response = collection_operation_response(
                operation,
                collection,
                processed_collections,
                vec![],
                CrowdSecCollectionServiceReloadState::Failed,
                "CrowdSec collection mutation completed",
            );
            let response = serde_json::to_value(response).unwrap();

            assert_eq!(response["service_reload"], json!("failed"));
            assert_eq!(response["processed_collections"].as_array().unwrap().len(), 1);
            assert!(response["message"]
                .as_str()
                .unwrap()
                .contains("CrowdSec service reload failed"));
            assert!(response.get("api_key").is_none());
            assert!(response.get("enrollment_key").is_none());
        }
    }

    #[test]
    fn maps_service_reload_errors_to_a_failed_state() {
        let state = collection_service_reload_state_from_result(Err(FwcError::crowdsec(
            COLLECTION_INVALID,
            "CrowdSec service command failed",
        )));

        assert_eq!(state, CrowdSecCollectionServiceReloadState::Failed);
    }
}
