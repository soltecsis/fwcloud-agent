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

use log::debug;
use tokio::{process::Command, time::timeout};

use crate::{
    crowdsec::{
        command::CrowdSecCommand,
        errors::{COMMAND_FAILED, OPERATION_TIMEOUT},
        models::{
            CrowdSecDataRetention, CrowdSecInstallResponse, CrowdSecInstallStep,
            CrowdSecStepResult, CrowdSecStepStatus,
        },
        packages,
        progress::CrowdSecProgress,
    },
    errors::{FwcError, Result},
};

const SERVICE_COMMAND_TIMEOUT: Duration = Duration::from_secs(60);

pub async fn install() -> Result<CrowdSecInstallResponse> {
    install_with_progress(None).await
}

pub async fn install_with_progress(
    progress: Option<&CrowdSecProgress>,
) -> Result<CrowdSecInstallResponse> {
    log::info!("Installing CrowdSec packages and default collections");

    emit_progress(progress, "Installing CrowdSec packages and dependencies");
    let mut steps = packages::install_packages_with_progress(progress).await?;
    emit_progress(progress, "Enabling CrowdSec service");
    enable_crowdsec_service().await?;
    steps.push(CrowdSecStepResult {
        step: CrowdSecInstallStep::CrowdSecService,
        status: CrowdSecStepStatus::Completed,
        message: "CrowdSec service is enabled and running".to_string(),
    });

    emit_progress(progress, "Updating CrowdSec Hub index");
    update_hub().await?;
    steps.push(CrowdSecStepResult {
        step: CrowdSecInstallStep::HubUpdate,
        status: CrowdSecStepStatus::Completed,
        message: "CrowdSec Hub index is up to date".to_string(),
    });

    emit_progress(progress, "Installing CrowdSec default collections");
    install_default_collections(progress).await?;
    steps.push(CrowdSecStepResult {
        step: CrowdSecInstallStep::DefaultCollections,
        status: CrowdSecStepStatus::Completed,
        message: "Ensured CrowdSec default collections: crowdsecurity/linux, crowdsecurity/sshd"
            .to_string(),
    });

    emit_progress(progress, "Restarting CrowdSec service");
    restart_crowdsec_service().await?;
    log::info!("CrowdSec installation completed");
    emit_progress(progress, "CrowdSec installation completed");

    Ok(CrowdSecInstallResponse {
        data_retention: CrowdSecDataRetention::Preserve,
        steps,
    })
}

async fn enable_crowdsec_service() -> Result<()> {
    run_systemctl(&["enable", "--now", "crowdsec.service"]).await
}

async fn restart_crowdsec_service() -> Result<()> {
    run_systemctl(&["restart", "crowdsec.service"]).await
}

async fn update_hub() -> Result<()> {
    debug!("Updating CrowdSec Hub index");
    CrowdSecCommand::cscli(&["hub", "update"])?
        .execute()
        .await?;

    Ok(())
}

async fn install_default_collections(progress: Option<&CrowdSecProgress>) -> Result<()> {
    for collection in ["crowdsecurity/linux", "crowdsecurity/sshd"] {
        if collection_is_installed(collection).await? {
            debug!(
                "CrowdSec default collection is already installed; preserving its local state: {}",
                collection
            );
            emit_progress(
                progress,
                &format!("CrowdSec collection is already installed: {collection}"),
            );
            continue;
        }

        debug!("Installing CrowdSec default collection: {}", collection);
        emit_progress(
            progress,
            &format!("Installing CrowdSec collection: {collection}"),
        );
        CrowdSecCommand::cscli(&["collections", "install", collection])?
            .execute()
            .await?;
        emit_progress(
            progress,
            &format!("CrowdSec collection installed: {collection}"),
        );
    }

    Ok(())
}

fn emit_progress(progress: Option<&CrowdSecProgress>, message: &str) {
    if let Some(progress) = progress {
        progress.message(message);
    }
}

async fn collection_is_installed(collection: &str) -> Result<bool> {
    let output = CrowdSecCommand::cscli(&["collections", "inspect", "-o", "json", collection])?
        .execute()
        .await?;
    let collection_state =
        serde_json::from_str::<serde_json::Value>(output.stdout()).map_err(|_| {
            FwcError::crowdsec(
                COMMAND_FAILED,
                "Unable to read CrowdSec collection installation state",
            )
        })?;

    Ok(json_collection_is_installed(&collection_state, collection))
}

fn json_collection_is_installed(value: &serde_json::Value, collection: &str) -> bool {
    match value {
        serde_json::Value::Array(values) => values
            .iter()
            .any(|value| json_collection_is_installed(value, collection)),
        serde_json::Value::Object(values) => {
            values.get("name").and_then(serde_json::Value::as_str) == Some(collection)
                && values.get("installed").and_then(serde_json::Value::as_bool) == Some(true)
                || values
                    .values()
                    .any(|value| json_collection_is_installed(value, collection))
        }
        _ => false,
    }
}

async fn run_systemctl(arguments: &[&str]) -> Result<()> {
    let output = timeout(
        SERVICE_COMMAND_TIMEOUT,
        Command::new("/usr/bin/systemctl").args(arguments).output(),
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

#[cfg(test)]
mod tests {
    use super::{emit_progress, json_collection_is_installed};
    use crate::{crowdsec::progress::CrowdSecProgress, utils::ws::WsData};
    use serde_json::json;
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
        time::SystemTime,
    };
    use uuid::Uuid;

    #[test]
    fn recognizes_installed_collections_in_json_output() {
        let collection_state = json!({
            "collections": [
                {"name": "crowdsecurity/linux", "installed": true, "tainted": true},
                {"name": "crowdsecurity/sshd", "installed": false}
            ]
        });

        assert!(json_collection_is_installed(
            &collection_state,
            "crowdsecurity/linux"
        ));
        assert!(!json_collection_is_installed(
            &collection_state,
            "crowdsecurity/sshd"
        ));
    }

    #[test]
    fn installation_progress_messages_are_published_without_secrets() {
        let map = Arc::new(Mutex::new(HashMap::new()));
        let id = Uuid::new_v4();
        let data = Arc::new(Mutex::new(WsData {
            created_at: SystemTime::now(),
            lines: Vec::new(),
            finished: false,
        }));
        map.lock().unwrap().insert(id, Arc::clone(&data));
        let progress = CrowdSecProgress::from_ws_map(map, Some(id)).unwrap();

        emit_progress(
            Some(&progress),
            "Installing CrowdSec collection: crowdsecurity/sshd",
        );

        assert_eq!(
            data.lock().unwrap().lines,
            vec!["Installing CrowdSec collection: crowdsecurity/sshd"]
        );
    }
}
