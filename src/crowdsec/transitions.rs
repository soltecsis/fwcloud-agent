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

use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{fs, process::Command, time::timeout};
use uuid::Uuid;

use super::{
    bouncers,
    errors::{NOT_INSTALLED, TRANSITION_FAILED, TRANSITION_INVALID, TRANSITION_UNSUPPORTED},
    lapi,
    models::CrowdSecFirewallBackend,
    packages,
    progress::{CrowdSecProgress, CrowdSecProgressMessageType},
};
use crate::errors::{FwcError, Result};

pub mod address;
pub mod local_lapi;
pub mod remediation;
pub mod remote;

const CROWDSEC_CONFIG_PATH: &str = "/etc/crowdsec/config.yaml";
const CROWDSEC_CREDENTIALS_PATH: &str = "/etc/crowdsec/local_api_credentials.yaml";
const CROWDSEC_SERVICE: &str = "crowdsec.service";
const FIREWALL_BOUNCER_SERVICE: &str = "crowdsec-firewall-bouncer.service";

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct TransitionServiceState {
    pub enabled: bool,
    pub running: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct TransitionBackup {
    pub configuration: String,
    pub credentials: Option<String>,
    pub bouncer_configuration: Option<String>,
    pub crowdsec_service: TransitionServiceState,
    pub firewall_bouncer_service: TransitionServiceState,
}

fn backup_failed() -> FwcError {
    FwcError::crowdsec(
        TRANSITION_FAILED,
        "Unable to save CrowdSec transition rollback backup",
    )
}

fn backup_path(data_directory: &str, transition_id: Uuid) -> PathBuf {
    Path::new(data_directory)
        .join("crowdsec/transitions")
        .join(format!("{transition_id}.rollback"))
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    let temporary = path.with_extension(format!("{}.tmp", Uuid::new_v4()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        std::fs::File::open(path.parent().ok_or_else(backup_failed)?)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result.map_err(|_: FwcError| backup_failed())
}

async fn systemctl(arguments: &[&str]) -> Result<std::process::Output> {
    timeout(
        Duration::from_secs(60),
        Command::new("/usr/bin/systemctl").args(arguments).output(),
    )
    .await
    .map_err(|_| backup_failed())?
    .map_err(|_| backup_failed())
}

async fn service_exists(service: &str) -> Result<bool> {
    let output = systemctl(&["show", "--property=LoadState", "--value", service]).await?;
    Ok(output.status.success() && String::from_utf8_lossy(&output.stdout).trim() != "not-found")
}

pub(crate) async fn restore_service_state(
    service: &str,
    state: &TransitionServiceState,
) -> Result<()> {
    if !service_exists(service).await? {
        return if state.enabled || state.running {
            Err(backup_failed())
        } else {
            Ok(())
        };
    }

    let output = systemctl(&["stop", service]).await?;
    if !output.status.success() {
        return Err(backup_failed());
    }

    let enabled = systemctl(&["is-enabled", service]).await?;
    let enabled = String::from_utf8_lossy(&enabled.stdout).trim().to_string();
    if state.enabled {
        let output = systemctl(&["enable", service]).await?;
        if !output.status.success() {
            return Err(backup_failed());
        }
    } else if matches!(enabled.as_str(), "enabled" | "enabled-runtime") {
        let output = systemctl(&["disable", service]).await?;
        if !output.status.success() {
            return Err(backup_failed());
        }
    }

    if state.running {
        let output = systemctl(&["start", service]).await?;
        if !output.status.success() {
            return Err(backup_failed());
        }
    }
    let restored = service_state(service).await?;
    if restored.enabled != state.enabled || restored.running != state.running {
        return Err(backup_failed());
    }
    Ok(())
}

pub(crate) async fn service_state(service: &str) -> Result<TransitionServiceState> {
    if !service_exists(service).await? {
        return Ok(TransitionServiceState {
            enabled: false,
            running: false,
        });
    }

    let running = timeout(
        Duration::from_secs(15),
        Command::new("/usr/bin/systemctl")
            .args(["is-active", service])
            .output(),
    )
    .await
    .map_err(|_| backup_failed())?
    .map_err(|_| backup_failed())?;
    let running = match String::from_utf8_lossy(&running.stdout).trim() {
        "active" => true,
        "inactive" | "failed" | "unknown" => false,
        _ => return Err(backup_failed()),
    };

    let enabled = timeout(
        Duration::from_secs(15),
        Command::new("/usr/bin/systemctl")
            .args(["is-enabled", service])
            .output(),
    )
    .await
    .map_err(|_| backup_failed())?
    .map_err(|_| backup_failed())?;
    let enabled = match String::from_utf8_lossy(&enabled.stdout).trim() {
        "enabled" | "enabled-runtime" => true,
        "disabled" | "static" | "indirect" | "masked" | "not-found" => false,
        _ => return Err(backup_failed()),
    };

    Ok(TransitionServiceState { enabled, running })
}

async fn optional_file(path: &str) -> Result<Option<String>> {
    match fs::read_to_string(path).await {
        Ok(contents) => Ok(Some(contents)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(backup_failed()),
    }
}

pub(crate) async fn capture_backup() -> Result<TransitionBackup> {
    let configuration = fs::read_to_string(CROWDSEC_CONFIG_PATH)
        .await
        .map_err(|_| backup_failed())?;

    Ok(TransitionBackup {
        configuration,
        credentials: optional_file(CROWDSEC_CREDENTIALS_PATH).await?,
        bouncer_configuration: optional_file(bouncers::BOUNCER_CONFIG_PATH).await?,
        crowdsec_service: service_state(CROWDSEC_SERVICE).await?,
        firewall_bouncer_service: service_state(FIREWALL_BOUNCER_SERVICE).await?,
    })
}

pub(crate) fn save_backup(
    data_directory: &str,
    transition_id: Uuid,
    backup: &TransitionBackup,
) -> Result<()> {
    let directory = Path::new(data_directory).join("crowdsec/transitions");
    std::fs::create_dir_all(&directory).map_err(|_| backup_failed())?;
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
        .map_err(|_| backup_failed())?;

    let path = backup_path(data_directory, transition_id);
    if path.exists() {
        return Ok(());
    }
    let temporary = path.with_extension(format!("{}.tmp", Uuid::new_v4()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&serde_json::to_vec(backup).map_err(|_| backup_failed())?)?;
        file.sync_all()?;
        std::fs::rename(&temporary, &path)?;
        std::fs::File::open(&directory)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result.map_err(|_: FwcError| backup_failed())
}

pub(crate) async fn remove_backup(data_directory: &str, transition_id: Uuid) -> Result<()> {
    match fs::remove_file(backup_path(data_directory, transition_id)).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(backup_failed()),
    }
}

pub(crate) async fn restore_backup(data_directory: &str, transition_id: Uuid) -> Result<()> {
    let backup: TransitionBackup = serde_json::from_slice(
        &fs::read(backup_path(data_directory, transition_id))
            .await
            .map_err(|_| backup_failed())?,
    )
    .map_err(|_| backup_failed())?;

    for service in [CROWDSEC_SERVICE, FIREWALL_BOUNCER_SERVICE] {
        if service_exists(service).await? {
            let output = systemctl(&["stop", service]).await?;
            if !output.status.success() {
                return Err(backup_failed());
            }
        }
    }
    atomic_write(
        Path::new(CROWDSEC_CONFIG_PATH),
        backup.configuration.as_bytes(),
    )?;
    match backup.credentials {
        Some(contents) => atomic_write(Path::new(CROWDSEC_CREDENTIALS_PATH), contents.as_bytes())?,
        None => match fs::remove_file(CROWDSEC_CREDENTIALS_PATH).await {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(backup_failed()),
        },
    }
    match backup.bouncer_configuration {
        Some(contents) => atomic_write(
            Path::new(bouncers::BOUNCER_CONFIG_PATH),
            contents.as_bytes(),
        )?,
        None => match fs::remove_file(bouncers::BOUNCER_CONFIG_PATH).await {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(backup_failed()),
        },
    }
    restore_service_state(CROWDSEC_SERVICE, &backup.crowdsec_service).await?;
    restore_service_state(FIREWALL_BOUNCER_SERVICE, &backup.firewall_bouncer_service).await?;
    Ok(())
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransitionMode {
    Lapi,
    Machine,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransitionTarget {
    pub mode: TransitionMode,
    pub local_remediation: bool,
    pub machine_name: Option<String>,
    pub lapi_url: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionPrepareRequest {
    pub transition_id: Uuid,
    pub confirm: bool,
    pub expected: TransitionTarget,
    pub target: TransitionTarget,
    pub authority_changed: bool,
    pub backend: Option<CrowdSecFirewallBackend>,
    #[serde(default)]
    pub machine_connectivity_pending: bool,
    pub ws_id: Option<Uuid>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionActivateRequest {
    pub transition_id: Uuid,
    pub bouncer_api_key: Option<String>,
    pub ws_id: Option<Uuid>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransitionPhase {
    Checking,
    Preparing,
    AwaitingValidation,
    Prepared,
    Activating,
    ActivePendingFinalize,
    Completed,
    RecoveryRequired,
    RolledBack,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransitionKind {
    Address,
    Remote,
    Remediation,
    Lapi,
}

pub async fn kind(data_directory: &str, transition_id: Uuid) -> Result<TransitionKind> {
    let path = Path::new(data_directory)
        .join("crowdsec/transitions")
        .join(format!("{transition_id}.json"));
    let state: serde_json::Value = serde_json::from_slice(&fs::read(path).await.map_err(|_| {
        FwcError::crowdsec(TRANSITION_UNSUPPORTED, "CrowdSec transition is not found")
    })?)
    .map_err(|_| FwcError::crowdsec(TRANSITION_INVALID, "CrowdSec transition state is invalid"))?;
    serde_json::from_value(state.get("kind").cloned().ok_or_else(|| {
        FwcError::crowdsec(TRANSITION_INVALID, "CrowdSec transition state is invalid")
    })?)
    .map_err(|_| FwcError::crowdsec(TRANSITION_INVALID, "CrowdSec transition state is invalid"))
}

#[derive(Debug, Serialize)]
pub struct TransitionPreflightResponse {
    pub transition_id: Uuid,
    pub phase: TransitionPhase,
    pub connectivity_checked: bool,
    pub message: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionRecoveryOutcome {
    Restored,
    AlreadyRestored,
}

#[derive(Debug, Serialize)]
pub struct TransitionRecoveryResponse {
    pub transition_id: Uuid,
    pub outcome: TransitionRecoveryOutcome,
}

fn invalid(message: &'static str) -> FwcError {
    FwcError::crowdsec(TRANSITION_INVALID, message)
}

fn validate_target(target: &TransitionTarget) -> Result<()> {
    match target.mode {
        TransitionMode::Lapi => {
            if !target.local_remediation
                || target.machine_name.is_some()
                || target.lapi_url.is_some()
            {
                return Err(invalid(
                    "LAPI requires local remediation and no remote Machine fields",
                ));
            }
        }
        TransitionMode::Machine => {
            lapi::validate_machine_name(
                target
                    .machine_name
                    .as_deref()
                    .ok_or_else(|| invalid("Machine name is required"))?,
            )?;
            lapi::remote_lapi_url(
                target
                    .lapi_url
                    .as_deref()
                    .ok_or_else(|| invalid("Machine Local API URL is required"))?,
            )?;
        }
    }
    Ok(())
}

pub fn validate(request: &TransitionPrepareRequest) -> Result<()> {
    if request.transition_id.is_nil() || !request.confirm {
        return Err(invalid(
            "A transition identifier and explicit confirmation are required",
        ));
    }
    validate_target(&request.expected)?;
    validate_target(&request.target)?;
    if request.target.local_remediation != request.backend.is_some() {
        return Err(invalid(
            "A firewall backend is required only for local remediation",
        ));
    }
    if request.expected.mode != request.target.mode && !request.authority_changed {
        return Err(invalid(
            "Changing between LAPI and Machine changes the Local API authority",
        ));
    }
    if request.expected.mode == TransitionMode::Lapi
        && request.target.mode == TransitionMode::Lapi
        && request.authority_changed
    {
        return Err(invalid(
            "LAPI cannot change to a remote Local API authority",
        ));
    }
    if request.machine_connectivity_pending
        && (request.expected.mode != TransitionMode::Machine
            || request.target.mode != TransitionMode::Lapi
            || request.expected.local_remediation)
    {
        return Err(invalid(
            "Pending Machine connectivity is only valid when restoring a Machine without local remediation",
        ));
    }
    if !request.authority_changed && request.expected.machine_name != request.target.machine_name {
        return Err(invalid(
            "Changing only the Local API address must preserve the Machine name",
        ));
    }
    Ok(())
}

/// Validates transition prerequisites without reserving a transition or
/// establishing its effective source role; prepare rechecks before changing
/// configuration.
pub async fn preflight(
    request: &TransitionPrepareRequest,
    progress: &CrowdSecProgress,
) -> Result<TransitionPreflightResponse> {
    validate(request)?;
    if !packages::package_status().await?.crowdsec_installed {
        return Err(FwcError::crowdsec(
            NOT_INSTALLED,
            "CrowdSec is not installed",
        ));
    }
    if request.target.mode == TransitionMode::Machine {
        progress.typed_message(
            CrowdSecProgressMessageType::Info,
            "Checking central CrowdSec Local API connectivity",
        );
        let url = lapi::remote_lapi_url(
            request
                .target
                .lapi_url
                .as_deref()
                .ok_or_else(|| invalid("Machine Local API URL is required"))?,
        )?;
        lapi::ensure_remote_lapi_reachable(&url).await?;
    }
    progress.typed_message(
        CrowdSecProgressMessageType::Success,
        "CrowdSec transition requirements validated; configuration is unchanged",
    );
    Ok(TransitionPreflightResponse {
        transition_id: request.transition_id,
        phase: TransitionPhase::Checking,
        connectivity_checked: request.target.mode == TransitionMode::Machine,
        message: "Transition requirements validated; configuration has not been prepared",
    })
}

pub fn unsupported() -> FwcError {
    FwcError::crowdsec(
        TRANSITION_UNSUPPORTED,
        "This CrowdSec transition is not supported by this agent version",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> TransitionPrepareRequest {
        serde_json::from_value(serde_json::json!({
            "transition_id": Uuid::new_v4(), "confirm": true,
            "expected": {"mode":"lapi", "local_remediation":true},
            "target": {"mode":"machine", "local_remediation":false,
                "machine_name":"fwcloud-node", "lapi_url":"http://192.0.2.1:8080"},
            "authority_changed":true
        }))
        .unwrap()
    }

    #[test]
    fn rejects_inconsistent_authority_and_missing_confirmation() {
        let mut value = request();
        assert!(validate(&value).is_ok());
        value.authority_changed = false;
        assert!(validate(&value).is_err());
        value.authority_changed = true;
        value.confirm = false;
        assert!(validate(&value).is_err());
    }

    #[test]
    fn rejects_missing_backend_for_local_remediation() {
        let mut value = request();
        value.target.local_remediation = true;
        assert!(validate(&value).is_err());
    }

    #[test]
    fn rejects_legacy_agent_preflight_data() {
        let request = serde_json::from_value::<TransitionPrepareRequest>(serde_json::json!({
            "transition_id": Uuid::new_v4(), "confirm": true,
            "expected": {"mode":"lapi", "local_remediation":false},
            "target": {"mode":"machine", "local_remediation":false,
                "machine_name":"fwcloud-node", "lapi_url":"http://192.0.2.1:8080"},
            "authority_changed": true,
            "preflight": {"preflight_token":"obsolete"}
        }));

        assert!(request.is_err());
    }

    #[test]
    fn accepts_remediation_removal_without_a_target_backend() {
        let request: TransitionPrepareRequest = serde_json::from_value(serde_json::json!({
            "transition_id": Uuid::new_v4(), "confirm": true,
            "expected": {"mode":"machine", "local_remediation":true,
                "machine_name":"fwcloud-node", "lapi_url":"http://192.0.2.1:8080"},
            "target": {"mode":"machine", "local_remediation":false,
                "machine_name":"fwcloud-node", "lapi_url":"http://192.0.2.1:8080"},
            "authority_changed": false
        }))
        .unwrap();
        assert!(validate(&request).is_ok());
    }

    #[test]
    fn accepts_pending_machine_connectivity_when_restoring_lapi() {
        let request: TransitionPrepareRequest = serde_json::from_value(serde_json::json!({
            "transition_id": Uuid::new_v4(), "confirm": true,
            "expected": {"mode":"machine", "local_remediation":false,
                "machine_name":"fwcloud-node", "lapi_url":"http://192.0.2.1:8080"},
            "target": {"mode":"lapi", "local_remediation":true},
            "authority_changed": true,
            "backend": "iptables",
            "machine_connectivity_pending": true
        }))
        .unwrap();

        assert!(validate(&request).is_ok());
        assert!(request.machine_connectivity_pending);
    }
    #[test]
    fn serializes_typed_recovery_outcomes_without_transition_state() {
        let response = TransitionRecoveryResponse {
            transition_id: Uuid::nil(),
            outcome: TransitionRecoveryOutcome::Restored,
        };
        assert_eq!(
            serde_json::to_value(response).unwrap(),
            serde_json::json!({
                "transition_id": "00000000-0000-0000-0000-000000000000",
                "outcome": "restored"
            })
        );
    }
}
