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
use std::path::Path;
use tokio::fs;
use uuid::Uuid;

use super::{
    errors::{NOT_INSTALLED, TRANSITION_INVALID, TRANSITION_UNSUPPORTED},
    lapi,
    models::CrowdSecFirewallBackend,
    packages,
    progress::{CrowdSecProgress, CrowdSecProgressMessageType},
};
use crate::errors::{FwcError, Result};

pub mod address;
pub mod remediation;
pub mod remote;
pub mod standalone;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransitionMode {
    Standalone,
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
    Standalone,
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

fn invalid(message: &'static str) -> FwcError {
    FwcError::crowdsec(TRANSITION_INVALID, message)
}

fn validate_target(target: &TransitionTarget) -> Result<()> {
    match target.mode {
        TransitionMode::Standalone => {
            if !target.local_remediation
                || target.machine_name.is_some()
                || target.lapi_url.is_some()
            {
                return Err(invalid(
                    "Standalone requires local remediation and no remote Machine fields",
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
            "Changing between standalone and Machine changes the Local API authority",
        ));
    }
    if request.expected.mode == TransitionMode::Standalone
        && request.target.mode == TransitionMode::Standalone
        && request.authority_changed
    {
        return Err(invalid(
            "Standalone cannot change to a remote Local API authority",
        ));
    }
    if request.machine_connectivity_pending
        && (request.expected.mode != TransitionMode::Machine
            || request.target.mode != TransitionMode::Standalone
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
            "expected": {"mode":"standalone", "local_remediation":true},
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
            "expected": {"mode":"standalone", "local_remediation":false},
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
    fn accepts_pending_machine_connectivity_when_restoring_standalone() {
        let request: TransitionPrepareRequest = serde_json::from_value(serde_json::json!({
            "transition_id": Uuid::new_v4(), "confirm": true,
            "expected": {"mode":"machine", "local_remediation":false,
                "machine_name":"fwcloud-node", "lapi_url":"http://192.0.2.1:8080"},
            "target": {"mode":"standalone", "local_remediation":true},
            "authority_changed": true,
            "backend": "iptables",
            "machine_connectivity_pending": true
        }))
        .unwrap();

        assert!(validate(&request).is_ok());
        assert!(request.machine_connectivity_pending);
    }
}
