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

use super::*;
use crate::{
    crowdsec::{
        bouncers,
        errors::{TRANSITION_CONFLICT, TRANSITION_FAILED, TRANSITION_RECOVERY_REQUIRED},
        lapi,
    },
    errors::{FwcError, Result},
};
use serde::{Deserialize, Serialize};
use std::{
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use tokio::fs;
use uuid::Uuid;

#[derive(Deserialize, Serialize)]
pub struct RemediationTransition {
    pub kind: TransitionKind,
    pub transition_id: Uuid,
    pub phase: TransitionPhase,
    pub expected: TransitionTarget,
    pub target: TransitionTarget,
    pub backend: Option<CrowdSecFirewallBackend>,
    pub changed: bool,
    pub central_registration_cleanup_required: bool,
}

fn conflict() -> FwcError {
    FwcError::crowdsec(
        TRANSITION_CONFLICT,
        "CrowdSec remediation transition conflicts with current configuration or transition state",
    )
}
fn failed() -> FwcError {
    FwcError::crowdsec(
        TRANSITION_FAILED,
        "CrowdSec local remediation transition failed",
    )
}
fn recovery() -> FwcError {
    FwcError::crowdsec(
        TRANSITION_RECOVERY_REQUIRED,
        "CrowdSec remediation transition requires manual recovery",
    )
}
fn directory(data: &str) -> PathBuf {
    Path::new(data).join("crowdsec/transitions")
}
fn state_path(data: &str, id: Uuid) -> PathBuf {
    directory(data).join(format!("{id}.json"))
}

fn save(data: &str, state: &RemediationTransition) -> Result<()> {
    let path = state_path(data, state.transition_id);
    let temporary = path.with_extension(format!("{}.tmp", Uuid::new_v4()));
    let contents = serde_json::to_vec(state).map_err(|_| failed())?;
    let result = (|| {
        let mut options = std::fs::OpenOptions::new();
        let mut file = options
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        std::io::Write::write_all(&mut file, &contents)?;
        file.sync_all()?;
        std::fs::rename(&temporary, &path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result.map_err(|_: FwcError| failed())
}

pub async fn load(data: &str, id: Uuid) -> Result<RemediationTransition> {
    let state: RemediationTransition = serde_json::from_slice(
        &fs::read(state_path(data, id))
            .await
            .map_err(|_| conflict())?,
    )
    .map_err(|_| recovery())?;
    if state.kind != TransitionKind::Remediation {
        return Err(conflict());
    }
    Ok(state)
}

fn supported(request: &TransitionPrepareRequest) -> bool {
    !request.authority_changed
        && request.expected.mode == TransitionMode::Machine
        && request.target.mode == TransitionMode::Machine
        && request.expected.machine_name == request.target.machine_name
        && request.expected.lapi_url == request.target.lapi_url
        && request.expected.local_remediation != request.target.local_remediation
}

async fn verify_remote_url(target: &TransitionTarget) -> Result<String> {
    let credentials = fs::read_to_string("/etc/crowdsec/local_api_credentials.yaml")
        .await
        .map_err(|_| conflict())?;
    let configured = lapi::remote_lapi_url(&remote::root_scalar(&credentials, "url")?)?;
    let expected = lapi::remote_lapi_url(target.lapi_url.as_deref().ok_or_else(conflict)?)?;
    if configured != expected {
        return Err(conflict());
    }
    Ok(configured.to_string())
}

pub async fn prepare(
    data: &str,
    request: &TransitionPrepareRequest,
    progress: &CrowdSecProgress,
) -> Result<RemediationTransition> {
    validate(request)?;
    if !supported(request) {
        return Err(unsupported());
    }
    if state_path(data, request.transition_id).exists() {
        let state = load(data, request.transition_id).await?;
        if state.expected != request.expected
            || state.target != request.target
            || state.backend != request.backend
        {
            return Err(conflict());
        }
        return Ok(state);
    }
    address::ensure_idle(data).await?;
    preflight(request, progress).await?;
    let source_backend = if request.expected.local_remediation {
        Some(bouncers::configured_backend().await?.ok_or_else(conflict)?)
    } else {
        None
    };
    remote::verify_source(&request.expected, source_backend).await?;
    verify_remote_url(&request.expected).await?;
    if !request.expected.local_remediation && Path::new(bouncers::BOUNCER_CONFIG_PATH).exists() {
        return Err(conflict());
    }
    std::fs::create_dir_all(directory(data)).map_err(|_| failed())?;
    std::fs::set_permissions(directory(data), std::fs::Permissions::from_mode(0o700))
        .map_err(|_| failed())?;
    let state = RemediationTransition {
        kind: TransitionKind::Remediation,
        transition_id: request.transition_id,
        phase: TransitionPhase::Prepared,
        expected: request.expected.clone(),
        target: request.target.clone(),
        backend: request.backend,
        changed: true,
        central_registration_cleanup_required: !request.target.local_remediation,
    };
    save(data, &state)?;
    progress.typed_message(
        CrowdSecProgressMessageType::Success,
        if state.target.local_remediation {
            "CrowdSec local remediation is prepared; a central Bouncer key is required to activate it"
        } else {
            "CrowdSec local remediation removal is prepared; remove its central Bouncer registration before activation"
        },
    );
    Ok(state)
}

pub async fn activate(
    data: &str,
    request: &TransitionActivateRequest,
    progress: &CrowdSecProgress,
) -> Result<RemediationTransition> {
    let mut state = load(data, request.transition_id).await?;
    if matches!(
        state.phase,
        TransitionPhase::ActivePendingFinalize | TransitionPhase::Completed
    ) {
        return Ok(state);
    }
    if state.phase != TransitionPhase::Prepared {
        return Err(conflict());
    }
    let lapi_url = verify_remote_url(&state.expected).await?;
    state.phase = TransitionPhase::Activating;
    save(data, &state)?;
    let result = if state.target.local_remediation {
        let api_key = request
            .bouncer_api_key
            .as_deref()
            .filter(|key| !key.is_empty())
            .ok_or_else(|| {
                FwcError::crowdsec(
                    crate::crowdsec::errors::BOUNCER_INVALID,
                    "A central CrowdSec Firewall Bouncer API key is required",
                )
            })?;
        bouncers::install_with_remote_lapi_and_progress(
            state.backend.ok_or_else(conflict)?,
            &lapi_url,
            api_key,
            Some(progress),
        )
        .await
        .map(|_| ())
    } else {
        if request.bouncer_api_key.is_some() {
            return Err(conflict());
        }
        bouncers::disable_local_remediation_with_progress(Some(progress)).await
    };
    if result.is_err() {
        state.phase = if state.target.local_remediation {
            TransitionPhase::Prepared
        } else {
            TransitionPhase::RecoveryRequired
        };
        save(data, &state)?;
        return Err(result.err().unwrap_or_else(failed));
    }
    state.phase = TransitionPhase::ActivePendingFinalize;
    save(data, &state)?;
    progress.typed_message(
        CrowdSecProgressMessageType::Success,
        "CrowdSec local remediation transition is active and awaits topology finalization",
    );
    Ok(state)
}

pub async fn finalize(data: &str, id: Uuid) -> Result<RemediationTransition> {
    let mut state = load(data, id).await?;
    if !matches!(
        state.phase,
        TransitionPhase::ActivePendingFinalize | TransitionPhase::Completed
    ) {
        return Err(conflict());
    }
    state.phase = TransitionPhase::Completed;
    save(data, &state)?;
    Ok(state)
}

/// A prepared remediation transition has not changed local configuration and
/// can be cancelled safely. Once removal has started, recreating the central
/// Bouncer registration is an API-coordinated operation, so the agent keeps
/// the failure visible instead of guessing a replacement key.
pub async fn recover(data: &str, id: Uuid) -> Result<RemediationTransition> {
    let mut state = load(data, id).await?;
    if state.phase == TransitionPhase::RolledBack {
        return Ok(state);
    }
    if state.phase != TransitionPhase::Prepared {
        return Err(recovery());
    }
    state.phase = TransitionPhase::RolledBack;
    save(data, &state)?;
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_machine_remediation_changes() {
        let machine = |local_remediation| TransitionTarget {
            mode: TransitionMode::Machine,
            local_remediation,
            machine_name: Some("fwcloud-node".into()),
            lapi_url: Some("http://192.0.2.10:8080".into()),
        };
        let request = TransitionPrepareRequest {
            transition_id: Uuid::new_v4(),
            confirm: true,
            expected: machine(false),
            target: machine(true),
            authority_changed: false,
            backend: Some(CrowdSecFirewallBackend::Iptables),
            ws_id: None,
        };
        assert!(supported(&request));
    }

    #[tokio::test]
    async fn cancels_a_prepared_plan_without_storing_a_bouncer_key() {
        let root =
            std::env::temp_dir().join(format!("fwcloud-remediation-test-{}", Uuid::new_v4()));
        let data = root.to_str().unwrap();
        std::fs::create_dir_all(directory(data)).unwrap();
        let id = Uuid::new_v4();
        let target = TransitionTarget {
            mode: TransitionMode::Machine,
            local_remediation: false,
            machine_name: Some("fwcloud-node".into()),
            lapi_url: Some("http://192.0.2.10:8080".into()),
        };
        let state = RemediationTransition {
            kind: TransitionKind::Remediation,
            transition_id: id,
            phase: TransitionPhase::Prepared,
            expected: target.clone(),
            target,
            backend: None,
            changed: true,
            central_registration_cleanup_required: true,
        };
        save(data, &state).unwrap();
        assert!(!std::fs::read_to_string(state_path(data, id))
            .unwrap()
            .contains("api_key"));
        assert_eq!(
            recover(data, id).await.unwrap().phase,
            TransitionPhase::RolledBack
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
