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
pub struct StandaloneTransition {
    pub kind: TransitionKind,
    pub transition_id: Uuid,
    pub phase: TransitionPhase,
    pub expected: TransitionTarget,
    pub target: TransitionTarget,
    pub backend: Option<CrowdSecFirewallBackend>,
    pub changed: bool,
    pub central_machine_cleanup_required: bool,
    pub central_bouncer_cleanup_required: bool,
}

fn conflict() -> FwcError {
    FwcError::crowdsec(
        TRANSITION_CONFLICT,
        "CrowdSec standalone transition conflicts with current configuration or transition state",
    )
}
fn failed() -> FwcError {
    FwcError::crowdsec(TRANSITION_FAILED, "CrowdSec standalone transition failed")
}
fn recovery() -> FwcError {
    FwcError::crowdsec(
        TRANSITION_RECOVERY_REQUIRED,
        "CrowdSec standalone transition requires manual recovery",
    )
}
fn directory(data: &str) -> PathBuf {
    Path::new(data).join("crowdsec/transitions")
}
fn state_path(data: &str, id: Uuid) -> PathBuf {
    directory(data).join(format!("{id}.json"))
}

fn save(data: &str, state: &StandaloneTransition) -> Result<()> {
    let path = state_path(data, state.transition_id);
    let temporary = path.with_extension(format!("{}.tmp", Uuid::new_v4()));
    let contents = serde_json::to_vec(state).map_err(|_| failed())?;
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        std::io::Write::write_all(&mut file, &contents)?;
        file.sync_all()?;
        std::fs::rename(&temporary, &path)?;
        Ok(())
    })();
    if result.is_err() { let _ = std::fs::remove_file(temporary); }
    result.map_err(|_: FwcError| failed())
}

pub async fn load(data: &str, id: Uuid) -> Result<StandaloneTransition> {
    let state: StandaloneTransition = serde_json::from_slice(
        &fs::read(state_path(data, id)).await.map_err(|_| conflict())?,
    )
    .map_err(|_| recovery())?;
    if state.kind != TransitionKind::Standalone { return Err(conflict()); }
    Ok(state)
}

fn supported(request: &TransitionPrepareRequest) -> bool {
    request.authority_changed
        && request.expected.mode == TransitionMode::Machine
        && request.target.mode == TransitionMode::Standalone
}

pub async fn prepare(
    data: &str,
    request: &TransitionPrepareRequest,
    progress: &CrowdSecProgress,
) -> Result<StandaloneTransition> {
    validate(request)?;
    if !supported(request) { return Err(unsupported()); }
    if state_path(data, request.transition_id).exists() {
        let state = load(data, request.transition_id).await?;
        if state.expected != request.expected || state.target != request.target || state.backend != request.backend {
            return Err(conflict());
        }
        return Ok(state);
    }
    address::ensure_idle(data).await?;
    remote::verify_source(&request.expected, request.backend).await?;
    std::fs::create_dir_all(directory(data)).map_err(|_| failed())?;
    std::fs::set_permissions(directory(data), std::fs::Permissions::from_mode(0o700)).map_err(|_| failed())?;
    let state = StandaloneTransition {
        kind: TransitionKind::Standalone,
        transition_id: request.transition_id,
        phase: TransitionPhase::Prepared,
        expected: request.expected.clone(),
        target: request.target.clone(),
        backend: request.backend,
        changed: true,
        central_machine_cleanup_required: true,
        central_bouncer_cleanup_required: request.expected.local_remediation,
    };
    save(data, &state)?;
    progress.typed_message(
        CrowdSecProgressMessageType::Success,
        "CrowdSec standalone restoration is prepared; remove central Machine and Bouncer registrations before activation",
    );
    Ok(state)
}

pub async fn activate(
    data: &str,
    request: &TransitionActivateRequest,
    progress: &CrowdSecProgress,
) -> Result<StandaloneTransition> {
    if request.bouncer_api_key.is_some() { return Err(conflict()); }
    let mut state = load(data, request.transition_id).await?;
    if matches!(state.phase, TransitionPhase::ActivePendingFinalize | TransitionPhase::Completed) {
        return Ok(state);
    }
    if state.phase != TransitionPhase::Prepared { return Err(conflict()); }
    state.phase = TransitionPhase::Activating;
    save(data, &state)?;
    progress.typed_message(CrowdSecProgressMessageType::Info, "Restoring CrowdSec local Local API credentials");
    let result: Result<()> = async {
        if state.expected.local_remediation {
            bouncers::disable_local_remediation_with_progress(Some(progress)).await?;
        }
        lapi::restore_standalone_lapi().await?;
        bouncers::install_with_backend_and_progress(
            state.backend.ok_or_else(conflict)?,
            Some(progress),
        ).await?;
        Ok(())
    }.await;
    if let Err(error) = result {
        state.phase = TransitionPhase::RecoveryRequired;
        save(data, &state)?;
        return Err(error);
    }
    state.phase = TransitionPhase::ActivePendingFinalize;
    save(data, &state)?;
    progress.typed_message(CrowdSecProgressMessageType::Success, "CrowdSec standalone Local API and local remediation are active");
    Ok(state)
}

pub async fn finalize(data: &str, id: Uuid) -> Result<StandaloneTransition> {
    let mut state = load(data, id).await?;
    if !matches!(state.phase, TransitionPhase::ActivePendingFinalize | TransitionPhase::Completed) { return Err(conflict()); }
    state.phase = TransitionPhase::Completed;
    save(data, &state)?;
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_machine_to_standalone_authority_changes() {
        let request = TransitionPrepareRequest {
            transition_id: Uuid::new_v4(), confirm: true,
            expected: TransitionTarget {
                mode: TransitionMode::Machine, local_remediation: false,
                machine_name: Some("fwcloud-node".into()),
                lapi_url: Some("http://192.0.2.10:8080".into()),
            },
            target: TransitionTarget {
                mode: TransitionMode::Standalone, local_remediation: true,
                machine_name: None, lapi_url: None,
            },
            authority_changed: true, backend: Some(CrowdSecFirewallBackend::Iptables),
            preflight: None, ws_id: None,
        };
        assert!(supported(&request));
    }
}
