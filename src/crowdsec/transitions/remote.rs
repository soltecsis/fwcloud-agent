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
        command::CrowdSecCommand,
        errors::{TRANSITION_CONFLICT, TRANSITION_FAILED, TRANSITION_RECOVERY_REQUIRED},
        lapi,
    },
    errors::{FwcError, Result},
};
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{fs, process::Command, time::timeout};
use uuid::Uuid;

const CONFIG: &str = "/etc/crowdsec/config.yaml";
const CREDENTIALS: &str = "/etc/crowdsec/local_api_credentials.yaml";
const ENGINE: &str = "crowdsec.service";
const BOUNCER: &str = "crowdsec-firewall-bouncer.service";

#[derive(Deserialize, Serialize)]
pub struct RemoteTransition {
    pub kind: TransitionKind,
    pub transition_id: Uuid,
    pub phase: TransitionPhase,
    pub expected: TransitionTarget,
    pub target: TransitionTarget,
    pub backend: Option<CrowdSecFirewallBackend>,
    pub changed: bool,
}

// This is only ever written to the 0600 recovery file and is never returned.
#[derive(Deserialize, Serialize)]
struct Backup {
    configuration: String,
    credentials: Option<String>,
    bouncer: Option<String>,
    engine_running: bool,
    bouncer_running: bool,
}

fn failed() -> FwcError {
    FwcError::crowdsec(
        TRANSITION_FAILED,
        "CrowdSec Local API authority transition failed",
    )
}
fn conflict() -> FwcError {
    FwcError::crowdsec(
        TRANSITION_CONFLICT,
        "CrowdSec transition conflicts with current configuration or transition state",
    )
}
fn recovery() -> FwcError {
    FwcError::crowdsec(
        TRANSITION_RECOVERY_REQUIRED,
        "CrowdSec authority transition requires recovery before further changes",
    )
}
fn directory(data: &str) -> PathBuf {
    Path::new(data).join("crowdsec/transitions")
}
fn state_path(data: &str, id: Uuid) -> PathBuf {
    directory(data).join(format!("{id}.json"))
}
fn backup_path(data: &str, id: Uuid) -> PathBuf {
    directory(data).join(format!("{id}.backup"))
}

fn staged_credentials_path(id: Uuid) -> PathBuf {
    Path::new(CREDENTIALS)
        .with_file_name(format!(".fwcloud-crowdsec-transition-{id}.credentials"))
}

async fn stash_credentials(id: Uuid) -> Result<Option<PathBuf>> {
    let path = staged_credentials_path(id);
    match fs::rename(CREDENTIALS, &path).await {
        Ok(()) => Ok(Some(path)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(failed()),
    }
}

async fn restore_stashed_credentials(path: Option<&Path>) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    match fs::remove_file(CREDENTIALS).await {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(_) => return Err(failed()),
    }
    fs::rename(path, CREDENTIALS).await.map_err(|_| failed())
}

async fn discard_stashed_credentials(path: Option<&Path>) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    match fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(failed()),
    }
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    let temp = path.with_extension(format!("{}.tmp", Uuid::new_v4()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(contents)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)?;
        std::fs::File::open(path.parent().ok_or_else(failed)?)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result.map_err(|_: FwcError| failed())
}

fn save(data: &str, state: &RemoteTransition) -> Result<()> {
    atomic_write(
        &state_path(data, state.transition_id),
        &serde_json::to_vec(state).map_err(|_| failed())?,
    )
}

pub async fn load(data: &str, id: Uuid) -> Result<RemoteTransition> {
    let bytes = fs::read(state_path(data, id))
        .await
        .map_err(|_| conflict())?;
    let state: RemoteTransition = serde_json::from_slice(&bytes).map_err(|_| recovery())?;
    if state.kind != TransitionKind::Remote {
        return Err(conflict());
    }
    Ok(state)
}

async fn service(action: &str, name: &str) -> Result<()> {
    let arguments: Vec<&str> = match action {
        "disable --now" => vec!["disable", "--now", name],
        "enable --now" => vec!["enable", "--now", name],
        _ => vec![action, name],
    };
    let output = timeout(
        Duration::from_secs(60),
        Command::new("/usr/bin/systemctl").args(arguments).output(),
    )
    .await
    .map_err(|_| failed())?
    .map_err(|_| failed())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(failed())
    }
}

async fn disable_service_if_present(name: &str) -> Result<()> {
    let output = timeout(
        Duration::from_secs(15),
        Command::new("/usr/bin/systemctl")
            .args(["show", "--property=LoadState", "--value", name])
            .output(),
    )
    .await
    .map_err(|_| failed())?
    .map_err(|_| failed())?;
    if !output.status.success()
        || String::from_utf8_lossy(&output.stdout).trim() == "not-found"
    {
        return Ok(());
    }
    service("disable --now", name).await
}

async fn running(name: &str) -> Result<bool> {
    let output = timeout(
        Duration::from_secs(15),
        Command::new("/usr/bin/systemctl")
            .args(["is-active", name])
            .output(),
    )
    .await
    .map_err(|_| failed())?
    .map_err(|_| failed())?;
    match String::from_utf8_lossy(&output.stdout).trim() {
        "active" => Ok(true),
        "inactive" | "failed" | "unknown" => Ok(false),
        _ => Err(conflict()),
    }
}

async fn backup() -> Result<Backup> {
    let configuration = fs::read_to_string(CONFIG).await.map_err(|_| conflict())?;
    let credentials = match fs::read_to_string(CREDENTIALS).await {
        Ok(value) => Some(value),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(conflict()),
    };
    let bouncer = match fs::read_to_string(bouncers::BOUNCER_CONFIG_PATH).await {
        Ok(value) => Some(value),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(conflict()),
    };
    Ok(Backup {
        configuration,
        credentials,
        bouncer,
        engine_running: running(ENGINE).await?,
        bouncer_running: running(BOUNCER).await?,
    })
}

pub(crate) fn root_scalar(contents: &str, key: &str) -> Result<String> {
    let mut values = contents
        .lines()
        .filter_map(|line| line.strip_prefix(&format!("{key}:")));
    let raw = values.next().ok_or_else(conflict)?.trim();
    if values.next().is_some() {
        return Err(conflict());
    }
    let value = raw
        .split(" #")
        .next()
        .unwrap_or(raw)
        .trim_matches(['\'', '"'])
        .trim();
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        return Err(conflict());
    }
    Ok(value.to_string())
}

pub(crate) async fn verify_source(
    expected: &TransitionTarget,
    backend: Option<CrowdSecFirewallBackend>,
) -> Result<()> {
    let configuration = fs::read_to_string(CONFIG).await.map_err(|_| conflict())?;
    match expected.mode {
        TransitionMode::Lapi => {
            if !configuration
                .lines()
                .any(|line| line.trim() == "enable: true")
            {
                return Err(conflict());
            }
        }
        TransitionMode::Machine => {
            let credentials = fs::read_to_string(CREDENTIALS)
                .await
                .map_err(|_| conflict())?;
            if root_scalar(&credentials, "login")?
                != expected.machine_name.as_deref().ok_or_else(conflict)?
                || lapi::remote_lapi_url(&root_scalar(&credentials, "url")?)?
                    != lapi::remote_lapi_url(expected.lapi_url.as_deref().ok_or_else(conflict)?)?
            {
                return Err(conflict());
            }
        }
    }
    if expected.local_remediation {
        let configuration = fs::read_to_string(bouncers::BOUNCER_CONFIG_PATH)
            .await
            .map_err(|_| conflict())?;
        if !bouncers::configuration_is_fwcloud_managed(&configuration)
            || !bouncers::configuration_is_set_only(&configuration, backend.ok_or_else(conflict)?)
        {
            return Err(conflict());
        }
    }
    Ok(())
}

pub(crate) async fn verify_pending_machine_source(expected: &TransitionTarget) -> Result<()> {
    if expected.mode != TransitionMode::Machine || expected.local_remediation {
        return Err(conflict());
    }
    let configuration = fs::read_to_string(CONFIG).await.map_err(|_| conflict())?;
    if !configuration
        .lines()
        .any(|line| line.trim() == "enable: false")
    {
        return Err(conflict());
    }
    match fs::read_to_string(CREDENTIALS).await {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(conflict()),
    }
}

async fn restore(backup: &Backup) -> Result<()> {
    let _ = service("disable --now", BOUNCER).await;
    let _ = service("disable --now", ENGINE).await;
    // Restore the credential file before any other state. A failed role change
    // must never leave the previous Machine credentials absent or truncated.
    match &backup.credentials {
        Some(credentials) => atomic_write(Path::new(CREDENTIALS), credentials.as_bytes())?,
        None => match fs::remove_file(CREDENTIALS).await {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(failed()),
        },
    }
    atomic_write(Path::new(CONFIG), backup.configuration.as_bytes())?;
    match &backup.bouncer {
        Some(configuration) => atomic_write(
            Path::new(bouncers::BOUNCER_CONFIG_PATH),
            configuration.as_bytes(),
        )?,
        None => match fs::remove_file(bouncers::BOUNCER_CONFIG_PATH).await {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(failed()),
        },
    }
    if backup.engine_running {
        service("enable --now", ENGINE).await?;
    }
    if backup.bouncer_running {
        service("enable --now", BOUNCER).await?;
    }
    Ok(())
}

fn is_supported(request: &TransitionPrepareRequest) -> bool {
    request.authority_changed && request.target.mode == TransitionMode::Machine
}

pub async fn prepare(
    data: &str,
    request: &TransitionPrepareRequest,
    progress: &CrowdSecProgress,
) -> Result<RemoteTransition> {
    validate(request)?;
    if !is_supported(request) {
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
    verify_source(&request.expected, source_backend).await?;
    progress.typed_message(
        CrowdSecProgressMessageType::Warning,
        "Active CrowdSec decisions are not migrated to the new Local API",
    );
    let backup = backup().await?;
    std::fs::create_dir_all(directory(data)).map_err(|_| failed())?;
    std::fs::set_permissions(directory(data), std::fs::Permissions::from_mode(0o700))
        .map_err(|_| failed())?;
    let mut state = RemoteTransition {
        kind: TransitionKind::Remote,
        transition_id: request.transition_id,
        phase: TransitionPhase::Preparing,
        expected: request.expected.clone(),
        target: request.target.clone(),
        backend: request.backend,
        changed: true,
    };
    atomic_write(
        &backup_path(data, state.transition_id),
        &serde_json::to_vec(&backup).map_err(|_| failed())?,
    )?;
    save(data, &state)?;
    progress.typed_message(
        CrowdSecProgressMessageType::Info,
        "Stopping CrowdSec services before remote Machine registration",
    );
    let mut registered = false;
    let mut staged_credentials = None;
    let result: Result<()> = async {
        disable_service_if_present(BOUNCER).await?;
        service("disable --now", ENGINE).await?;
        if request.expected.local_remediation && !state.target.local_remediation {
            bouncers::disable_local_remediation_with_progress(Some(progress)).await?;
        }
        lapi::configure_remote_machine().await?;
        // cscli lapi register writes its generated credentials to the configured
        // path. Move the current file aside instead of deleting it so a failed
        // registration can restore the source Machine without relying on a
        // later, broader rollback.
        staged_credentials = stash_credentials(state.transition_id).await?;
        let lapi_url =
            lapi::remote_lapi_url(state.target.lapi_url.as_deref().ok_or_else(conflict)?)?;
        CrowdSecCommand::cscli(&[
            "lapi",
            "register",
            "--machine",
            state.target.machine_name.as_deref().ok_or_else(conflict)?,
            "--url",
            lapi_url.as_str(),
        ])?
        .execute()
        .await?;
        registered = true;
        discard_stashed_credentials(staged_credentials.as_deref()).await?;
        lapi::restrict_machine_credentials_permissions().await
    }
    .await;
    if let Err(error) = result {
        let restored = !registered
            && restore_stashed_credentials(staged_credentials.as_deref())
                .await
                .is_ok()
            && restore(&backup).await.is_ok();
        if registered {
            progress.typed_message(
                CrowdSecProgressMessageType::Error,
                "CrowdSec Machine registration may exist in the new central Local API; cleanup is required before recovery",
            );
            state.phase = TransitionPhase::RecoveryRequired;
            save(data, &state)?;
        } else if restored {
            progress.typed_message(
                CrowdSecProgressMessageType::Error,
                "CrowdSec Machine registration failed; restoring the previous role",
            );
            state.phase = TransitionPhase::RolledBack;
            save(data, &state)?;
            let _ = fs::remove_file(backup_path(data, state.transition_id)).await;
        } else {
            state.phase = TransitionPhase::RecoveryRequired;
            save(data, &state)?;
        }
        return Err(error);
    }
    state.phase = TransitionPhase::AwaitingValidation;
    save(data, &state)?;
    progress.typed_message(
        CrowdSecProgressMessageType::Success,
        "CrowdSec Machine is registered and awaits central Local API validation",
    );
    Ok(state)
}

pub async fn activate(
    data: &str,
    request: &TransitionActivateRequest,
    progress: &CrowdSecProgress,
) -> Result<RemoteTransition> {
    let mut state = load(data, request.transition_id).await?;
    if matches!(
        state.phase,
        TransitionPhase::ActivePendingFinalize | TransitionPhase::Completed
    ) {
        return Ok(state);
    }
    if state.phase != TransitionPhase::AwaitingValidation {
        return Err(conflict());
    }
    state.phase = TransitionPhase::Activating;
    save(data, &state)?;
    let name = state.target.machine_name.as_deref().ok_or_else(conflict)?;
    let backend = state.backend.unwrap_or(CrowdSecFirewallBackend::Iptables);
    let result = lapi::activate_remote_machine(
        name,
        state.target.local_remediation,
        backend,
        request.bouncer_api_key.as_deref(),
        Some(progress),
    )
    .await;
    if let Err(error) = result {
        state.phase = TransitionPhase::AwaitingValidation;
        save(data, &state)?;
        return Err(error);
    }
    state.phase = TransitionPhase::ActivePendingFinalize;
    save(data, &state)?;
    progress.typed_message(
        CrowdSecProgressMessageType::Success,
        "CrowdSec Machine transition is active and awaits topology finalization",
    );
    Ok(state)
}

pub async fn recover(data: &str, id: Uuid) -> Result<RemoteTransition> {
    let mut state = load(data, id).await?;
    if state.phase == TransitionPhase::RolledBack {
        return Ok(state);
    }
    if !matches!(
        state.phase,
        TransitionPhase::Preparing
            | TransitionPhase::AwaitingValidation
            | TransitionPhase::RecoveryRequired
    ) {
        return Err(conflict());
    }
    let backup: Backup = serde_json::from_slice(
        &fs::read(backup_path(data, id))
            .await
            .map_err(|_| recovery())?,
    )
    .map_err(|_| recovery())?;
    if restore(&backup).await.is_err() {
        state.phase = TransitionPhase::RecoveryRequired;
        save(data, &state)?;
        return Err(recovery());
    }
    state.phase = TransitionPhase::RolledBack;
    save(data, &state)?;
    fs::remove_file(backup_path(data, id))
        .await
        .map_err(|_| failed())?;
    let staged_credentials = staged_credentials_path(id);
    let _ = discard_stashed_credentials(Some(&staged_credentials)).await;
    Ok(state)
}

pub async fn finalize(data: &str, id: Uuid) -> Result<RemoteTransition> {
    let mut state = load(data, id).await?;
    if !matches!(
        state.phase,
        TransitionPhase::ActivePendingFinalize | TransitionPhase::Completed
    ) {
        return Err(conflict());
    }
    match fs::remove_file(backup_path(data, id)).await {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(_) => return Err(failed()),
    }
    state.phase = TransitionPhase::Completed;
    save(data, &state)?;
    let staged_credentials = staged_credentials_path(id);
    let _ = discard_stashed_credentials(Some(&staged_credentials)).await;
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepares_authority_changes_to_a_machine_with_or_without_remediation() {
        let target = TransitionTarget {
            mode: TransitionMode::Machine,
            local_remediation: false,
            machine_name: Some("fwcloud-node".to_string()),
            lapi_url: Some("http://192.0.2.10:8080".to_string()),
        };
        let request = TransitionPrepareRequest {
            transition_id: Uuid::new_v4(),
            confirm: true,
            expected: TransitionTarget {
                mode: TransitionMode::Lapi,
                local_remediation: false,
                machine_name: None,
                lapi_url: None,
            },
            target,
            authority_changed: true,
            backend: None,
            machine_connectivity_pending: false,
            ws_id: None,
        };
        assert!(is_supported(&request));
        let without_remediation = TransitionPrepareRequest {
            transition_id: Uuid::new_v4(),
            confirm: true,
            expected: TransitionTarget {
                mode: TransitionMode::Lapi,
                local_remediation: true,
                machine_name: None,
                lapi_url: None,
            },
            target: TransitionTarget {
                mode: TransitionMode::Machine,
                local_remediation: false,
                machine_name: Some("fwcloud-node".to_string()),
                lapi_url: Some("http://192.0.2.10:8080".to_string()),
            },
            authority_changed: true,
            backend: None,
            machine_connectivity_pending: false,
            ws_id: None,
        };
        assert!(is_supported(&without_remediation));
        let mut unchanged = request;
        unchanged.authority_changed = false;
        assert!(!is_supported(&unchanged));
    }

    #[test]
    fn rejects_ambiguous_credential_values() {
        assert!(root_scalar("url: one\nurl: two\n", "url").is_err());
        assert!(root_scalar("url: http://192.0.2.10:8080\n", "url").is_ok());
    }
}
