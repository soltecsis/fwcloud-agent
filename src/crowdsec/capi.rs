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

    You should have received a copy of the GNU Affero General Public License
    along with FWCloud.  If not, see <https://www.gnu.org/licenses/>.
*/

use std::{
    future::Future,
    io::ErrorKind,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use tokio::fs;

use crate::{
    crowdsec::{
        command::CrowdSecCommand,
        errors::COMMAND_FAILED,
        models::{CrowdSecCapiState, CrowdSecCapiStatus},
    },
    errors::{FwcError, Result},
};

pub const CAPI_COOLDOWN_DURATION: Duration = Duration::from_secs(61 * 60);
const CAPI_COOLDOWN_STATE_PATH: &str = "./data/crowdsec/capi-cooldown.json";

#[derive(Deserialize, Serialize)]
struct CapiCooldownState {
    retry_at_unix_seconds: u64,
}

struct CapiStatusCheck {
    from_cooldown: bool,
    status: CrowdSecCapiStatus,
}

pub async fn status() -> Result<CrowdSecCapiStatus> {
    let check = status_with_active_cooldown(active_cooldown().await?, execute_status_check).await?;
    if check.from_cooldown {
        return Ok(check.status);
    }

    let status = check.status;
    match &status.state {
        CrowdSecCapiState::Connected => {
            clear_cooldown().await?;
            Ok(status)
        }
        CrowdSecCapiState::TemporarilyBlocked => start_cooldown().await,
        CrowdSecCapiState::NotConfigured | CrowdSecCapiState::Error => Ok(status),
    }
}

async fn execute_status_check() -> Result<CrowdSecCapiStatus> {
    let output = CrowdSecCommand::cscli(&["capi", "status", "-o", "json"])?
        .execute_allow_failure()
        .await?;
    let diagnostics = format!("{}\n{}", output.stdout(), output.stderr());
    let status = if output_uses_unsupported_json_option(&diagnostics) {
        let output = CrowdSecCommand::cscli(&["capi", "status"])?
            .execute_allow_failure()
            .await?;
        status_from_command_output(output.succeeded(), output.stdout(), output.stderr())
    } else {
        status_from_command_output(output.succeeded(), output.stdout(), output.stderr())
    };

    Ok(status)
}

async fn status_with_active_cooldown<F, Fut>(
    active_cooldown: Option<CrowdSecCapiStatus>,
    status_check: F,
) -> Result<CapiStatusCheck>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<CrowdSecCapiStatus>>,
{
    match active_cooldown {
        Some(status) => Ok(CapiStatusCheck {
            from_cooldown: true,
            status,
        }),
        None => Ok(CapiStatusCheck {
            from_cooldown: false,
            status: status_check().await?,
        }),
    }
}

pub fn status_from_command_output(
    succeeded: bool,
    stdout: &str,
    stderr: &str,
) -> CrowdSecCapiStatus {
    let diagnostics = format!("{stdout}\n{stderr}").to_ascii_lowercase();
    let state = if succeeded {
        CrowdSecCapiState::Connected
    } else if is_not_configured(&diagnostics) {
        CrowdSecCapiState::NotConfigured
    } else if is_temporarily_blocked(&diagnostics) {
        CrowdSecCapiState::TemporarilyBlocked
    } else {
        CrowdSecCapiState::Error
    };

    CrowdSecCapiStatus {
        state,
        retry_after_minutes: None,
    }
}

pub fn is_not_configured(diagnostics: &str) -> bool {
    diagnostics.contains("not enrolled")
        || diagnostics.contains("not registered")
        || diagnostics.contains("no credentials")
        || diagnostics.contains("online_api_credentials")
        || diagnostics.contains("credentials file")
}

pub async fn start_cooldown() -> Result<CrowdSecCapiStatus> {
    let now = current_unix_seconds()?;
    let retry_at_unix_seconds = now + CAPI_COOLDOWN_DURATION.as_secs();
    write_cooldown(CAPI_COOLDOWN_STATE_PATH, retry_at_unix_seconds).await?;

    Ok(cooldown_status(retry_at_unix_seconds - now))
}

pub async fn active_cooldown() -> Result<Option<CrowdSecCapiStatus>> {
    active_cooldown_at(CAPI_COOLDOWN_STATE_PATH, current_unix_seconds()?).await
}

pub async fn clear_cooldown() -> Result<()> {
    remove_cooldown(CAPI_COOLDOWN_STATE_PATH).await
}

async fn active_cooldown_at(path: &str, now: u64) -> Result<Option<CrowdSecCapiStatus>> {
    let state = match fs::read_to_string(path).await {
        Ok(contents) => serde_json::from_str::<CapiCooldownState>(&contents).map_err(|_| {
            FwcError::crowdsec(
                COMMAND_FAILED,
                "Unable to read CrowdSec CAPI cooldown state",
            )
        })?,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return Err(FwcError::crowdsec(
                COMMAND_FAILED,
                "Unable to read CrowdSec CAPI cooldown state",
            ));
        }
    };

    if state.retry_at_unix_seconds <= now {
        remove_cooldown(path).await?;
        return Ok(None);
    }

    Ok(Some(cooldown_status(state.retry_at_unix_seconds - now)))
}

async fn write_cooldown(path: &str, retry_at_unix_seconds: u64) -> Result<()> {
    let parent = Path::new(path).parent().ok_or_else(|| {
        FwcError::crowdsec(
            COMMAND_FAILED,
            "Unable to determine CrowdSec CAPI data directory",
        )
    })?;
    fs::create_dir_all(parent).await.map_err(|_| {
        FwcError::crowdsec(
            COMMAND_FAILED,
            "Unable to create CrowdSec CAPI data directory",
        )
    })?;
    let state = serde_json::to_string(&CapiCooldownState {
        retry_at_unix_seconds,
    })
    .map_err(|_| FwcError::crowdsec(COMMAND_FAILED, "Unable to save CrowdSec CAPI cooldown"))?;

    fs::write(path, state)
        .await
        .map_err(|_| FwcError::crowdsec(COMMAND_FAILED, "Unable to save CrowdSec CAPI cooldown"))
}

async fn remove_cooldown(path: &str) -> Result<()> {
    match fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(_) => Err(FwcError::crowdsec(
            COMMAND_FAILED,
            "Unable to remove CrowdSec CAPI cooldown",
        )),
    }
}

fn cooldown_status(remaining_seconds: u64) -> CrowdSecCapiStatus {
    CrowdSecCapiStatus {
        state: CrowdSecCapiState::TemporarilyBlocked,
        retry_after_minutes: Some((remaining_seconds + 59) / 60),
    }
}

fn current_unix_seconds() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| FwcError::crowdsec(COMMAND_FAILED, "Unable to read current system time"))
}

fn is_temporarily_blocked(diagnostics: &str) -> bool {
    diagnostics.contains("api error: forbidden")
        || diagnostics.contains("http status 403")
        || diagnostics.contains("status code: 403")
        || diagnostics.contains("http 403")
}

fn output_uses_unsupported_json_option(diagnostics: &str) -> bool {
    let diagnostics = diagnostics.to_ascii_lowercase();
    diagnostics.contains("unknown flag") && diagnostics.contains("output")
}

#[cfg(test)]
mod tests {
    use super::{
        active_cooldown_at, cooldown_status, remove_cooldown, status_from_command_output,
        status_with_active_cooldown, write_cooldown,
    };
    use crate::crowdsec::models::{CrowdSecCapiState, CrowdSecCapiStatus};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use uuid::Uuid;

    #[test]
    fn recognizes_a_temporary_capi_403_block() {
        let status = status_from_command_output(
            false,
            "",
            "Failed to authenticate to Central API (CAPI): API error: Forbidden",
        );

        assert_eq!(status.state, CrowdSecCapiState::TemporarilyBlocked);
        assert_eq!(status.retry_after_minutes, None);
    }

    #[test]
    fn keeps_regular_capi_errors_distinct_from_a_temporary_block() {
        let status = status_from_command_output(false, "", "network timeout");

        assert_eq!(status.state, CrowdSecCapiState::Error);
        assert_eq!(status.retry_after_minutes, None);
    }

    #[test]
    fn recognizes_not_configured_capi_credentials() {
        let status = status_from_command_output(false, "", "no credentials found");

        assert_eq!(status.state, CrowdSecCapiState::NotConfigured);
    }

    #[test]
    fn rounds_cooldown_time_up_to_whole_minutes() {
        assert_eq!(cooldown_status(1).retry_after_minutes, Some(1));
        assert_eq!(cooldown_status(61).retry_after_minutes, Some(2));
    }

    #[tokio::test]
    async fn expires_and_removes_the_cooldown_file() {
        let path =
            std::env::temp_dir().join(format!("fwcloud-crowdsec-capi-{}.json", Uuid::new_v4()));
        let path = path.to_string_lossy().to_string();

        write_cooldown(&path, 100).await.unwrap();

        assert!(active_cooldown_at(&path, 100).await.unwrap().is_none());
        assert!(!std::path::Path::new(&path).exists());
        remove_cooldown(&path).await.unwrap();
    }

    #[tokio::test]
    async fn reads_an_active_cooldown_from_the_persisted_file() {
        let path =
            std::env::temp_dir().join(format!("fwcloud-crowdsec-capi-{}.json", Uuid::new_v4()));
        let path = path.to_string_lossy().to_string();

        write_cooldown(&path, 161).await.unwrap();

        let status = active_cooldown_at(&path, 100).await.unwrap().unwrap();
        assert_eq!(status.state, CrowdSecCapiState::TemporarilyBlocked);
        assert_eq!(status.retry_after_minutes, Some(2));
        remove_cooldown(&path).await.unwrap();
    }

    #[tokio::test]
    async fn suppresses_the_capi_command_while_a_cooldown_is_active() {
        let command_called = Arc::new(AtomicBool::new(false));
        let command_called_by_check = Arc::clone(&command_called);
        let active_status = cooldown_status(61);

        let result = status_with_active_cooldown(Some(active_status), move || {
            command_called_by_check.store(true, Ordering::SeqCst);
            async {
                Ok(CrowdSecCapiStatus {
                    state: CrowdSecCapiState::Connected,
                    retry_after_minutes: None,
                })
            }
        })
        .await
        .unwrap();

        assert!(result.from_cooldown);
        assert!(!command_called.load(Ordering::SeqCst));
        assert_eq!(result.status.state, CrowdSecCapiState::TemporarilyBlocked);
    }

    #[tokio::test]
    async fn successful_recovery_removes_the_cooldown_file() {
        let path =
            std::env::temp_dir().join(format!("fwcloud-crowdsec-capi-{}.json", Uuid::new_v4()));
        let path = path.to_string_lossy().to_string();

        write_cooldown(&path, 161).await.unwrap();
        remove_cooldown(&path).await.unwrap();

        assert!(active_cooldown_at(&path, 100).await.unwrap().is_none());
        assert!(!std::path::Path::new(&path).exists());
    }
}
