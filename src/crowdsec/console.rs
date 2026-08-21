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
        capi,
        command::CrowdSecCommand,
        errors::CONSOLE_INVALID_ENROLLMENT,
        models::{
            CrowdSecCapiState, CrowdSecCapiStatus, CrowdSecConsoleState,
            CrowdSecConsoleStatusResponse,
        },
    },
    errors::{FwcError, Result},
};

const MAX_ENROLLMENT_KEY_LENGTH: usize = 512;
const MAX_INSTANCE_NAME_LENGTH: usize = 64;
const MAX_TAG_LENGTH: usize = 64;
const MAX_TAGS: usize = 16;

pub async fn status() -> Result<CrowdSecConsoleStatusResponse> {
    Ok(capi_status(capi::status().await?))
}

pub async fn enroll(
    enrollment_key: &str,
    name: Option<&str>,
    tags: Option<&[String]>,
) -> Result<CrowdSecConsoleStatusResponse> {
    validate_enrollment_key(enrollment_key)?;
    validate_instance_name(name)?;
    validate_tags(tags)?;

    let arguments = enrollment_arguments(enrollment_key, name, tags);

    CrowdSecCommand::cscli(&arguments)?.execute().await?;
    Ok(pending_approval_status())
}

fn validate_enrollment_key(enrollment_key: &str) -> Result<()> {
    if enrollment_key.is_empty()
        || enrollment_key.len() > MAX_ENROLLMENT_KEY_LENGTH
        || enrollment_key.chars().any(char::is_control)
    {
        return Err(FwcError::crowdsec(
            CONSOLE_INVALID_ENROLLMENT,
            "Invalid CrowdSec enrollment key",
        ));
    }

    Ok(())
}

fn validate_instance_name(name: Option<&str>) -> Result<()> {
    if let Some(name) = name {
        if !is_valid_console_identifier(name, MAX_INSTANCE_NAME_LENGTH) {
            return Err(FwcError::crowdsec(
                CONSOLE_INVALID_ENROLLMENT,
                "Invalid CrowdSec Console instance name",
            ));
        }
    }

    Ok(())
}

fn validate_tags(tags: Option<&[String]>) -> Result<()> {
    if let Some(tags) = tags {
        if tags.len() > MAX_TAGS
            || tags
                .iter()
                .any(|tag| !is_valid_console_identifier(tag, MAX_TAG_LENGTH))
        {
            return Err(FwcError::crowdsec(
                CONSOLE_INVALID_ENROLLMENT,
                "Invalid CrowdSec Console tags",
            ));
        }
    }

    Ok(())
}

fn is_valid_console_identifier(value: &str, maximum_length: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_length
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        })
}

fn enrollment_arguments<'a>(
    enrollment_key: &'a str,
    name: Option<&'a str>,
    tags: Option<&'a [String]>,
) -> Vec<&'a str> {
    let mut arguments = vec!["console", "enroll"];
    if let Some(name) = name {
        arguments.extend(["--name", name]);
    }
    if let Some(tags) = tags {
        for tag in tags {
            arguments.extend(["--tags", tag]);
        }
    }
    arguments.push(enrollment_key);
    arguments
}

fn capi_status(status: CrowdSecCapiStatus) -> CrowdSecConsoleStatusResponse {
    let state = match &status.state {
        CrowdSecCapiState::Connected => CrowdSecConsoleState::Connected,
        CrowdSecCapiState::NotConfigured => CrowdSecConsoleState::NotConfigured,
        CrowdSecCapiState::TemporarilyBlocked | CrowdSecCapiState::Error => {
            CrowdSecConsoleState::Error
        }
    };
    CrowdSecConsoleStatusResponse {
        message: capi_status_message(&state, status.retry_after_minutes).to_string(),
        state,
    }
}

fn pending_approval_status() -> CrowdSecConsoleStatusResponse {
    CrowdSecConsoleStatusResponse {
        state: CrowdSecConsoleState::PendingApproval,
        message: "Enrollment request submitted. Accept the Security Engine in CrowdSec Console to complete enrollment.".to_string(),
    }
}

fn capi_status_message(state: &CrowdSecConsoleState, retry_after_minutes: Option<u64>) -> String {
    match state {
        CrowdSecConsoleState::NotConfigured => {
            "CrowdSec Central API credentials are not configured".to_string()
        }
        CrowdSecConsoleState::PendingApproval => {
            unreachable!("CAPI status cannot determine enrollment approval")
        }
        CrowdSecConsoleState::Connected => {
            "CrowdSec Central API is reachable; CrowdSec Console approval cannot be checked locally"
                .to_string()
        }
        CrowdSecConsoleState::Error => match retry_after_minutes {
            Some(minutes) => format!(
                "CrowdSec Central API requests are temporarily blocked. Retry in {minutes} minutes."
            ),
            None => "Unable to determine CrowdSec Central API connectivity".to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{
        capi_status, enrollment_arguments, pending_approval_status, validate_enrollment_key,
        validate_instance_name, validate_tags,
    };
    use crate::{
        crowdsec::{
            errors::CONSOLE_INVALID_ENROLLMENT,
            models::{
                CrowdSecCapiState, CrowdSecCapiStatus, CrowdSecConsoleEnrollResponse,
                CrowdSecConsoleState, CrowdSecConsoleStatusResponse,
            },
        },
        errors::FwcError,
    };

    #[test]
    fn rejects_invalid_enrollment_values() {
        for enrollment_key in ["", "invalid\nkey"] {
            let error = validate_enrollment_key(enrollment_key).unwrap_err();
            assert!(matches!(
                error,
                FwcError::CrowdSec {
                    code: CONSOLE_INVALID_ENROLLMENT,
                    ..
                }
            ));
        }

        let error = validate_instance_name(Some("invalid name")).unwrap_err();
        assert!(matches!(
            error,
            FwcError::CrowdSec {
                code: CONSOLE_INVALID_ENROLLMENT,
                ..
            }
        ));

        let tags = ["valid".to_string(), "invalid tag".to_string()];
        let error = validate_tags(Some(&tags)).unwrap_err();
        assert!(matches!(
            error,
            FwcError::CrowdSec {
                code: CONSOLE_INVALID_ENROLLMENT,
                ..
            }
        ));
    }

    #[test]
    fn builds_separate_enrollment_arguments() {
        let tags = ["production".to_string(), "madrid".to_string()];
        let arguments = enrollment_arguments("enrollment-key", Some("fwcloud-01"), Some(&tags));

        assert_eq!(
            arguments,
            [
                "console",
                "enroll",
                "--name",
                "fwcloud-01",
                "--tags",
                "production",
                "--tags",
                "madrid",
                "enrollment-key",
            ]
        );
    }

    #[test]
    fn normalizes_capi_connection_states() {
        assert_eq!(
            capi_status(CrowdSecCapiStatus {
                state: CrowdSecCapiState::NotConfigured,
                retry_after_minutes: None,
            })
            .state,
            CrowdSecConsoleState::NotConfigured
        );
        assert_eq!(
            capi_status(CrowdSecCapiStatus {
                state: CrowdSecCapiState::Connected,
                retry_after_minutes: None,
            })
            .state,
            CrowdSecConsoleState::Connected
        );
        assert_eq!(
            capi_status(CrowdSecCapiStatus {
                state: CrowdSecCapiState::Error,
                retry_after_minutes: None,
            })
            .state,
            CrowdSecConsoleState::Error
        );
    }

    #[test]
    fn reports_the_remaining_minutes_for_a_temporary_capi_block() {
        let status = capi_status(CrowdSecCapiStatus {
            state: CrowdSecCapiState::TemporarilyBlocked,
            retry_after_minutes: Some(61),
        });

        assert_eq!(status.state, CrowdSecConsoleState::Error);
        assert!(status.message.contains("Retry in 61 minutes"));
    }

    #[test]
    fn enrollment_always_reports_pending_approval() {
        let status = pending_approval_status();

        assert_eq!(status.state, CrowdSecConsoleState::PendingApproval);
        assert!(status.message.contains("Accept the Security Engine"));
    }

    #[test]
    fn enrollment_response_never_serializes_the_enrollment_key() {
        let response = CrowdSecConsoleEnrollResponse {
            status: CrowdSecConsoleStatusResponse {
                state: CrowdSecConsoleState::PendingApproval,
                message: "CrowdSec Console enrollment is pending approval".to_string(),
            },
        };
        let response = serde_json::to_string(&response).unwrap();

        assert!(!response.contains("enrollment_key"));
        assert!(!response.contains("enrollment-key"));
    }
}
