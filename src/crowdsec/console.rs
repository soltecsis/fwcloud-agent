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
        command::CrowdSecCommand,
        errors::INVALID_COMMAND,
        models::{CrowdSecConsoleState, CrowdSecConsoleStatusResponse},
    },
    errors::{FwcError, Result},
};

const MAX_ENROLLMENT_KEY_LENGTH: usize = 512;
const MAX_INSTANCE_NAME_LENGTH: usize = 64;
const MAX_TAG_LENGTH: usize = 64;
const MAX_TAGS: usize = 16;

pub async fn status() -> Result<CrowdSecConsoleStatusResponse> {
    let output = CrowdSecCommand::cscli(&["capi", "status", "-o", "json"])?
        .execute_allow_failure()
        .await?;

    if output.succeeded() && !output_is_pending_approval(output.stdout()) {
        return Ok(console_status(true, output.stdout(), output.stderr()));
    }

    let diagnostics = format!("{}\n{}", output.stdout(), output.stderr());
    if output_uses_unsupported_json_option(&diagnostics) {
        let output = CrowdSecCommand::cscli(&["capi", "status"])?
            .execute_allow_failure()
            .await?;
        return Ok(console_status(
            output.succeeded(),
            output.stdout(),
            output.stderr(),
        ));
    }

    Ok(console_status(
        output.succeeded(),
        output.stdout(),
        output.stderr(),
    ))
}

pub async fn enroll(
    enrollment_key: &str,
    name: Option<&str>,
    tags: Option<&[String]>,
) -> Result<CrowdSecConsoleStatusResponse> {
    validate_enrollment_key(enrollment_key)?;
    validate_instance_name(name)?;
    validate_tags(tags)?;

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

    CrowdSecCommand::cscli(&arguments)?.execute().await?;
    status().await
}

fn validate_enrollment_key(enrollment_key: &str) -> Result<()> {
    if enrollment_key.is_empty()
        || enrollment_key.len() > MAX_ENROLLMENT_KEY_LENGTH
        || enrollment_key.chars().any(char::is_control)
    {
        return Err(FwcError::crowdsec(
            INVALID_COMMAND,
            "Invalid CrowdSec enrollment key",
        ));
    }

    Ok(())
}

fn validate_instance_name(name: Option<&str>) -> Result<()> {
    if let Some(name) = name {
        if !is_valid_console_identifier(name, MAX_INSTANCE_NAME_LENGTH) {
            return Err(FwcError::crowdsec(
                INVALID_COMMAND,
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
                INVALID_COMMAND,
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

fn console_status(succeeded: bool, stdout: &str, stderr: &str) -> CrowdSecConsoleStatusResponse {
    let diagnostics = format!("{}\n{}", stdout, stderr).to_ascii_lowercase();
    let state = if is_pending_approval(&diagnostics) {
        CrowdSecConsoleState::PendingApproval
    } else if succeeded {
        CrowdSecConsoleState::Connected
    } else if is_not_configured(&diagnostics) {
        CrowdSecConsoleState::NotConfigured
    } else {
        CrowdSecConsoleState::Error
    };

    CrowdSecConsoleStatusResponse {
        message: console_status_message(&state).to_string(),
        state,
    }
}

fn output_is_pending_approval(output: &str) -> bool {
    is_pending_approval(&output.to_ascii_lowercase())
}

fn is_pending_approval(diagnostics: &str) -> bool {
    diagnostics.contains("pending approval")
        || diagnostics.contains("pending validation")
        || diagnostics.contains("waiting for validation")
        || diagnostics.contains("not yet validated")
}

fn is_not_configured(diagnostics: &str) -> bool {
    diagnostics.contains("not enrolled")
        || diagnostics.contains("not registered")
        || diagnostics.contains("no credentials")
        || diagnostics.contains("online_api_credentials")
        || diagnostics.contains("credentials file")
}

fn output_uses_unsupported_json_option(diagnostics: &str) -> bool {
    let diagnostics = diagnostics.to_ascii_lowercase();
    diagnostics.contains("unknown flag") && diagnostics.contains("output")
}

fn console_status_message(state: &CrowdSecConsoleState) -> &'static str {
    match state {
        CrowdSecConsoleState::NotConfigured => "CrowdSec Console is not configured",
        CrowdSecConsoleState::PendingApproval => "CrowdSec Console enrollment is pending approval",
        CrowdSecConsoleState::Connected => "CrowdSec Console is connected",
        CrowdSecConsoleState::Error => "Unable to determine CrowdSec Console status",
    }
}
