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

use std::{net::SocketAddr, time::Duration};

use log::debug;
use serde_json::Value;
use tokio::{fs, process::Command, time::timeout};

use crate::{
    crowdsec::{
        command::CrowdSecCommand,
        errors::{
            COMMAND_FAILED, LAPI_INVALID, LAPI_UNREACHABLE, MACHINE_INVALID, MACHINE_NOT_FOUND,
        },
        models::{
            CrowdSecCentralLapiConfigureResponse, CrowdSecMachine, CrowdSecMachineRemoveResponse,
            CrowdSecMachineState, CrowdSecMachineValidationResponse, CrowdSecMachinesResponse,
        },
        packages,
    },
    errors::{FwcError, Result},
};

const CROWDSEC_CONFIG_PATH: &str = "/etc/crowdsec/config.yaml";
const CROWDSEC_SERVICE: &str = "crowdsec.service";
const SYSTEMCTL_COMMAND: &str = "/usr/bin/systemctl";
const SERVICE_COMMAND_TIMEOUT: Duration = Duration::from_secs(60);

pub async fn configure_central(listen_uri: &str) -> Result<CrowdSecCentralLapiConfigureResponse> {
    validate_listen_uri(listen_uri)?;
    require_crowdsec_installed().await?;

    let configuration = fs::read_to_string(CROWDSEC_CONFIG_PATH)
        .await
        .map_err(|_| {
            FwcError::crowdsec(
                LAPI_UNREACHABLE,
                "Unable to read CrowdSec Local API configuration",
            )
        })?;
    let updated_configuration = central_lapi_configuration(&configuration, listen_uri);

    if updated_configuration != configuration {
        debug!("Configuring CrowdSec Local API listener: {}", listen_uri);
        fs::write(CROWDSEC_CONFIG_PATH, updated_configuration)
            .await
            .map_err(|_| {
                FwcError::crowdsec(
                    LAPI_UNREACHABLE,
                    "Unable to write CrowdSec Local API configuration",
                )
            })?;
        restart_crowdsec_service().await?;
    }

    ensure_local_api_reachable().await?;

    Ok(CrowdSecCentralLapiConfigureResponse {
        listen_uri: listen_uri.to_string(),
        message: "CrowdSec Local API is configured for remote machines".to_string(),
    })
}

pub async fn machines() -> Result<CrowdSecMachinesResponse> {
    require_crowdsec_installed().await?;
    ensure_local_api_reachable().await?;

    let output = CrowdSecCommand::cscli(&["machines", "list", "-o", "json"])?
        .execute()
        .await?;
    let value = serde_json::from_str::<Value>(output.stdout())
        .map_err(|_| FwcError::crowdsec(COMMAND_FAILED, "Unable to read CrowdSec machine list"))?;

    Ok(CrowdSecMachinesResponse {
        machines: machines_from_json(&value),
    })
}

pub async fn validate_machine(name: &str) -> Result<CrowdSecMachineValidationResponse> {
    validate_machine_name(name)?;
    let machine = machine_by_name(name).await?;

    if machine.state == CrowdSecMachineState::Validated {
        return Ok(CrowdSecMachineValidationResponse {
            name: machine.name,
            state: CrowdSecMachineState::Validated,
            message: "CrowdSec machine is already validated".to_string(),
        });
    }

    debug!("Validating CrowdSec machine: {}", name);
    CrowdSecCommand::cscli(&["machines", "validate", name])?
        .execute()
        .await?;

    Ok(CrowdSecMachineValidationResponse {
        name: name.to_string(),
        state: CrowdSecMachineState::Validated,
        message: "CrowdSec machine is validated".to_string(),
    })
}

pub async fn remove_machine(name: &str) -> Result<CrowdSecMachineRemoveResponse> {
    validate_machine_name(name)?;
    let _machine = machine_by_name(name).await?;

    debug!("Removing CrowdSec machine: {}", name);
    CrowdSecCommand::cscli(&["machines", "delete", name])?
        .execute()
        .await?;

    Ok(CrowdSecMachineRemoveResponse {
        name: name.to_string(),
        message: "CrowdSec machine is removed".to_string(),
    })
}

pub async fn register_bouncer(
    name: &str,
) -> Result<crate::crowdsec::models::CrowdSecBouncerRegisterResponse> {
    require_crowdsec_installed().await?;
    ensure_local_api_reachable().await?;
    crate::crowdsec::bouncers::register(name).await
}

async fn machine_by_name(name: &str) -> Result<CrowdSecMachine> {
    machines()
        .await?
        .machines
        .into_iter()
        .find(|machine| machine.name == name)
        .ok_or_else(|| FwcError::crowdsec(MACHINE_NOT_FOUND, "CrowdSec machine is not registered"))
}

async fn require_crowdsec_installed() -> Result<()> {
    if packages::package_status().await?.crowdsec_installed {
        Ok(())
    } else {
        Err(FwcError::crowdsec(
            crate::crowdsec::errors::NOT_INSTALLED,
            "CrowdSec is not installed",
        ))
    }
}

async fn ensure_local_api_reachable() -> Result<()> {
    let output = CrowdSecCommand::cscli(&["lapi", "status"])?
        .execute_allow_failure()
        .await?;

    if output.succeeded() {
        Ok(())
    } else {
        Err(FwcError::crowdsec(
            LAPI_UNREACHABLE,
            "CrowdSec Local API is unavailable",
        ))
    }
}

async fn restart_crowdsec_service() -> Result<()> {
    let output = timeout(
        SERVICE_COMMAND_TIMEOUT,
        Command::new(SYSTEMCTL_COMMAND)
            .args(["restart", CROWDSEC_SERVICE])
            .output(),
    )
    .await
    .map_err(|_| FwcError::crowdsec(COMMAND_FAILED, "CrowdSec service restart timed out"))??;

    if output.status.success() {
        Ok(())
    } else {
        Err(FwcError::crowdsec(
            COMMAND_FAILED,
            "Unable to restart CrowdSec service",
        ))
    }
}

fn validate_listen_uri(listen_uri: &str) -> Result<()> {
    if listen_uri.parse::<SocketAddr>().is_ok() {
        Ok(())
    } else {
        Err(FwcError::crowdsec(
            LAPI_INVALID,
            "CrowdSec Local API listener must be a valid IP address and port",
        ))
    }
}

fn validate_machine_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 128
        || !name.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        return Err(FwcError::crowdsec(
            MACHINE_INVALID,
            "Invalid CrowdSec machine name",
        ));
    }

    Ok(())
}

fn machines_from_json(value: &Value) -> Vec<CrowdSecMachine> {
    let Some(machines) = value.as_array() else {
        return Vec::new();
    };

    machines
        .iter()
        .filter_map(machine_from_json)
        .collect::<Vec<_>>()
}

fn machine_from_json(value: &Value) -> Option<CrowdSecMachine> {
    let values = value.as_object()?;
    let name = values
        .get("machineId")
        .or_else(|| values.get("machine_id"))
        .or_else(|| values.get("name"))
        .and_then(Value::as_str)?;

    let validated = values
        .get("isValidated")
        .or_else(|| values.get("is_validated"))
        .and_then(Value::as_bool);
    let state = match validated {
        Some(true) => CrowdSecMachineState::Validated,
        Some(false) => CrowdSecMachineState::Pending,
        None => CrowdSecMachineState::Unknown,
    };
    let last_heartbeat = values
        .get("last_push")
        .or_else(|| values.get("last_heartbeat"))
        .or_else(|| values.get("updated_at"))
        .and_then(value_as_string);

    Some(CrowdSecMachine {
        name: name.to_string(),
        state,
        last_heartbeat,
    })
}

fn value_as_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) if !value.is_empty() => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn central_lapi_configuration(configuration: &str, listen_uri: &str) -> String {
    let mut lines = configuration
        .lines()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let trailing_newline = configuration.ends_with('\n');
    let api_index = lines.iter().position(|line| line.trim() == "api:");

    let Some(api_index) = api_index else {
        if !lines.is_empty() && !lines.last().is_some_and(String::is_empty) {
            lines.push(String::new());
        }
        lines.extend([
            "api:".to_string(),
            "  server:".to_string(),
            "    enable: true".to_string(),
            format!("    listen_uri: {listen_uri}"),
        ]);
        return with_trailing_newline(lines, trailing_newline);
    };

    let api_indent = indentation(&lines[api_index]);
    let api_end = block_end(&lines, api_index, api_indent);
    let server_index = (api_index + 1..api_end).find(|index| {
        indentation(&lines[*index]) == api_indent + 2 && lines[*index].trim() == "server:"
    });

    let Some(server_index) = server_index else {
        lines.splice(
            api_index + 1..api_index + 1,
            [
                format!("{}  server:", " ".repeat(api_indent)),
                format!("{}    enable: true", " ".repeat(api_indent)),
                format!("{}    listen_uri: {listen_uri}", " ".repeat(api_indent)),
            ],
        );
        return with_trailing_newline(lines, trailing_newline);
    };

    let server_indent = indentation(&lines[server_index]);
    let server_end = block_end(&lines, server_index, server_indent);
    let mut has_enable = false;
    let mut has_listen_uri = false;

    for line in lines.iter_mut().take(server_end).skip(server_index + 1) {
        if indentation(line) != server_indent + 2 {
            continue;
        }
        if line.trim_start().starts_with("enable:") {
            *line = format!("{}enable: true", " ".repeat(server_indent + 2));
            has_enable = true;
        } else if line.trim_start().starts_with("listen_uri:") {
            *line = format!("{}listen_uri: {listen_uri}", " ".repeat(server_indent + 2));
            has_listen_uri = true;
        }
    }

    let mut additions = Vec::new();
    if !has_enable {
        additions.push(format!("{}enable: true", " ".repeat(server_indent + 2)));
    }
    if !has_listen_uri {
        additions.push(format!(
            "{}listen_uri: {listen_uri}",
            " ".repeat(server_indent + 2)
        ));
    }
    if !additions.is_empty() {
        lines.splice(server_index + 1..server_index + 1, additions);
    }

    with_trailing_newline(lines, trailing_newline)
}

fn block_end(lines: &[String], start: usize, indentation_level: usize) -> usize {
    lines
        .iter()
        .enumerate()
        .skip(start + 1)
        .find_map(|(index, line)| {
            (!line.trim().is_empty()
                && !line.trim_start().starts_with('#')
                && indentation(line) <= indentation_level)
                .then_some(index)
        })
        .unwrap_or(lines.len())
}

fn indentation(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

fn with_trailing_newline(lines: Vec<String>, trailing_newline: bool) -> String {
    let mut configuration = lines.join("\n");
    if trailing_newline {
        configuration.push('\n');
    }
    configuration
}

#[cfg(test)]
mod tests {
    use super::{central_lapi_configuration, machine_from_json, validate_listen_uri};
    use crate::crowdsec::models::CrowdSecMachineState;
    use serde_json::json;

    #[test]
    fn updates_the_existing_local_api_listener() {
        let configuration = "api:\n  client:\n    credentials_path: /etc/crowdsec/local_api_credentials.yaml\n  server:\n    enable: false\n    listen_uri: 127.0.0.1:8080\ncommon:\n  log_media: stdout\n";

        let updated = central_lapi_configuration(configuration, "192.0.2.10:8080");

        assert!(updated.contains("    enable: true\n"));
        assert!(updated.contains("    listen_uri: 192.0.2.10:8080\n"));
        assert!(updated.contains("common:\n  log_media: stdout\n"));
    }

    #[test]
    fn adds_a_server_section_when_it_is_absent() {
        let updated = central_lapi_configuration("api:\n  client: {}\n", "0.0.0.0:8080");

        assert!(updated.contains("  server:\n    enable: true\n    listen_uri: 0.0.0.0:8080\n"));
    }

    #[test]
    fn validates_ip_address_and_port_listener() {
        assert!(validate_listen_uri("192.0.2.10:8080").is_ok());
        assert!(validate_listen_uri("[2001:db8::10]:8080").is_ok());
        assert!(validate_listen_uri("lapi.example.test:8080").is_err());
    }

    #[test]
    fn normalizes_machine_status_and_last_heartbeat() {
        let machine = machine_from_json(&json!({
            "machineId": "fwcloud-machine-1",
            "isValidated": false,
            "last_push": "2026-09-01T10:00:00Z"
        }))
        .unwrap();

        assert_eq!(machine.name, "fwcloud-machine-1");
        assert_eq!(machine.state, CrowdSecMachineState::Pending);
        assert_eq!(
            machine.last_heartbeat.as_deref(),
            Some("2026-09-01T10:00:00Z")
        );
    }
}
