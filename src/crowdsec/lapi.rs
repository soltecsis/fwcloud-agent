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

use std::{
    io::{self, ErrorKind},
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    time::Duration,
};

use log::debug;
use serde_json::Value;
use tokio::{fs, process::Command, task, time::timeout};
use url::Url;

use crate::{
    crowdsec::{
        bouncers,
        command::{CrowdSecCommand, CrowdSecCommandOutput},
        errors::{
            COMMAND_FAILED, LAPI_CONNECTION_FAILED, LAPI_CONNECTION_REFUSED,
            LAPI_CONNECTION_TIMEOUT, LAPI_HOST_UNRESOLVABLE, LAPI_INVALID, LAPI_UNREACHABLE,
            MACHINE_INVALID, MACHINE_NOT_FOUND,
            MACHINE_REAUTHENTICATION_REQUIRED,
        },
        install,
        models::{
            CrowdSecCentralLapiConfigureResponse, CrowdSecFirewallBackend, CrowdSecMachine,
            CrowdSecMachineRemoveResponse,
            CrowdSecMachineState, CrowdSecMachineValidationResponse, CrowdSecMachinesResponse,
            CrowdSecRemoteMachineActivationResponse, CrowdSecRemoteMachineInstallResponse,
        },
        packages,
        progress::{CrowdSecProgress, CrowdSecProgressMessageType},
    },
    errors::{FwcError, Result},
};

const CROWDSEC_CONFIG_PATH: &str = "/etc/crowdsec/config.yaml";
const CROWDSEC_SERVICE: &str = "crowdsec.service";
const SYSTEMCTL_COMMAND: &str = "/usr/bin/systemctl";
const SERVICE_COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
const REMOTE_LAPI_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

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

/// Restores an installed remote Machine as a standalone CrowdSec node. Remote
/// credentials must never be reused against the local API: a new local client
/// credential is generated before the engine is started.
pub(crate) async fn restore_standalone_lapi() -> Result<()> {
    require_crowdsec_installed().await?;
    disable_crowdsec_service().await?;
    let configuration = fs::read_to_string(CROWDSEC_CONFIG_PATH)
        .await
        .map_err(|_| FwcError::crowdsec(LAPI_UNREACHABLE, "Unable to read CrowdSec Local API configuration"))?;
    let updated_configuration = central_lapi_configuration(&configuration, "127.0.0.1:8080");
    if updated_configuration != configuration {
        fs::write(CROWDSEC_CONFIG_PATH, updated_configuration)
            .await
            .map_err(|_| FwcError::crowdsec(LAPI_UNREACHABLE, "Unable to restore CrowdSec local Local API configuration"))?;
    }
    remove_machine_credentials().await?;
    CrowdSecCommand::cscli(&["machines", "add", "--auto"])?
        .execute()
        .await?;
    restrict_machine_credentials_permissions().await?;
    enable_crowdsec_service().await?;
    ensure_local_api_reachable().await
}

pub async fn machines() -> Result<CrowdSecMachinesResponse> {
    ensure_central_ready().await?;

    let output = CrowdSecCommand::cscli(&["machines", "list", "-o", "json"])?
        .execute()
        .await?;
    let value = serde_json::from_str::<Value>(output.stdout())
        .map_err(|_| FwcError::crowdsec(COMMAND_FAILED, "Unable to read CrowdSec machine list"))?;

    Ok(CrowdSecMachinesResponse {
        machines: machines_from_json(&value),
    })
}

pub async fn ensure_central_ready() -> Result<()> {
    require_crowdsec_installed().await?;
    ensure_local_api_reachable().await
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

pub async fn install_remote_machine(
    machine_name: &str,
    lapi_url: &str,
    progress: Option<&CrowdSecProgress>,
) -> Result<CrowdSecRemoteMachineInstallResponse> {
    validate_machine_name(machine_name)?;
    let lapi_url = remote_lapi_url(lapi_url)?;

    emit_progress(progress, "Checking central CrowdSec Local API connectivity");
    ensure_remote_lapi_reachable(&lapi_url).await?;
    emit_success(progress, "Central CrowdSec Local API is reachable");

    emit_progress(
        progress,
        "Stopping existing CrowdSec service before machine configuration",
    );
    disable_crowdsec_service_if_present().await?;
    emit_success(
        progress,
        "CrowdSec service is stopped before machine configuration",
    );

    emit_progress(
        progress,
        "Removing existing local CrowdSec Firewall Bouncer before machine configuration",
    );
    bouncers::uninstall_for_crowdsec_with_progress(progress).await?;
    emit_success(
        progress,
        "Existing local CrowdSec Firewall Bouncer is removed before machine configuration",
    );

    emit_progress(progress, "Installing CrowdSec packages and dependencies");
    packages::install_packages_with_progress(progress).await?;
    emit_success(progress, "CrowdSec packages and dependencies are ready");

    emit_progress(progress, "Updating CrowdSec Hub index");
    install::update_hub().await?;
    emit_success(progress, "CrowdSec Hub index is up to date");

    install::install_default_collections(progress).await?;

    emit_progress(
        progress,
        "Stopping CrowdSec until central machine validation",
    );
    disable_crowdsec_service().await?;
    emit_success(
        progress,
        "CrowdSec service is stopped pending central validation",
    );
    configure_remote_machine().await?;

    emit_progress(
        progress,
        "Registering CrowdSec machine with the central Local API",
    );
    remove_machine_credentials().await?;
    CrowdSecCommand::cscli(&[
        "lapi",
        "register",
        "--machine",
        machine_name,
        "--url",
        lapi_url.as_str(),
    ])?
    .execute()
    .await?;
    restrict_machine_credentials_permissions().await?;
    emit_success(
        progress,
        "CrowdSec machine is registered and pending central validation",
    );

    Ok(CrowdSecRemoteMachineInstallResponse {
        machine_name: machine_name.to_string(),
        lapi_url: lapi_url.to_string(),
        state: CrowdSecMachineState::Pending,
        message: "CrowdSec machine is registered and awaits central validation".to_string(),
    })
}

pub async fn activate_remote_machine(
    machine_name: &str,
    local_remediation: bool,
    backend: CrowdSecFirewallBackend,
    bouncer_api_key: Option<&str>,
    progress: Option<&CrowdSecProgress>,
) -> Result<CrowdSecRemoteMachineActivationResponse> {
    validate_machine_name(machine_name)?;
    require_crowdsec_installed().await?;

    emit_progress(
        progress,
        "Checking central validation of the CrowdSec machine",
    );
    ensure_remote_machine_is_validated().await?;
    emit_success(
        progress,
        "CrowdSec machine is validated by the central Local API",
    );

    if local_remediation {
        let bouncer_api_key = bouncer_api_key
            .filter(|api_key| !api_key.is_empty())
            .ok_or_else(|| {
                FwcError::crowdsec(
                    crate::crowdsec::errors::BOUNCER_INVALID,
                    "CrowdSec Firewall Bouncer API key is required for local remediation",
                )
            })?;
        let lapi_url = configured_remote_lapi_url().await?;

        emit_progress(progress, "Configuring local CrowdSec Firewall Bouncer");
        bouncers::install_with_remote_lapi_and_progress(
            backend,
            &lapi_url,
            bouncer_api_key,
            progress,
        )
        .await?;
        emit_success(progress, "Local CrowdSec Firewall Bouncer is configured");
    }

    emit_progress(progress, "Starting CrowdSec machine service");
    enable_crowdsec_service().await?;
    emit_success(progress, "CrowdSec machine service is enabled and running");

    Ok(CrowdSecRemoteMachineActivationResponse {
        machine_name: machine_name.to_string(),
        state: CrowdSecMachineState::Validated,
        local_remediation,
        message: if local_remediation {
            "CrowdSec machine is validated, running and configured for local remediation"
                .to_string()
        } else {
            "CrowdSec machine is validated and running".to_string()
        },
    })
}

pub async fn reauthenticate_remote_machine(
    machine_name: &str,
    lapi_url: &str,
    progress: Option<&CrowdSecProgress>,
) -> Result<CrowdSecRemoteMachineInstallResponse> {
    validate_machine_name(machine_name)?;
    require_crowdsec_installed().await?;
    let lapi_url = remote_lapi_url(lapi_url)?;

    emit_progress(progress, "Checking central CrowdSec Local API connectivity");
    ensure_remote_lapi_reachable(&lapi_url).await?;
    emit_success(progress, "Central CrowdSec Local API is reachable");

    emit_progress(progress, "Stopping CrowdSec machine service before reauthentication");
    disable_crowdsec_service().await?;
    emit_success(progress, "CrowdSec machine service is stopped before reauthentication");
    configure_remote_machine().await?;

    emit_progress(progress, "Registering CrowdSec machine with the central Local API");
    remove_machine_credentials().await?;
    CrowdSecCommand::cscli(&[
        "lapi",
        "register",
        "--machine",
        machine_name,
        "--url",
        lapi_url.as_str(),
    ])?
    .execute()
    .await?;
    restrict_machine_credentials_permissions().await?;
    emit_success(progress, "CrowdSec machine is registered and pending central validation");

    Ok(CrowdSecRemoteMachineInstallResponse {
        machine_name: machine_name.to_string(),
        lapi_url: lapi_url.to_string(),
        state: CrowdSecMachineState::Pending,
        message: "CrowdSec machine is registered and awaits central validation".to_string(),
    })
}

pub async fn resume_remote_machine(
    machine_name: &str,
    local_remediation: bool,
    progress: Option<&CrowdSecProgress>,
) -> Result<CrowdSecRemoteMachineActivationResponse> {
    validate_machine_name(machine_name)?;
    require_crowdsec_installed().await?;

    emit_progress(progress, "Checking central validation of the CrowdSec machine");
    ensure_remote_machine_is_validated().await?;
    emit_success(progress, "CrowdSec machine is validated by the central Local API");

    emit_progress(progress, "Starting CrowdSec machine service");
    enable_crowdsec_service().await?;
    emit_success(progress, "CrowdSec machine service is enabled and running");

    Ok(CrowdSecRemoteMachineActivationResponse {
        machine_name: machine_name.to_string(),
        state: CrowdSecMachineState::Validated,
        local_remediation,
        message: "CrowdSec machine is validated and running".to_string(),
    })
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

async fn ensure_remote_machine_is_validated() -> Result<()> {
    let output = CrowdSecCommand::cscli(&["lapi", "status"])?
        .execute_allow_failure()
        .await?;

    if output.succeeded() {
        Ok(())
    } else if requires_machine_reauthentication(&output) {
        Err(FwcError::crowdsec(
            MACHINE_REAUTHENTICATION_REQUIRED,
            "CrowdSec machine is no longer registered in the central Local API. Register and validate it again.",
        ))
    } else {
        Err(FwcError::crowdsec(
            LAPI_UNREACHABLE,
            "CrowdSec machine is not validated by the central Local API",
        ))
    }
}

pub(crate) fn requires_machine_reauthentication(output: &CrowdSecCommandOutput) -> bool {
    machine_reauthentication_required_message(output.stdout())
        || machine_reauthentication_required_message(output.stderr())
}

fn machine_reauthentication_required_message(value: &str) -> bool {
    value.to_ascii_lowercase().contains("machine not found")
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

async fn enable_crowdsec_service() -> Result<()> {
    let output = timeout(
        SERVICE_COMMAND_TIMEOUT,
        Command::new(SYSTEMCTL_COMMAND)
            .args(["enable", "--now", CROWDSEC_SERVICE])
            .output(),
    )
    .await
    .map_err(|_| FwcError::crowdsec(COMMAND_FAILED, "CrowdSec service command timed out"))??;

    if output.status.success() {
        Ok(())
    } else {
        Err(FwcError::crowdsec(
            COMMAND_FAILED,
            "Unable to start CrowdSec machine service",
        ))
    }
}

async fn disable_crowdsec_service() -> Result<()> {
    let output = timeout(
        SERVICE_COMMAND_TIMEOUT,
        Command::new(SYSTEMCTL_COMMAND)
            .args(["disable", "--now", CROWDSEC_SERVICE])
            .output(),
    )
    .await
    .map_err(|_| FwcError::crowdsec(COMMAND_FAILED, "CrowdSec service command timed out"))??;

    if output.status.success() {
        Ok(())
    } else {
        Err(FwcError::crowdsec(
            COMMAND_FAILED,
            "Unable to stop CrowdSec service pending central validation",
        ))
    }
}

async fn disable_crowdsec_service_if_present() -> Result<()> {
    let output = timeout(
        SERVICE_COMMAND_TIMEOUT,
        Command::new(SYSTEMCTL_COMMAND)
            .args(["show", "--property=LoadState", "--value", CROWDSEC_SERVICE])
            .output(),
    )
    .await
    .map_err(|_| FwcError::crowdsec(COMMAND_FAILED, "CrowdSec service command timed out"))??;

    if !output.status.success() || String::from_utf8_lossy(&output.stdout).trim() == "not-found" {
        return Ok(());
    }

    disable_crowdsec_service().await
}

pub(crate) async fn restrict_machine_credentials_permissions() -> Result<()> {
    let output = Command::new("/usr/bin/chmod")
        .args(["0600", "/etc/crowdsec/local_api_credentials.yaml"])
        .output()
        .await
        .map_err(|_| {
            FwcError::crowdsec(
                COMMAND_FAILED,
                "Unable to protect CrowdSec machine credentials",
            )
        })?;

    if output.status.success() {
        Ok(())
    } else {
        Err(FwcError::crowdsec(
            COMMAND_FAILED,
            "Unable to protect CrowdSec machine credentials",
        ))
    }
}

pub(crate) async fn remove_machine_credentials() -> Result<()> {
    match fs::remove_file("/etc/crowdsec/local_api_credentials.yaml").await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(FwcError::crowdsec(
            COMMAND_FAILED,
            "Unable to remove existing CrowdSec machine credentials",
        )),
    }
}

pub(crate) async fn configure_remote_machine() -> Result<()> {
    let configuration = fs::read_to_string(CROWDSEC_CONFIG_PATH)
        .await
        .map_err(|_| {
            FwcError::crowdsec(
                LAPI_UNREACHABLE,
                "Unable to read CrowdSec Local API configuration",
            )
        })?;
    let updated_configuration = remote_machine_configuration(&configuration);

    if updated_configuration != configuration {
        fs::write(CROWDSEC_CONFIG_PATH, updated_configuration)
            .await
            .map_err(|_| {
                FwcError::crowdsec(
                    LAPI_UNREACHABLE,
                    "Unable to configure CrowdSec as a remote machine",
                )
            })?;
    }

    Ok(())
}

pub(crate) async fn configured_remote_lapi_url() -> Result<String> {
    let credentials = fs::read_to_string("/etc/crowdsec/local_api_credentials.yaml")
        .await
        .map_err(|_| {
            FwcError::crowdsec(
                LAPI_UNREACHABLE,
                "Unable to read CrowdSec machine credentials",
            )
        })?;
    let lapi_url = credentials
        .lines()
        .find_map(|line| line.trim().strip_prefix("url:").map(str::trim))
        .ok_or_else(|| {
            FwcError::crowdsec(
                LAPI_UNREACHABLE,
                "CrowdSec machine credentials do not define a Local API URL",
            )
        })?;

    Ok(remote_lapi_url(lapi_url)?.to_string())
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

pub(crate) fn remote_lapi_url(value: &str) -> Result<Url> {
    let url = Url::parse(value).map_err(|_| invalid_remote_lapi_error())?;
    if !matches!(url.scheme(), "http" | "https")
        || url.port().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
        || url.host().is_none()
    {
        return Err(invalid_remote_lapi_error());
    }

    Ok(url)
}

pub(crate) async fn ensure_remote_lapi_reachable(url: &Url) -> Result<()> {
    let host = url
        .host_str()
        .ok_or_else(invalid_remote_lapi_error)?
        .to_string();
    let port = url.port().ok_or_else(invalid_remote_lapi_error)?;
    let address = task::spawn_blocking(move || remote_lapi_socket_address(&host, port))
        .await
        .map_err(|_| {
            FwcError::crowdsec(
                LAPI_CONNECTION_FAILED,
                "CrowdSec Local API connection failed",
            )
        })?
        .map_err(|_| remote_lapi_resolution_error())?;

    task::spawn_blocking(move || TcpStream::connect_timeout(&address, REMOTE_LAPI_CONNECT_TIMEOUT))
        .await
        .map_err(|_| {
            FwcError::crowdsec(
                LAPI_CONNECTION_FAILED,
                "CrowdSec Local API connection failed",
            )
        })?
        .map(|_| ())
        .map_err(|error| remote_lapi_connection_error(error.kind()))
}

fn remote_lapi_socket_address(host: &str, port: u16) -> io::Result<SocketAddr> {
    (host, port).to_socket_addrs()?.next().ok_or_else(|| {
        io::Error::new(
            ErrorKind::NotFound,
            "CrowdSec Local API host has no address",
        )
    })
}

fn remote_lapi_resolution_error() -> FwcError {
    FwcError::crowdsec(
        LAPI_HOST_UNRESOLVABLE,
        "CrowdSec Local API host cannot be resolved",
    )
}

fn remote_lapi_connection_error(kind: ErrorKind) -> FwcError {
    match kind {
        ErrorKind::ConnectionRefused => FwcError::crowdsec(
            LAPI_CONNECTION_REFUSED,
            "CrowdSec Local API connection was refused",
        ),
        ErrorKind::TimedOut => FwcError::crowdsec(
            LAPI_CONNECTION_TIMEOUT,
            "CrowdSec Local API connection timed out",
        ),
        _ => FwcError::crowdsec(
            LAPI_CONNECTION_FAILED,
            "CrowdSec Local API connection failed",
        ),
    }
}

fn invalid_remote_lapi_error() -> FwcError {
    FwcError::crowdsec(
        LAPI_INVALID,
        "CrowdSec Local API URL must use an HTTP or HTTPS host and explicit port",
    )
}

fn emit_progress(progress: Option<&CrowdSecProgress>, message: &str) {
    if let Some(progress) = progress {
        progress.typed_message(CrowdSecProgressMessageType::Info, message);
    }
}

fn emit_success(progress: Option<&CrowdSecProgress>, message: &str) {
    if let Some(progress) = progress {
        progress.typed_message(CrowdSecProgressMessageType::Success, message);
    }
}

pub(crate) fn validate_machine_name(name: &str) -> Result<()> {
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

    let mut normalized_machines = machines
        .iter()
        .filter_map(machine_from_json)
        .collect::<Vec<_>>();
    normalized_machines.sort_by(|left, right| left.name.cmp(&right.name));
    normalized_machines
}

fn machine_from_json(value: &Value) -> Option<CrowdSecMachine> {
    let values = value.as_object()?;
    let name = values
        .get("machineId")
        .or_else(|| values.get("machine_id"))
        .or_else(|| values.get("name"))
        .and_then(Value::as_str)?;
    if validate_machine_name(name).is_err() {
        return None;
    }

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

fn remote_machine_configuration(configuration: &str) -> String {
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
            "    enable: false".to_string(),
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
                format!("{}    enable: false", " ".repeat(api_indent)),
            ],
        );
        return with_trailing_newline(lines, trailing_newline);
    };

    let server_indent = indentation(&lines[server_index]);
    let server_end = block_end(&lines, server_index, server_indent);
    let mut has_enable = false;

    for line in lines.iter_mut().take(server_end).skip(server_index + 1) {
        if indentation(line) == server_indent + 2 && line.trim_start().starts_with("enable:") {
            *line = format!("{}enable: false", " ".repeat(server_indent + 2));
            has_enable = true;
        }
    }

    if !has_enable {
        lines.insert(
            server_index + 1,
            format!("{}enable: false", " ".repeat(server_indent + 2)),
        );
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
    use std::io::ErrorKind;

    use super::{
        central_lapi_configuration, machine_from_json, machine_reauthentication_required_message,
        machines_from_json, remote_lapi_connection_error, remote_lapi_socket_address,
        remote_lapi_url, remote_machine_configuration, validate_listen_uri,
        validate_machine_name,
    };
    use crate::{
        crowdsec::{
            errors::{LAPI_CONNECTION_FAILED, LAPI_CONNECTION_REFUSED, LAPI_CONNECTION_TIMEOUT},
            models::CrowdSecMachineState,
        },
        errors::FwcError,
    };
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
    fn configures_a_remote_machine_without_a_local_api_server() {
        let configuration = "api:\n  client:\n    credentials_path: /etc/crowdsec/local_api_credentials.yaml\n  server:\n    enable: true\n    listen_uri: 127.0.0.1:8080\n";

        let updated = remote_machine_configuration(configuration);

        assert!(updated.contains("  server:\n    enable: false\n"));
        assert!(updated.contains("    listen_uri: 127.0.0.1:8080\n"));
    }

    #[test]
    fn validates_a_remote_lapi_url_with_a_host_and_port() {
        assert!(remote_lapi_url("http://192.0.2.10:8080").is_ok());
        assert!(remote_lapi_url("https://[2001:db8::10]:8443").is_ok());
        assert!(remote_lapi_url("http://lapi.example.test:8080").is_ok());
        assert!(remote_lapi_url("http://192.0.2.10").is_err());
        assert!(remote_lapi_url("http://192.0.2.10:8080/api").is_err());
    }

    #[test]
    fn resolves_a_remote_lapi_ip_address_without_connecting() {
        let address = remote_lapi_socket_address("192.0.2.10", 8080).unwrap();

        assert_eq!(address.to_string(), "192.0.2.10:8080");
    }

    #[test]
    fn normalizes_remote_lapi_connection_errors() {
        assert_eq!(
            crowdsec_error_code(remote_lapi_connection_error(ErrorKind::ConnectionRefused)),
            LAPI_CONNECTION_REFUSED,
        );
        assert_eq!(
            crowdsec_error_code(remote_lapi_connection_error(ErrorKind::TimedOut)),
            LAPI_CONNECTION_TIMEOUT,
        );
        assert_eq!(
            crowdsec_error_code(remote_lapi_connection_error(ErrorKind::ConnectionReset)),
            LAPI_CONNECTION_FAILED,
        );
    }

    #[test]
    fn validates_machine_names_for_registration_and_removal() {
        assert!(validate_machine_name("fwcloud-machine-01").is_ok());
        assert!(validate_machine_name("fwcloud.machine_01").is_ok());
        assert!(validate_machine_name("invalid machine name").is_err());
        assert!(validate_machine_name("../../machine").is_err());
    }

    #[test]
    fn recognizes_a_removed_machine_in_lapi_diagnostics() {
        assert!(machine_reauthentication_required_message(
            "API error: ent: machine not found"
        ));
        assert!(!machine_reauthentication_required_message(
            "connection refused"
        ));
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

    #[test]
    fn omits_invalid_machine_entries_and_credentials_from_inventory() {
        let machines = machines_from_json(&json!([
            {
                "machineId": "fwcloud-machine-2",
                "isValidated": true,
                "api_key": "must-not-be-exposed"
            },
            {
                "machineId": "invalid machine name",
                "isValidated": false
            },
            {
                "machineId": "fwcloud-machine-1",
                "isValidated": false
            }
        ]));

        let serialized = serde_json::to_value(&machines).unwrap();
        assert_eq!(machines.len(), 2);
        assert_eq!(machines[0].name, "fwcloud-machine-1");
        assert_eq!(machines[1].name, "fwcloud-machine-2");
        assert!(serialized[1].get("api_key").is_none());
    }

    fn crowdsec_error_code(error: FwcError) -> &'static str {
        match error {
            FwcError::CrowdSec { code, .. } => code,
            _ => panic!("Expected a CrowdSec error"),
        }
    }
}
