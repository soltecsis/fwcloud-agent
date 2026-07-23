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
    fs::{self as std_fs, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    time::Duration,
};

use log::debug;
use serde::Serialize;
use tokio::{fs, process::Command, time::timeout};

use crate::{
    crowdsec::{
        command::CrowdSecCommand,
        errors::{FIREWALL_INTEGRATION_INVALID, OPERATION_TIMEOUT},
        models::{
            CrowdSecBouncerInstallResponse, CrowdSecBouncerInstallStep,
            CrowdSecBouncerUninstallResponse, CrowdSecBouncerUninstallStep, CrowdSecStepResult,
            CrowdSecStepStatus,
        },
        packages,
    },
    errors::{FwcError, Result},
};

pub const FIREWALL_BOUNCER_PACKAGE: &str = "crowdsec-firewall-bouncer-iptables";
pub const FIREWALL_BOUNCER_SERVICE: &str = "crowdsec-firewall-bouncer.service";
pub const FWCLOUD_BOUNCER_NAME: &str = "fwcloud";
pub const BOUNCER_CONFIG_DIRECTORY: &str = "/etc/crowdsec/bouncers";
pub const BOUNCER_CONFIG_OVERRIDE_PATH: &str =
    "/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local";
pub const IPSET_SETUP_SERVICE: &str = "fwcloud-crowdsec-ipsets.service";
pub const IPSET_SETUP_SERVICE_PATH: &str = "/etc/systemd/system/fwcloud-crowdsec-ipsets.service";
pub const BOUNCER_IPSET_DROP_IN_DIRECTORY: &str =
    "/etc/systemd/system/crowdsec-firewall-bouncer.service.d";
pub const BOUNCER_IPSET_DROP_IN_PATH: &str =
    "/etc/systemd/system/crowdsec-firewall-bouncer.service.d/fwcloud-ipsets.conf";
pub const IPSET_V4_BLACKLIST: &str = "crowdsec-blacklists";
pub const IPSET_V6_BLACKLIST: &str = "crowdsec6-blacklists";

const IPSET_COMMAND: &str = "/usr/sbin/ipset";
const IPSET_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const IPSET_MAX_ELEMENTS: &str = "150000";
const SYSTEMCTL_COMMAND: &str = "/usr/bin/systemctl";

const IPSET_SETUP_SERVICE_CONTENT: &str = "[Unit]\nDescription=Create FWCloud CrowdSec blacklist IPSet\nBefore=crowdsec-firewall-bouncer.service\n\n[Service]\nType=oneshot\nExecStart=/usr/sbin/ipset create crowdsec-blacklists hash:ip timeout 0 maxelem 150000 -exist\nExecStart=/usr/sbin/ipset create crowdsec6-blacklists hash:ip family inet6 timeout 0 maxelem 150000 -exist\nRemainAfterExit=yes\n\n[Install]\nWantedBy=multi-user.target\n";
const BOUNCER_IPSET_DROP_IN_CONTENT: &str =
    "[Unit]\nRequires=fwcloud-crowdsec-ipsets.service\nAfter=fwcloud-crowdsec-ipsets.service\n";

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrowdSecBouncerIntegrationState {
    NotConfigured,
    Ready,
    MissingBlacklistSets,
    ManagedConfiguration,
    ServiceInactive,
    Error,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecIpSetStatus {
    pub name: &'static str,
    pub exists: bool,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecBouncerIntegrationStatus {
    pub state: CrowdSecBouncerIntegrationState,
    pub ipv4_blacklist: CrowdSecIpSetStatus,
    pub ipv6_blacklist: CrowdSecIpSetStatus,
    pub service_running: bool,
    pub message: String,
}

#[derive(Debug)]
pub struct CrowdSecBouncerSetOnlyConfig {
    pub mode: &'static str,
    pub blacklists_ipv4: &'static str,
    pub blacklists_ipv6: &'static str,
}

impl Default for CrowdSecBouncerSetOnlyConfig {
    fn default() -> Self {
        Self {
            mode: "ipset",
            blacklists_ipv4: IPSET_V4_BLACKLIST,
            blacklists_ipv6: IPSET_V6_BLACKLIST,
        }
    }
}

pub async fn prepare_set_only_configuration() -> Result<String> {
    let api_key = existing_bouncer_api_key()
        .await?
        .unwrap_or(generate_bouncer_api_key().await?);
    let configuration = CrowdSecBouncerSetOnlyConfig::default();

    fs::create_dir_all(BOUNCER_CONFIG_DIRECTORY)
        .await
        .map_err(|_| {
            FwcError::crowdsec(
                FIREWALL_INTEGRATION_INVALID,
                "Unable to create CrowdSec Firewall Bouncer configuration directory",
            )
        })?;
    write_bouncer_configuration(&configuration, &api_key)?;
    Ok(api_key)
}

pub async fn install() -> Result<CrowdSecBouncerInstallResponse> {
    log::info!("Installing CrowdSec Firewall Bouncer in FWCloud IPSet-only mode");

    ensure_blacklist_ipsets().await?;
    install_ipset_setup_service().await?;
    let api_key = prepare_set_only_configuration().await?;
    let package_installed = packages::install_firewall_bouncer_package().await?;
    write_set_only_configuration(&api_key).await?;
    enable_firewall_bouncer_service().await?;

    log::info!("CrowdSec Firewall Bouncer installation completed");

    Ok(CrowdSecBouncerInstallResponse {
        steps: vec![
            CrowdSecStepResult {
                step: CrowdSecBouncerInstallStep::BlacklistIpSets,
                status: CrowdSecStepStatus::Completed,
                message: "FWCloud CrowdSec blacklist IPSet are ready".to_string(),
            },
            CrowdSecStepResult {
                step: CrowdSecBouncerInstallStep::IpSetSetupService,
                status: CrowdSecStepStatus::Completed,
                message: "FWCloud CrowdSec IPSet boot service is enabled".to_string(),
            },
            CrowdSecStepResult {
                step: CrowdSecBouncerInstallStep::Configuration,
                status: CrowdSecStepStatus::Completed,
                message: "CrowdSec Firewall Bouncer is configured for FWCloud IPSet only"
                    .to_string(),
            },
            CrowdSecStepResult {
                step: CrowdSecBouncerInstallStep::Package,
                status: CrowdSecStepStatus::Completed,
                message: if package_installed {
                    "CrowdSec Firewall Bouncer package is installed".to_string()
                } else {
                    "CrowdSec Firewall Bouncer package is already installed".to_string()
                },
            },
            CrowdSecStepResult {
                step: CrowdSecBouncerInstallStep::Service,
                status: CrowdSecStepStatus::Completed,
                message: "CrowdSec Firewall Bouncer service is enabled and running".to_string(),
            },
        ],
    })
}

pub async fn uninstall() -> Result<CrowdSecBouncerUninstallResponse> {
    log::info!("Disabling FWCloud CrowdSec Firewall Bouncer while preserving packages and IPSet");

    let service_disabled = disable_systemd_service(FIREWALL_BOUNCER_SERVICE).await?;
    let registration_removed = remove_bouncer_registration().await?;
    let configuration_removed = remove_managed_file(BOUNCER_CONFIG_OVERRIDE_PATH).await?;
    let ipset_service_removed = remove_ipset_setup_service().await?;
    let cleared_ipsets = clear_blacklist_ipsets().await?;

    log::info!("FWCloud CrowdSec Firewall Bouncer disabled");

    Ok(CrowdSecBouncerUninstallResponse {
        steps: vec![
            boolean_step(
                CrowdSecBouncerUninstallStep::Service,
                service_disabled,
                "CrowdSec Firewall Bouncer service is disabled and stopped",
                "CrowdSec Firewall Bouncer service is already absent",
            ),
            boolean_step(
                CrowdSecBouncerUninstallStep::Registration,
                registration_removed,
                "FWCloud CrowdSec Firewall Bouncer registration is removed",
                "FWCloud CrowdSec Firewall Bouncer registration is already absent",
            ),
            boolean_step(
                CrowdSecBouncerUninstallStep::Configuration,
                configuration_removed,
                "FWCloud CrowdSec Firewall Bouncer configuration is removed",
                "FWCloud CrowdSec Firewall Bouncer configuration is already absent",
            ),
            boolean_step(
                CrowdSecBouncerUninstallStep::IpSetSetupService,
                ipset_service_removed,
                "FWCloud CrowdSec IPSet boot service is removed",
                "FWCloud CrowdSec IPSet boot service is already absent",
            ),
            boolean_step(
                CrowdSecBouncerUninstallStep::BlacklistIpSets,
                cleared_ipsets,
                "FWCloud CrowdSec blacklist IPSet are cleared and preserved",
                "FWCloud CrowdSec blacklist IPSet are already absent",
            ),
        ],
    })
}

async fn write_set_only_configuration(api_key: &str) -> Result<()> {
    let configuration = CrowdSecBouncerSetOnlyConfig::default();

    fs::create_dir_all(BOUNCER_CONFIG_DIRECTORY)
        .await
        .map_err(|_| {
            FwcError::crowdsec(
                FIREWALL_INTEGRATION_INVALID,
                "Unable to create CrowdSec Firewall Bouncer configuration directory",
            )
        })?;
    write_bouncer_configuration(&configuration, api_key)
}

fn boolean_step<T>(
    step: T,
    completed: bool,
    completed_message: &str,
    skipped_message: &str,
) -> CrowdSecStepResult<T> {
    CrowdSecStepResult {
        step,
        status: if completed {
            CrowdSecStepStatus::Completed
        } else {
            CrowdSecStepStatus::Skipped
        },
        message: if completed {
            completed_message.to_string()
        } else {
            skipped_message.to_string()
        },
    }
}

pub async fn ensure_blacklist_ipsets() -> Result<[CrowdSecIpSetStatus; 2]> {
    create_ipset(&[
        "create",
        IPSET_V4_BLACKLIST,
        "hash:ip",
        "timeout",
        "0",
        "maxelem",
        IPSET_MAX_ELEMENTS,
        "-exist",
    ])
    .await?;
    create_ipset(&[
        "create",
        IPSET_V6_BLACKLIST,
        "hash:ip",
        "family",
        "inet6",
        "timeout",
        "0",
        "maxelem",
        IPSET_MAX_ELEMENTS,
        "-exist",
    ])
    .await?;

    let ipv4_blacklist = ipset_status(IPSET_V4_BLACKLIST).await?;
    let ipv6_blacklist = ipset_status(IPSET_V6_BLACKLIST).await?;

    if !ipv4_blacklist.exists || !ipv6_blacklist.exists {
        return Err(FwcError::crowdsec(
            FIREWALL_INTEGRATION_INVALID,
            "FWCloud CrowdSec blacklist IPSet are unavailable",
        ));
    }

    Ok([ipv4_blacklist, ipv6_blacklist])
}

pub async fn install_ipset_setup_service() -> Result<()> {
    write_if_changed(IPSET_SETUP_SERVICE_PATH, IPSET_SETUP_SERVICE_CONTENT).await?;
    fs::create_dir_all(BOUNCER_IPSET_DROP_IN_DIRECTORY)
        .await
        .map_err(|_| {
            FwcError::crowdsec(
                FIREWALL_INTEGRATION_INVALID,
                "Unable to create CrowdSec Firewall Bouncer systemd drop-in directory",
            )
        })?;
    write_if_changed(BOUNCER_IPSET_DROP_IN_PATH, BOUNCER_IPSET_DROP_IN_CONTENT).await?;

    run_systemctl(
        &["daemon-reload"],
        "Unable to reload CrowdSec IPSet systemd configuration",
    )
    .await?;
    run_systemctl(
        &["enable", IPSET_SETUP_SERVICE],
        "Unable to enable CrowdSec IPSet systemd service",
    )
    .await
}

async fn enable_firewall_bouncer_service() -> Result<()> {
    run_systemctl(
        &["enable", "--now", FIREWALL_BOUNCER_SERVICE],
        "Unable to enable CrowdSec Firewall Bouncer service",
    )
    .await
}

async fn disable_systemd_service(service: &str) -> Result<bool> {
    if !systemd_unit_exists(service).await? {
        return Ok(false);
    }

    run_systemctl(
        &["disable", "--now", service],
        "Unable to disable CrowdSec Firewall Bouncer service",
    )
    .await?;
    Ok(true)
}

async fn remove_bouncer_registration() -> Result<bool> {
    if !bouncer_is_registered().await? {
        return Ok(false);
    }

    debug!("Removing FWCloud CrowdSec Firewall Bouncer registration");
    CrowdSecCommand::cscli(&["bouncers", "delete", FWCLOUD_BOUNCER_NAME])?
        .execute()
        .await?;
    Ok(true)
}

async fn remove_ipset_setup_service() -> Result<bool> {
    let service_exists = systemd_unit_exists(IPSET_SETUP_SERVICE).await?;

    if service_exists {
        run_systemctl(
            &["disable", "--now", IPSET_SETUP_SERVICE],
            "Unable to disable CrowdSec IPSet systemd service",
        )
        .await?;
    }

    let service_removed = remove_managed_file(IPSET_SETUP_SERVICE_PATH).await?;
    let drop_in_removed = remove_managed_file(BOUNCER_IPSET_DROP_IN_PATH).await?;

    if service_removed || drop_in_removed {
        run_systemctl(
            &["daemon-reload"],
            "Unable to reload CrowdSec IPSet systemd configuration",
        )
        .await?;
    }

    Ok(service_exists || service_removed || drop_in_removed)
}

async fn clear_blacklist_ipsets() -> Result<bool> {
    let mut cleared_ipsets = false;

    for name in [IPSET_V4_BLACKLIST, IPSET_V6_BLACKLIST] {
        if ipset_status(name).await?.exists {
            let output = run_ipset(&["flush", name]).await?;

            if !output.status.success() {
                return Err(FwcError::crowdsec(
                    FIREWALL_INTEGRATION_INVALID,
                    "Unable to clear FWCloud CrowdSec blacklist IPSet",
                ));
            }

            cleared_ipsets = true;
        }
    }

    Ok(cleared_ipsets)
}

pub async fn ipset_status(name: &'static str) -> Result<CrowdSecIpSetStatus> {
    let output = run_ipset(&["list", name]).await?;

    Ok(CrowdSecIpSetStatus {
        name,
        exists: output.status.success(),
    })
}

async fn create_ipset(arguments: &[&str]) -> Result<()> {
    let output = run_ipset(arguments).await?;

    if output.status.success() {
        Ok(())
    } else {
        Err(FwcError::crowdsec(
            FIREWALL_INTEGRATION_INVALID,
            "Unable to create FWCloud CrowdSec blacklist IPSet",
        ))
    }
}

async fn run_ipset(arguments: &[&str]) -> Result<std::process::Output> {
    debug!(
        "Running CrowdSec IPSet command: {} {:?}",
        IPSET_COMMAND, arguments
    );

    timeout(
        IPSET_COMMAND_TIMEOUT,
        Command::new(IPSET_COMMAND).args(arguments).output(),
    )
    .await
    .map_err(|_| FwcError::crowdsec(OPERATION_TIMEOUT, "CrowdSec IPSet command timed out"))?
    .map_err(|_| {
        FwcError::crowdsec(
            FIREWALL_INTEGRATION_INVALID,
            "Unable to run FWCloud CrowdSec IPSet command",
        )
    })
}

async fn run_systemctl(arguments: &[&str], error_message: &'static str) -> Result<()> {
    debug!(
        "Running CrowdSec IPSet systemd command: {} {:?}",
        SYSTEMCTL_COMMAND, arguments
    );

    let output = timeout(
        IPSET_COMMAND_TIMEOUT,
        Command::new(SYSTEMCTL_COMMAND).args(arguments).output(),
    )
    .await
    .map_err(|_| {
        FwcError::crowdsec(
            OPERATION_TIMEOUT,
            "CrowdSec IPSet systemd command timed out",
        )
    })?
    .map_err(|_| {
        FwcError::crowdsec(
            FIREWALL_INTEGRATION_INVALID,
            "Unable to run CrowdSec IPSet systemd command",
        )
    })?;

    if output.status.success() {
        Ok(())
    } else {
        Err(FwcError::crowdsec(
            FIREWALL_INTEGRATION_INVALID,
            error_message,
        ))
    }
}

async fn systemd_unit_exists(service: &str) -> Result<bool> {
    debug!(
        "Checking CrowdSec IPSet systemd unit: {} show LoadState",
        service
    );
    let output = timeout(
        IPSET_COMMAND_TIMEOUT,
        Command::new(SYSTEMCTL_COMMAND)
            .args(["show", "--property=LoadState", "--value", service])
            .output(),
    )
    .await
    .map_err(|_| {
        FwcError::crowdsec(
            OPERATION_TIMEOUT,
            "CrowdSec IPSet systemd command timed out",
        )
    })?
    .map_err(|_| {
        FwcError::crowdsec(
            FIREWALL_INTEGRATION_INVALID,
            "Unable to run CrowdSec IPSet systemd command",
        )
    })?;

    Ok(output.status.success() && String::from_utf8_lossy(&output.stdout).trim() != "not-found")
}

async fn remove_managed_file(path: &str) -> Result<bool> {
    match fs::remove_file(path).await {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(FwcError::crowdsec(
            FIREWALL_INTEGRATION_INVALID,
            "Unable to remove FWCloud CrowdSec configuration",
        )),
    }
}

async fn write_if_changed(path: &str, contents: &str) -> Result<()> {
    match fs::read_to_string(path).await {
        Ok(current_contents) if current_contents == contents => Ok(()),
        Ok(_) | Err(_) => fs::write(path, contents).await.map_err(|_| {
            FwcError::crowdsec(
                FIREWALL_INTEGRATION_INVALID,
                "Unable to write CrowdSec IPSet systemd configuration",
            )
        }),
    }
}

async fn existing_bouncer_api_key() -> Result<Option<String>> {
    match fs::read_to_string(BOUNCER_CONFIG_OVERRIDE_PATH).await {
        Ok(configuration) => configuration
            .lines()
            .find_map(|line| {
                line.split_once(':').and_then(|(key, value)| {
                    (key.trim() == "api_key").then(|| {
                        value
                            .trim()
                            .trim_matches('"')
                            .trim_matches('\'')
                            .to_string()
                    })
                })
            })
            .filter(|api_key| valid_api_key(api_key))
            .map(Some)
            .ok_or_else(|| {
                FwcError::crowdsec(
                    FIREWALL_INTEGRATION_INVALID,
                    "Existing CrowdSec Firewall Bouncer configuration has no valid API key",
                )
            }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(FwcError::crowdsec(
            FIREWALL_INTEGRATION_INVALID,
            "Unable to read CrowdSec Firewall Bouncer configuration",
        )),
    }
}

async fn generate_bouncer_api_key() -> Result<String> {
    if bouncer_is_registered().await? {
        debug!(
            "Replacing FWCloud CrowdSec Firewall Bouncer registration without local configuration"
        );
        CrowdSecCommand::cscli(&["bouncers", "delete", FWCLOUD_BOUNCER_NAME])?
            .execute()
            .await?;
    }

    debug!("Generating FWCloud CrowdSec Firewall Bouncer API key");
    let output = CrowdSecCommand::cscli(&["bouncers", "add", FWCLOUD_BOUNCER_NAME, "-o", "raw"])?
        .execute()
        .await?;
    let api_key = output.stdout().trim().to_string();

    if valid_api_key(&api_key) {
        Ok(api_key)
    } else {
        Err(FwcError::crowdsec(
            FIREWALL_INTEGRATION_INVALID,
            "CrowdSec Firewall Bouncer did not return a valid API key",
        ))
    }
}

async fn bouncer_is_registered() -> Result<bool> {
    let output = CrowdSecCommand::cscli(&["bouncers", "list", "-o", "json"])?
        .execute()
        .await?;
    let bouncers = serde_json::from_str::<serde_json::Value>(output.stdout()).map_err(|_| {
        FwcError::crowdsec(
            FIREWALL_INTEGRATION_INVALID,
            "Unable to read CrowdSec Firewall Bouncer registrations",
        )
    })?;

    Ok(json_bouncer_is_registered(&bouncers))
}

fn json_bouncer_is_registered(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Array(values) => values.iter().any(json_bouncer_is_registered),
        serde_json::Value::Object(values) => {
            values.get("name").and_then(serde_json::Value::as_str) == Some(FWCLOUD_BOUNCER_NAME)
                || values.values().any(json_bouncer_is_registered)
        }
        _ => false,
    }
}

fn valid_api_key(api_key: &str) -> bool {
    !api_key.is_empty()
        && api_key.len() <= 512
        && !api_key.chars().any(char::is_control)
        && !api_key.contains('\n')
        && !api_key.contains('\r')
}

fn write_bouncer_configuration(
    configuration: &CrowdSecBouncerSetOnlyConfig,
    api_key: &str,
) -> Result<()> {
    let temporary_path = format!("{}.tmp", BOUNCER_CONFIG_OVERRIDE_PATH);
    let _ = std_fs::remove_file(&temporary_path);
    let mut configuration_file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&temporary_path)
        .map_err(|_| {
            FwcError::crowdsec(
                FIREWALL_INTEGRATION_INVALID,
                "Unable to create CrowdSec Firewall Bouncer configuration",
            )
        })?;
    std_fs::set_permissions(&temporary_path, std_fs::Permissions::from_mode(0o600)).map_err(
        |_| {
            FwcError::crowdsec(
                FIREWALL_INTEGRATION_INVALID,
                "Unable to secure CrowdSec Firewall Bouncer configuration",
            )
        },
    )?;
    configuration_file
        .write_all(set_only_configuration_contents(configuration, api_key).as_bytes())
        .and_then(|_| configuration_file.sync_all())
        .map_err(|_| {
            FwcError::crowdsec(
                FIREWALL_INTEGRATION_INVALID,
                "Unable to write CrowdSec Firewall Bouncer configuration",
            )
        })?;
    std_fs::rename(&temporary_path, BOUNCER_CONFIG_OVERRIDE_PATH).map_err(|_| {
        FwcError::crowdsec(
            FIREWALL_INTEGRATION_INVALID,
            "Unable to install CrowdSec Firewall Bouncer configuration",
        )
    })
}

fn set_only_configuration_contents(
    configuration: &CrowdSecBouncerSetOnlyConfig,
    api_key: &str,
) -> String {
    format!(
        "mode: {}\napi_url: http://127.0.0.1:8080/\napi_key: {}\ndisable_ipv6: false\nblacklists_ipv4: {}\nblacklists_ipv6: {}\nipset_type: hash:ip\n",
        configuration.mode,
        api_key,
        configuration.blacklists_ipv4,
        configuration.blacklists_ipv6,
    )
}
