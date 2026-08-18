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
    path::Path,
    time::Duration,
};

use log::debug;
use serde::Serialize;
use serde_json::Value;
use tokio::{fs, process::Command, time::timeout};

use crate::{
    crowdsec::{
        command::CrowdSecCommand,
        errors::{
            BOUNCER_CONFLICT, BOUNCER_INVALID, BOUNCER_NOT_FOUND, COMMAND_FAILED,
            FIREWALL_INTEGRATION_INVALID, OPERATION_TIMEOUT,
        },
        models::{
            CrowdSecBouncer, CrowdSecBouncerInstallResponse, CrowdSecBouncerInstallStep,
            CrowdSecBouncerRegisterResponse, CrowdSecBouncerRemoveResponse,
            CrowdSecBouncerUninstallResponse, CrowdSecBouncerUninstallStep,
            CrowdSecBouncersResponse, CrowdSecFirewallBackend, CrowdSecStepResult,
            CrowdSecStepStatus,
        },
        packages,
        progress::{CrowdSecProgress, CrowdSecProgressMessageType},
    },
    errors::{FwcError, Result},
};

pub const IPTABLES_FIREWALL_BOUNCER_PACKAGE: &str = "crowdsec-firewall-bouncer-iptables";
pub const NFTABLES_FIREWALL_BOUNCER_PACKAGE: &str = "crowdsec-firewall-bouncer-nftables";
pub const NFTABLES_RUNTIME_PACKAGE: &str = "nftables";
pub const FIREWALL_BOUNCER_PACKAGE: &str = IPTABLES_FIREWALL_BOUNCER_PACKAGE;
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
const CSCLI_COMMAND: &str = "/usr/bin/cscli";
const IPTABLES_SAVE_COMMAND: &str = "/usr/sbin/iptables-save";
const IP6TABLES_SAVE_COMMAND: &str = "/usr/sbin/ip6tables-save";
const IPSET_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const IPSET_MAX_ELEMENTS: &str = "150000";
const SYSTEMCTL_COMMAND: &str = "/usr/bin/systemctl";

const IPSET_SETUP_SERVICE_CONTENT: &str = "[Unit]\nDescription=Create FWCloud CrowdSec blacklist IPSet\nBefore=crowdsec-firewall-bouncer.service\n\n[Service]\nType=oneshot\nExecStart=/usr/sbin/ipset create crowdsec-blacklists hash:ip timeout 0 maxelem 150000 -exist\nExecStart=/usr/sbin/ipset create crowdsec6-blacklists hash:ip family inet6 timeout 0 maxelem 150000 -exist\nRemainAfterExit=yes\n\n[Install]\nWantedBy=multi-user.target\n";
const BOUNCER_IPSET_DROP_IN_CONTENT: &str =
    "[Unit]\nRequires=fwcloud-crowdsec-ipsets.service\nAfter=fwcloud-crowdsec-ipsets.service\n";

pub const fn firewall_bouncer_package(backend: CrowdSecFirewallBackend) -> &'static str {
    match backend {
        CrowdSecFirewallBackend::Iptables => IPTABLES_FIREWALL_BOUNCER_PACKAGE,
        CrowdSecFirewallBackend::Nftables => NFTABLES_FIREWALL_BOUNCER_PACKAGE,
    }
}

pub const fn firewall_bouncer_packages(
    backend: CrowdSecFirewallBackend,
) -> &'static [&'static str] {
    match backend {
        CrowdSecFirewallBackend::Iptables => &[IPTABLES_FIREWALL_BOUNCER_PACKAGE],
        CrowdSecFirewallBackend::Nftables => {
            &[NFTABLES_RUNTIME_PACKAGE, NFTABLES_FIREWALL_BOUNCER_PACKAGE]
        }
    }
}

pub const fn non_selected_firewall_backend(
    backend: CrowdSecFirewallBackend,
) -> CrowdSecFirewallBackend {
    match backend {
        CrowdSecFirewallBackend::Iptables => CrowdSecFirewallBackend::Nftables,
        CrowdSecFirewallBackend::Nftables => CrowdSecFirewallBackend::Iptables,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrowdSecBouncerIntegrationState {
    NotConfigured,
    Ready,
    MissingBlacklistSets,
    ManagedConfiguration,
    UnmanagedFirewallRules,
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
    pub managed_configuration: bool,
    pub unmanaged_firewall_rules: bool,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BouncerConfigurationState {
    NotConfigured,
    SetOnly,
    Managed,
}

pub async fn status() -> Result<CrowdSecBouncerIntegrationStatus> {
    let ipv4_blacklist = blacklist_ipset_status(IPSET_V4_BLACKLIST).await?;
    let ipv6_blacklist = blacklist_ipset_status(IPSET_V6_BLACKLIST).await?;
    let configuration_state = bouncer_configuration_state().await?;
    let service_running = systemd_service_is_running(FIREWALL_BOUNCER_SERVICE).await?;
    let unmanaged_firewall_rules = has_unmanaged_crowdsec_firewall_rules().await?;

    Ok(integration_status(
        ipv4_blacklist,
        ipv6_blacklist,
        configuration_state,
        service_running,
        unmanaged_firewall_rules,
    ))
}

pub async fn list() -> Result<CrowdSecBouncersResponse> {
    let output = CrowdSecCommand::cscli(&["bouncers", "list", "-o", "json"])?
        .execute()
        .await?;
    let value = serde_json::from_str::<Value>(output.stdout())
        .map_err(|_| FwcError::crowdsec(COMMAND_FAILED, "Unable to read CrowdSec bouncer list"))?;

    Ok(CrowdSecBouncersResponse {
        bouncers: bouncers_from_json(&value),
    })
}

pub async fn register(name: &str) -> Result<CrowdSecBouncerRegisterResponse> {
    validate_bouncer_name(name)?;
    reject_fwcloud_bouncer(name, "The FWCloud bouncer name is reserved")?;

    if list()
        .await?
        .bouncers
        .iter()
        .any(|bouncer| bouncer.name == name)
    {
        return Err(FwcError::crowdsec(
            BOUNCER_CONFLICT,
            "CrowdSec bouncer is already registered",
        ));
    }

    debug!("Registering CrowdSec bouncer: {}", name);
    let output = CrowdSecCommand::cscli(&["bouncers", "add", name, "-o", "raw"])?
        .execute()
        .await?;

    bouncer_register_response(name, output.stdout())
}

pub async fn remove(name: &str) -> Result<CrowdSecBouncerRemoveResponse> {
    validate_bouncer_name(name)?;

    if !list()
        .await?
        .bouncers
        .iter()
        .any(|bouncer| bouncer.name == name)
    {
        return Err(FwcError::crowdsec(
            BOUNCER_NOT_FOUND,
            "CrowdSec bouncer is not registered",
        ));
    }

    reject_fwcloud_bouncer(name, "Use the FWCloud local bouncer uninstall operation")?;

    debug!("Removing CrowdSec bouncer: {}", name);
    CrowdSecCommand::cscli(&["bouncers", "delete", name])?
        .execute()
        .await?;

    Ok(CrowdSecBouncerRemoveResponse {
        name: name.to_string(),
        message: "CrowdSec bouncer is removed".to_string(),
    })
}

fn bouncers_from_json(value: &Value) -> Vec<CrowdSecBouncer> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(bouncer_from_json)
        .collect()
}

fn bouncer_from_json(value: &Value) -> Option<CrowdSecBouncer> {
    Some(CrowdSecBouncer {
        name: value_as_string(value.get("name"))?,
        bouncer_type: optional_string(value.get("type")),
        revoked: value
            .get("revoked")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        last_pull: optional_string(value.get("last_pull")),
    })
}

fn optional_string(value: Option<&Value>) -> Option<String> {
    value_as_string(value).filter(|value| !value.is_empty())
}

fn value_as_string(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn validate_bouncer_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 128
        || !name.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        return Err(FwcError::crowdsec(
            BOUNCER_INVALID,
            "Invalid CrowdSec bouncer name",
        ));
    }

    Ok(())
}

fn reject_fwcloud_bouncer(name: &str, message: &'static str) -> Result<()> {
    if name == FWCLOUD_BOUNCER_NAME {
        Err(FwcError::crowdsec(BOUNCER_CONFLICT, message))
    } else {
        Ok(())
    }
}

fn bouncer_register_response(name: &str, output: &str) -> Result<CrowdSecBouncerRegisterResponse> {
    let api_key = output.trim().to_string();

    if !valid_api_key(&api_key) {
        return Err(FwcError::crowdsec(
            COMMAND_FAILED,
            "CrowdSec bouncer did not return a valid API key",
        ));
    }

    Ok(CrowdSecBouncerRegisterResponse {
        name: name.to_string(),
        api_key,
    })
}

async fn blacklist_ipset_status(name: &'static str) -> Result<CrowdSecIpSetStatus> {
    if !Path::new(IPSET_COMMAND).is_file() {
        return Ok(CrowdSecIpSetStatus {
            name,
            exists: false,
        });
    }

    ipset_status(name).await
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
    install_with_backend_and_progress(CrowdSecFirewallBackend::Iptables, None).await
}

pub async fn install_with_progress(
    progress: Option<&CrowdSecProgress>,
) -> Result<CrowdSecBouncerInstallResponse> {
    install_with_backend_and_progress(CrowdSecFirewallBackend::Iptables, progress).await
}

pub async fn install_with_backend_and_progress(
    backend: CrowdSecFirewallBackend,
    progress: Option<&CrowdSecProgress>,
) -> Result<CrowdSecBouncerInstallResponse> {
    if backend != CrowdSecFirewallBackend::Iptables {
        return Err(FwcError::crowdsec(
            BOUNCER_INVALID,
            "NFTables CrowdSec Firewall Bouncer support is not configured",
        ));
    }

    log::info!("Installing CrowdSec Firewall Bouncer in FWCloud IPSet-only mode");

    reconcile_non_selected_bouncer_backend(backend, progress).await?;

    emit_progress(progress, "Preparing FWCloud CrowdSec blacklist IPSet");
    ensure_blacklist_ipsets().await?;
    emit_success(progress, "FWCloud CrowdSec blacklist IPSet are ready");
    emit_progress(progress, "Configuring FWCloud CrowdSec IPSet boot service");
    install_ipset_setup_service().await?;
    emit_success(progress, "FWCloud CrowdSec IPSet boot service is enabled");
    emit_progress(
        progress,
        "Preparing CrowdSec Firewall Bouncer configuration",
    );
    let api_key = prepare_set_only_configuration().await?;
    emit_success(
        progress,
        "CrowdSec Firewall Bouncer is configured for FWCloud IPSet only",
    );
    emit_progress(progress, "Installing CrowdSec Firewall Bouncer package");
    let package_installed =
        packages::install_firewall_bouncer_package_with_progress(progress).await?;
    if package_installed {
        emit_success(progress, "CrowdSec Firewall Bouncer package is installed");
    } else {
        emit_warning(
            progress,
            "CrowdSec Firewall Bouncer package is already installed",
        );
    }
    emit_progress(progress, "Writing FWCloud IPSet-only bouncer configuration");
    write_set_only_configuration(&api_key).await?;
    emit_success(
        progress,
        "FWCloud IPSet-only bouncer configuration is written",
    );
    emit_progress(progress, "Enabling CrowdSec Firewall Bouncer service");
    enable_firewall_bouncer_service().await?;
    emit_success(
        progress,
        "CrowdSec Firewall Bouncer service is enabled and running",
    );

    log::info!("CrowdSec Firewall Bouncer installation completed");
    emit_success(progress, "CrowdSec Firewall Bouncer installation completed");

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

async fn reconcile_non_selected_bouncer_backend(
    backend: CrowdSecFirewallBackend,
    progress: Option<&CrowdSecProgress>,
) -> Result<()> {
    let non_selected_backend = non_selected_firewall_backend(backend);
    if !packages::firewall_bouncer_package_is_installed(non_selected_backend).await? {
        return Ok(());
    }

    emit_progress(
        progress,
        "Removing the non-selected CrowdSec Firewall Bouncer backend",
    );
    disable_systemd_service(FIREWALL_BOUNCER_SERVICE).await?;
    packages::uninstall_firewall_bouncer_package(non_selected_backend, progress).await?;
    emit_success(
        progress,
        "The non-selected CrowdSec Firewall Bouncer backend is removed",
    );
    Ok(())
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

fn emit_warning(progress: Option<&CrowdSecProgress>, message: &str) {
    if let Some(progress) = progress {
        progress.typed_message(CrowdSecProgressMessageType::Warning, message);
    }
}

pub async fn uninstall() -> Result<CrowdSecBouncerUninstallResponse> {
    uninstall_with_progress(None).await
}

pub async fn uninstall_with_progress(
    progress: Option<&CrowdSecProgress>,
) -> Result<CrowdSecBouncerUninstallResponse> {
    log::info!("Disabling FWCloud CrowdSec Firewall Bouncer while preserving packages and IPSet");

    emit_progress(progress, "Stopping CrowdSec Firewall Bouncer service");
    let service_disabled = disable_systemd_service(FIREWALL_BOUNCER_SERVICE).await?;
    emit_boolean_result(
        progress,
        service_disabled,
        "CrowdSec Firewall Bouncer service is disabled and stopped",
        "CrowdSec Firewall Bouncer service is already absent",
    );
    emit_progress(
        progress,
        "Removing FWCloud CrowdSec Firewall Bouncer registration",
    );
    let registration_removed = remove_bouncer_registration().await?;
    emit_boolean_result(
        progress,
        registration_removed,
        "FWCloud CrowdSec Firewall Bouncer registration is removed",
        "FWCloud CrowdSec Firewall Bouncer registration is already absent",
    );
    emit_progress(
        progress,
        "Removing FWCloud CrowdSec Firewall Bouncer configuration",
    );
    let configuration_removed = remove_managed_file(BOUNCER_CONFIG_OVERRIDE_PATH).await?;
    emit_boolean_result(
        progress,
        configuration_removed,
        "FWCloud CrowdSec Firewall Bouncer configuration is removed",
        "FWCloud CrowdSec Firewall Bouncer configuration is already absent",
    );
    emit_progress(progress, "Removing FWCloud CrowdSec IPSet boot service");
    let ipset_service_removed = remove_ipset_setup_service().await?;
    emit_boolean_result(
        progress,
        ipset_service_removed,
        "FWCloud CrowdSec IPSet boot service is removed",
        "FWCloud CrowdSec IPSet boot service is already absent",
    );
    emit_progress(progress, "Clearing FWCloud CrowdSec blacklist IPSet");
    let cleared_ipsets = clear_blacklist_ipsets().await?;
    emit_boolean_result(
        progress,
        cleared_ipsets,
        "FWCloud CrowdSec blacklist IPSet are cleared and preserved",
        "FWCloud CrowdSec blacklist IPSet are already absent",
    );

    log::info!("FWCloud CrowdSec Firewall Bouncer disabled");
    emit_success(
        progress,
        "FWCloud CrowdSec Firewall Bouncer uninstall completed",
    );

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

fn emit_boolean_result(
    progress: Option<&CrowdSecProgress>,
    completed: bool,
    success_message: &str,
    warning_message: &str,
) {
    if completed {
        emit_success(progress, success_message);
    } else {
        emit_warning(progress, warning_message);
    }
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

async fn bouncer_configuration_state() -> Result<BouncerConfigurationState> {
    match fs::read_to_string(BOUNCER_CONFIG_OVERRIDE_PATH).await {
        Ok(configuration) if configuration_is_set_only(&configuration) => {
            Ok(BouncerConfigurationState::SetOnly)
        }
        Ok(_) => Ok(BouncerConfigurationState::Managed),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(BouncerConfigurationState::NotConfigured)
        }
        Err(_) => Err(FwcError::crowdsec(
            FIREWALL_INTEGRATION_INVALID,
            "Unable to read CrowdSec Firewall Bouncer configuration",
        )),
    }
}

fn integration_status(
    ipv4_blacklist: CrowdSecIpSetStatus,
    ipv6_blacklist: CrowdSecIpSetStatus,
    configuration_state: BouncerConfigurationState,
    service_running: bool,
    unmanaged_firewall_rules: bool,
) -> CrowdSecBouncerIntegrationStatus {
    let (state, message) = if unmanaged_firewall_rules {
        (
            CrowdSecBouncerIntegrationState::UnmanagedFirewallRules,
            "Unmanaged CrowdSec firewall rules were detected".to_string(),
        )
    } else if !ipv4_blacklist.exists || !ipv6_blacklist.exists {
        (
            CrowdSecBouncerIntegrationState::MissingBlacklistSets,
            "FWCloud CrowdSec blacklist IPSet are missing".to_string(),
        )
    } else if configuration_state == BouncerConfigurationState::Managed {
        (
            CrowdSecBouncerIntegrationState::ManagedConfiguration,
            "CrowdSec Firewall Bouncer configuration is not FWCloud IPSet-only".to_string(),
        )
    } else if configuration_state == BouncerConfigurationState::NotConfigured {
        (
            CrowdSecBouncerIntegrationState::NotConfigured,
            "CrowdSec Firewall Bouncer is not configured".to_string(),
        )
    } else if !service_running {
        (
            CrowdSecBouncerIntegrationState::ServiceInactive,
            "CrowdSec Firewall Bouncer service is not running".to_string(),
        )
    } else {
        (
            CrowdSecBouncerIntegrationState::Ready,
            "CrowdSec Firewall Bouncer is updating FWCloud IPSet only".to_string(),
        )
    };

    CrowdSecBouncerIntegrationStatus {
        state,
        ipv4_blacklist,
        ipv6_blacklist,
        managed_configuration: configuration_state == BouncerConfigurationState::Managed,
        unmanaged_firewall_rules,
        service_running,
        message,
    }
}

fn configuration_is_set_only(configuration: &str) -> bool {
    let expected = [
        ("mode", "ipset"),
        ("blacklists_ipv4", IPSET_V4_BLACKLIST),
        ("blacklists_ipv6", IPSET_V6_BLACKLIST),
        ("ipset_type", "hash:ip"),
    ];

    expected.iter().all(|(key, expected_value)| {
        configuration.lines().any(|line| {
            line.split_once(':').is_some_and(|(line_key, value)| {
                line_key.trim() == *key && value.trim().trim_matches('"') == *expected_value
            })
        })
    })
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
    if !Path::new(CSCLI_COMMAND).is_file() {
        debug!("CrowdSec is not installed; skipping Firewall Bouncer registration removal");
        return Ok(false);
    }

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

async fn systemd_service_is_running(service: &str) -> Result<bool> {
    debug!(
        "Checking CrowdSec systemd service state: {} is-active",
        service
    );
    let output = timeout(
        IPSET_COMMAND_TIMEOUT,
        Command::new(SYSTEMCTL_COMMAND)
            .args(["is-active", "--quiet", service])
            .output(),
    )
    .await
    .map_err(|_| {
        FwcError::crowdsec(
            OPERATION_TIMEOUT,
            "CrowdSec Firewall Bouncer service command timed out",
        )
    })?
    .map_err(|_| {
        FwcError::crowdsec(
            FIREWALL_INTEGRATION_INVALID,
            "Unable to run CrowdSec Firewall Bouncer service command",
        )
    })?;

    Ok(output.status.success())
}

async fn has_unmanaged_crowdsec_firewall_rules() -> Result<bool> {
    for command in [IPTABLES_SAVE_COMMAND, IP6TABLES_SAVE_COMMAND] {
        if !Path::new(command).is_file() {
            continue;
        }

        debug!(
            "Inspecting firewall rules for unmanaged CrowdSec entries: {}",
            command
        );
        let output = timeout(IPSET_COMMAND_TIMEOUT, Command::new(command).output())
            .await
            .map_err(|_| {
                FwcError::crowdsec(
                    OPERATION_TIMEOUT,
                    "CrowdSec firewall inspection command timed out",
                )
            })?
            .map_err(|_| {
                FwcError::crowdsec(
                    FIREWALL_INTEGRATION_INVALID,
                    "Unable to inspect firewall rules for CrowdSec integration",
                )
            })?;

        if !output.status.success() {
            return Err(FwcError::crowdsec(
                FIREWALL_INTEGRATION_INVALID,
                "Unable to inspect firewall rules for CrowdSec integration",
            ));
        }

        if firewall_rules_contain_unmanaged_crowdsec(&String::from_utf8_lossy(&output.stdout)) {
            return Ok(true);
        }
    }

    Ok(false)
}

fn firewall_rules_contain_unmanaged_crowdsec(rules: &str) -> bool {
    rules.lines().any(|line| {
        let normalized = line.to_ascii_lowercase();
        normalized.contains("crowdsec") && !is_fwcloud_blacklist_rule(&normalized)
    })
}

fn is_fwcloud_blacklist_rule(rule: &str) -> bool {
    (rule.starts_with("-a input ") || rule.starts_with("-a forward "))
        && (rule.contains("--match-set crowdsec-blacklists ")
            || rule.contains("--match-set crowdsec6-blacklists "))
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

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
        time::SystemTime,
    };

    use super::{
        bouncer_register_response, bouncers_from_json, configuration_is_set_only,
        emit_boolean_result, firewall_rules_contain_unmanaged_crowdsec, integration_status,
        reject_fwcloud_bouncer, set_only_configuration_contents, validate_bouncer_name,
        BouncerConfigurationState, CrowdSecBouncerIntegrationState, CrowdSecBouncerSetOnlyConfig,
        CrowdSecBouncersResponse, CrowdSecIpSetStatus, FWCLOUD_BOUNCER_NAME, IPSET_V4_BLACKLIST,
        IPSET_V6_BLACKLIST,
    };
    use crate::{
        crowdsec::{
            errors::{BOUNCER_CONFLICT, BOUNCER_INVALID, COMMAND_FAILED},
            progress::{CrowdSecProgress, CrowdSecProgressMessage, CrowdSecProgressMessageType},
        },
        errors::FwcError,
        utils::ws::WsData,
    };
    use uuid::Uuid;

    fn ipset_status(name: &'static str, exists: bool) -> CrowdSecIpSetStatus {
        CrowdSecIpSetStatus { name, exists }
    }

    #[test]
    fn recognizes_set_only_configuration() {
        let configuration =
            set_only_configuration_contents(&CrowdSecBouncerSetOnlyConfig::default(), "secret");

        assert!(configuration_is_set_only(&configuration));
        assert!(!configuration_is_set_only(
            &configuration.replace("mode: ipset", "mode: iptables")
        ));
    }

    #[test]
    fn identifies_unmanaged_crowdsec_firewall_rules() {
        let fwcloud_rules = "-A INPUT -m set --match-set crowdsec-blacklists src -j DROP\n-A FORWARD -m set --match-set crowdsec6-blacklists src -j DROP\n";
        let unmanaged_rules = "-N CROWDSEC\n-A INPUT -j CROWDSEC\n";

        assert!(!firewall_rules_contain_unmanaged_crowdsec(fwcloud_rules));
        assert!(firewall_rules_contain_unmanaged_crowdsec(unmanaged_rules));
    }

    #[test]
    fn reports_invalid_integration_without_serializing_a_key() {
        let status = integration_status(
            ipset_status(IPSET_V4_BLACKLIST, true),
            ipset_status(IPSET_V6_BLACKLIST, true),
            BouncerConfigurationState::Managed,
            true,
            false,
        );

        assert_eq!(
            status.state,
            CrowdSecBouncerIntegrationState::ManagedConfiguration
        );
        assert!(status.managed_configuration);
        assert!(!serde_json::to_string(&status).unwrap().contains("api_key"));
    }

    #[test]
    fn validates_optional_bouncer_names() {
        assert!(validate_bouncer_name("nginx-prod_01.example").is_ok());

        for name in ["", "invalid name", "invalid/name", "invalid\nname"] {
            let error = validate_bouncer_name(name).unwrap_err();
            assert!(matches!(
                error,
                FwcError::CrowdSec {
                    code: BOUNCER_INVALID,
                    ..
                }
            ));
        }
    }

    #[test]
    fn protects_the_fwcloud_bouncer_from_generic_operations() {
        let error = reject_fwcloud_bouncer(
            FWCLOUD_BOUNCER_NAME,
            "Use the FWCloud local bouncer uninstall operation",
        )
        .unwrap_err();
        assert!(matches!(
            error,
            FwcError::CrowdSec {
                code: BOUNCER_CONFLICT,
                ..
            }
        ));
        assert!(reject_fwcloud_bouncer("nginx-prod", "unused").is_ok());
    }

    #[test]
    fn returns_a_generated_key_only_from_the_registration_response() {
        let response = bouncer_register_response("nginx-prod", "generated-key\n").unwrap();

        assert_eq!(response.name, "nginx-prod");
        assert_eq!(response.api_key, "generated-key");
        assert!(bouncer_register_response("nginx-prod", "\n").is_err());
        let error = match bouncer_register_response("nginx-prod", "invalid\nkey") {
            Err(error) => error,
            Ok(_) => panic!("an API key containing a control character must be rejected"),
        };
        assert!(matches!(
            error,
            FwcError::CrowdSec {
                code: COMMAND_FAILED,
                ..
            }
        ));
    }

    #[test]
    fn bouncer_lists_do_not_serialize_api_keys() {
        let response = CrowdSecBouncersResponse {
            bouncers: bouncers_from_json(&serde_json::json!([{
                "name": "nginx-prod",
                "type": "",
                "api_key": "generated-key",
                "revoked": false,
                "last_pull": "2026-07-27T10:00:00Z"
            }])),
        };

        let serialized = serde_json::to_string(&response).unwrap();
        assert!(!serialized.contains("api_key"));
        assert!(!serialized.contains("generated-key"));
        assert!(response.bouncers[0].bouncer_type.is_none());
    }

    #[test]
    fn bouncer_uninstall_progress_classifies_completed_and_absent_resources() {
        let map = Arc::new(Mutex::new(HashMap::new()));
        let id = Uuid::new_v4();
        let data = Arc::new(Mutex::new(WsData {
            created_at: SystemTime::now(),
            lines: Vec::new(),
            finished: false,
        }));
        map.lock().unwrap().insert(id, Arc::clone(&data));
        let progress = CrowdSecProgress::from_ws_map(map, Some(id)).unwrap();

        emit_boolean_result(Some(&progress), true, "Bouncer removed", "Bouncer absent");
        emit_boolean_result(Some(&progress), false, "Bouncer removed", "Bouncer absent");

        let data = data.lock().unwrap();
        let completed = serde_json::from_str::<CrowdSecProgressMessage>(&data.lines[0]).unwrap();
        let absent = serde_json::from_str::<CrowdSecProgressMessage>(&data.lines[1]).unwrap();
        assert_eq!(completed.message_type, CrowdSecProgressMessageType::Success);
        assert_eq!(absent.message_type, CrowdSecProgressMessageType::Warning);
    }
}
