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
pub const FIREWALL_BOUNCER_SERVICE: &str = "crowdsec-firewall-bouncer.service";
pub const FWCLOUD_BOUNCER_NAME: &str = "fwcloud";
pub const BOUNCER_CONFIG_DIRECTORY: &str = "/etc/crowdsec/bouncers";
pub const BOUNCER_CONFIG_PATH: &str = "/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml";
const LEGACY_BOUNCER_CONFIG_OVERRIDE_PATH: &str =
    "/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local";
const FWCLOUD_BOUNCER_CONFIGURATION_MARKER: &str = "# Managed by FWCloud";
pub const BOUNCER_PENDING_BACKEND_PATH: &str =
    "/etc/crowdsec/bouncers/fwcloud-crowdsec-bouncer-pending";
pub const IPSET_SETUP_SERVICE: &str = "fwcloud-crowdsec-ipsets.service";
pub const IPSET_SETUP_SERVICE_PATH: &str = "/etc/systemd/system/fwcloud-crowdsec-ipsets.service";
pub const BOUNCER_IPSET_DROP_IN_DIRECTORY: &str =
    "/etc/systemd/system/crowdsec-firewall-bouncer.service.d";
pub const BOUNCER_IPSET_DROP_IN_PATH: &str =
    "/etc/systemd/system/crowdsec-firewall-bouncer.service.d/fwcloud-ipsets.conf";
pub const BOUNCER_NFTABLES_DROP_IN_PATH: &str =
    "/etc/systemd/system/crowdsec-firewall-bouncer.service.d/fwcloud-nftables.conf";
pub const IPSET_V4_BLACKLIST: &str = "crowdsec-blacklists";
pub const IPSET_V6_BLACKLIST: &str = "crowdsec6-blacklists";
pub const NFTABLES_V4_TABLE: &str = "filter";
pub const NFTABLES_V4_CHAIN: &str = "INPUT";
pub const NFTABLES_V6_TABLE: &str = "filter";
pub const NFTABLES_V6_CHAIN: &str = "INPUT";

const IPSET_COMMAND: &str = "/usr/sbin/ipset";
const NFT_COMMAND: &str = "/usr/sbin/nft";
const CSCLI_COMMAND: &str = "/usr/bin/cscli";
const IPTABLES_COMMAND: &str = "/usr/sbin/iptables";
const IP6TABLES_COMMAND: &str = "/usr/sbin/ip6tables";
const IPTABLES_SAVE_COMMAND: &str = "/usr/sbin/iptables-save";
const IP6TABLES_SAVE_COMMAND: &str = "/usr/sbin/ip6tables-save";
const IPSET_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const IPSET_MAX_ELEMENTS: &str = "150000";
const SYSTEMCTL_COMMAND: &str = "/usr/bin/systemctl";
const LEGACY_BOUNCER_CHAIN: &str = "CROWDSEC_CHAIN";
const LEGACY_BOUNCER_IPSET_V4_PREFIX: &str = "crowdsec-blacklists-";
const LEGACY_BOUNCER_IPSET_V6_PREFIX: &str = "crowdsec6-blacklists-";
const LEGACY_BOUNCER_BASE_CHAINS: [&str; 2] = ["INPUT", "FORWARD"];

const IPSET_SETUP_SERVICE_CONTENT: &str = "[Unit]\nDescription=Create FWCloud CrowdSec blacklist IPSet\nBefore=crowdsec-firewall-bouncer.service\n\n[Service]\nType=oneshot\nExecStart=/usr/sbin/ipset create crowdsec-blacklists hash:ip timeout 0 maxelem 150000 -exist\nExecStart=/usr/sbin/ipset create crowdsec6-blacklists hash:ip family inet6 timeout 0 maxelem 150000 -exist\nRemainAfterExit=yes\n\n[Install]\nWantedBy=multi-user.target\n";
const BOUNCER_IPSET_DROP_IN_CONTENT: &str =
    "[Unit]\nRequires=fwcloud-crowdsec-ipsets.service\nAfter=fwcloud-crowdsec-ipsets.service\n";
const BOUNCER_NFTABLES_DROP_IN_CONTENT: &str = "[Unit]\nAfter=fwcloud.service\n";

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
    PendingFirewallPolicy,
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

#[derive(Debug)]
pub struct CrowdSecNftablesSetOnlyConfig {
    pub mode: &'static str,
    pub ipv4_table: &'static str,
    pub ipv4_chain: &'static str,
    pub ipv6_table: &'static str,
    pub ipv6_chain: &'static str,
}

impl Default for CrowdSecNftablesSetOnlyConfig {
    fn default() -> Self {
        Self {
            mode: "nftables",
            ipv4_table: NFTABLES_V4_TABLE,
            ipv4_chain: NFTABLES_V4_CHAIN,
            ipv6_table: NFTABLES_V6_TABLE,
            ipv6_chain: NFTABLES_V6_CHAIN,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BouncerConfigurationState {
    NotConfigured,
    SetOnly,
    Managed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NftablesBouncerServiceAction {
    Enable,
    Restart,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BouncerReconciliationAction {
    SkipCrowdSecNotInstalled,
    PendingFirewallPolicy,
    Reconcile,
}

pub async fn active_backend() -> Result<CrowdSecFirewallBackend> {
    let configured_backend = configured_backend().await?;
    Ok(select_active_backend(configured_backend))
}

pub async fn pending_backend() -> Result<Option<CrowdSecFirewallBackend>> {
    match fs::read_to_string(BOUNCER_PENDING_BACKEND_PATH).await {
        Ok(backend) => pending_backend_from_contents(&backend)
            .map(Some)
            .ok_or_else(|| {
                FwcError::crowdsec(
                    FIREWALL_INTEGRATION_INVALID,
                    "Invalid pending CrowdSec Firewall Bouncer backend",
                )
            }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(FwcError::crowdsec(
            FIREWALL_INTEGRATION_INVALID,
            "Unable to read pending CrowdSec Firewall Bouncer backend",
        )),
    }
}

pub fn pending_policy_status(backend: CrowdSecFirewallBackend) -> CrowdSecBouncerIntegrationStatus {
    CrowdSecBouncerIntegrationStatus {
        state: CrowdSecBouncerIntegrationState::PendingFirewallPolicy,
        ipv4_blacklist: CrowdSecIpSetStatus {
            name: IPSET_V4_BLACKLIST,
            exists: false,
        },
        ipv6_blacklist: CrowdSecIpSetStatus {
            name: IPSET_V6_BLACKLIST,
            exists: false,
        },
        managed_configuration: false,
        unmanaged_firewall_rules: false,
        service_running: false,
        message: match backend {
            CrowdSecFirewallBackend::Nftables => {
                "CrowdSec NFTables Firewall Bouncer waits for a deployed FWCloud policy"
            }
            CrowdSecFirewallBackend::Iptables => {
                "CrowdSec Firewall Bouncer waits for a deployed FWCloud policy"
            }
        }
        .to_string(),
    }
}

fn select_active_backend(
    configured_backend: Option<CrowdSecFirewallBackend>,
) -> CrowdSecFirewallBackend {
    configured_backend.unwrap_or(CrowdSecFirewallBackend::Iptables)
}

pub async fn status(backend: CrowdSecFirewallBackend) -> Result<CrowdSecBouncerIntegrationStatus> {
    let (ipv4_blacklist, ipv6_blacklist) = match backend {
        CrowdSecFirewallBackend::Iptables => (
            blacklist_ipset_status(IPSET_V4_BLACKLIST).await?,
            blacklist_ipset_status(IPSET_V6_BLACKLIST).await?,
        ),
        CrowdSecFirewallBackend::Nftables => (
            blacklist_nftables_status("ip", NFTABLES_V4_TABLE, IPSET_V4_BLACKLIST, "ipv4_addr")
                .await?,
            blacklist_nftables_status("ip6", NFTABLES_V6_TABLE, IPSET_V6_BLACKLIST, "ipv6_addr")
                .await?,
        ),
    };
    let configuration_state = bouncer_configuration_state(backend).await?;
    let service_running = systemd_service_is_running(FIREWALL_BOUNCER_SERVICE).await?;
    let unmanaged_firewall_rules = match backend {
        CrowdSecFirewallBackend::Iptables => has_unmanaged_crowdsec_firewall_rules().await?,
        CrowdSecFirewallBackend::Nftables => false,
    };

    Ok(integration_status(
        backend,
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

async fn blacklist_nftables_status(
    family: &str,
    table: &str,
    name: &'static str,
    expected_type: &str,
) -> Result<CrowdSecIpSetStatus> {
    if !Path::new(NFT_COMMAND).is_file() {
        return Ok(CrowdSecIpSetStatus {
            name,
            exists: false,
        });
    }

    let output = run_nft(&["--json", "list", "set", family, table, name]).await?;
    Ok(CrowdSecIpSetStatus {
        name,
        exists: output.status.success()
            && nftables_blacklist_set_is_compatible(
                String::from_utf8_lossy(&output.stdout).as_ref(),
                family,
                table,
                name,
                expected_type,
            ),
    })
}

pub async fn prepare_set_only_configuration() -> Result<String> {
    let api_key = existing_bouncer_api_key()
        .await?
        .unwrap_or(generate_bouncer_api_key().await?);

    fs::create_dir_all(BOUNCER_CONFIG_DIRECTORY)
        .await
        .map_err(|_| {
            FwcError::crowdsec(
                FIREWALL_INTEGRATION_INVALID,
                "Unable to create CrowdSec Firewall Bouncer configuration directory",
            )
        })?;
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
    emit_progress(
        progress,
        "Temporarily blocking CrowdSec Firewall Bouncer service during package transition",
    );
    mask_firewall_bouncer_service().await?;

    let response = match backend {
        CrowdSecFirewallBackend::Iptables => install_iptables_bouncer(progress).await,
        CrowdSecFirewallBackend::Nftables => install_nftables_bouncer(progress).await,
    };

    let response = match response {
        Ok(response) => response,
        Err(error) => {
            if let Err(unmask_error) = unmask_firewall_bouncer_service().await {
                debug!(
                    "Unable to restore CrowdSec Firewall Bouncer service after package transition failure: {}",
                    unmask_error
                );
            }
            return Err(error);
        }
    };

    clear_pending_backend().await?;

    Ok(response)
}

pub async fn reconcile_after_policy_deployment(backend: CrowdSecFirewallBackend) -> Result<bool> {
    if bouncer_reconciliation_action(
        packages::package_status().await?.crowdsec_installed,
        backend,
        true,
    ) == BouncerReconciliationAction::SkipCrowdSecNotInstalled
    {
        debug!(
            "CrowdSec is not installed; skipping Firewall Bouncer reconciliation after policy deployment"
        );
        return Ok(false);
    }

    reconcile_for_installed_crowdsec(backend, None).await
}

pub async fn reconcile_for_installed_crowdsec(
    backend: CrowdSecFirewallBackend,
    progress: Option<&CrowdSecProgress>,
) -> Result<bool> {
    let nftables_blacklist_sets_ready = if backend == CrowdSecFirewallBackend::Nftables {
        nftables_blacklist_sets_are_ready().await?
    } else {
        true
    };

    if bouncer_reconciliation_action(true, backend, nftables_blacklist_sets_ready)
        == BouncerReconciliationAction::PendingFirewallPolicy
    {
        debug!(
            "FWCloud NFTables CrowdSec blacklist sets are unavailable; delaying Firewall Bouncer reconciliation"
        );
        emit_warning(
            progress,
            "CrowdSec NFTables Firewall Bouncer waits for a deployed FWCloud policy",
        );
        write_pending_backend(backend).await?;
        return Ok(false);
    }

    reconcile_non_selected_bouncer_backend(backend, progress).await?;
    emit_progress(
        progress,
        "Reconciling CrowdSec Firewall Bouncer for the FWCloud firewall backend",
    );
    install_with_backend_and_progress(backend, progress).await?;
    emit_success(
        progress,
        "CrowdSec Firewall Bouncer is reconciled for the FWCloud firewall backend",
    );
    Ok(true)
}

fn bouncer_reconciliation_action(
    crowdsec_installed: bool,
    backend: CrowdSecFirewallBackend,
    nftables_blacklist_sets_ready: bool,
) -> BouncerReconciliationAction {
    if !crowdsec_installed {
        BouncerReconciliationAction::SkipCrowdSecNotInstalled
    } else if backend == CrowdSecFirewallBackend::Nftables && !nftables_blacklist_sets_ready {
        BouncerReconciliationAction::PendingFirewallPolicy
    } else {
        BouncerReconciliationAction::Reconcile
    }
}

async fn install_iptables_bouncer(
    progress: Option<&CrowdSecProgress>,
) -> Result<CrowdSecBouncerInstallResponse> {
    log::info!("Installing CrowdSec Firewall Bouncer in FWCloud IPSet-only mode");

    reconcile_non_selected_bouncer_backend(CrowdSecFirewallBackend::Iptables, progress).await?;
    remove_nftables_bouncer_drop_in().await?;

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
    emit_progress(progress, "Writing FWCloud IPSet-only bouncer configuration");
    write_set_only_configuration(CrowdSecFirewallBackend::Iptables, &api_key).await?;
    emit_success(
        progress,
        "FWCloud IPSet-only bouncer configuration is written",
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
    let legacy_resources_removed = reconcile_legacy_bouncer_resources(progress).await?;
    emit_progress(progress, "Enabling CrowdSec Firewall Bouncer service");
    unmask_firewall_bouncer_service().await?;
    enable_firewall_bouncer_service().await?;
    emit_success(
        progress,
        "CrowdSec Firewall Bouncer service is enabled and running",
    );
    let integration =
        validate_bouncer_integration(CrowdSecFirewallBackend::Iptables, progress).await?;

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
            boolean_step(
                CrowdSecBouncerInstallStep::LegacyResources,
                legacy_resources_removed,
                "Legacy CrowdSec Firewall Bouncer resources are removed",
                "No legacy CrowdSec Firewall Bouncer resources were found",
            ),
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
        integration,
    })
}

async fn install_nftables_bouncer(
    progress: Option<&CrowdSecProgress>,
) -> Result<CrowdSecBouncerInstallResponse> {
    log::info!("Installing CrowdSec Firewall Bouncer in FWCloud NFTables set-only mode");

    emit_progress(progress, "Installing NFTables runtime");
    let runtime_installed = packages::install_nftables_runtime_with_progress(progress).await?;
    if runtime_installed {
        emit_success(progress, "NFTables runtime is installed");
    } else {
        emit_warning(progress, "NFTables runtime is already installed");
    }

    emit_progress(
        progress,
        "Validating FWCloud CrowdSec NFTables blacklist sets",
    );
    validate_nftables_blacklist_sets().await?;
    emit_success(
        progress,
        "FWCloud CrowdSec NFTables blacklist sets are ready",
    );

    reconcile_non_selected_bouncer_backend(CrowdSecFirewallBackend::Nftables, progress).await?;

    emit_progress(
        progress,
        "Preparing CrowdSec NFTables Firewall Bouncer configuration",
    );
    let api_key = prepare_set_only_configuration().await?;
    write_set_only_configuration(CrowdSecFirewallBackend::Nftables, &api_key).await?;
    emit_success(
        progress,
        "FWCloud NFTables set-only bouncer configuration is written",
    );

    emit_progress(
        progress,
        "Installing CrowdSec NFTables Firewall Bouncer package",
    );
    let package_installed = packages::install_firewall_bouncer_package_for_backend_with_progress(
        CrowdSecFirewallBackend::Nftables,
        progress,
    )
    .await?;
    if package_installed {
        emit_success(
            progress,
            "CrowdSec NFTables Firewall Bouncer package is installed",
        );
    } else {
        emit_warning(
            progress,
            "CrowdSec NFTables Firewall Bouncer package is already installed",
        );
    }

    let legacy_resources_removed = reconcile_legacy_bouncer_resources(progress).await?;
    emit_progress(
        progress,
        "Configuring CrowdSec NFTables Firewall Bouncer startup order",
    );
    install_nftables_bouncer_drop_in().await?;
    emit_success(
        progress,
        "CrowdSec NFTables Firewall Bouncer starts after the FWCloud policy service",
    );
    let service_action = nftables_bouncer_service_action(
        systemd_service_is_running(FIREWALL_BOUNCER_SERVICE).await?,
    );
    let service_message = match service_action {
        NftablesBouncerServiceAction::Enable => {
            "CrowdSec NFTables Firewall Bouncer service is enabled and running"
        }
        NftablesBouncerServiceAction::Restart => {
            "CrowdSec NFTables Firewall Bouncer service is restarted and synchronizing decisions"
        }
    };
    emit_progress(progress, service_message);
    unmask_firewall_bouncer_service().await?;
    reconcile_nftables_firewall_bouncer_service(service_action).await?;
    emit_success(progress, service_message);
    let integration =
        validate_bouncer_integration(CrowdSecFirewallBackend::Nftables, progress).await?;

    log::info!("CrowdSec NFTables Firewall Bouncer installation completed");
    emit_success(
        progress,
        "CrowdSec NFTables Firewall Bouncer installation completed",
    );

    Ok(CrowdSecBouncerInstallResponse {
        steps: vec![
            CrowdSecStepResult {
                step: CrowdSecBouncerInstallStep::NftablesRuntime,
                status: CrowdSecStepStatus::Completed,
                message: if runtime_installed {
                    "NFTables runtime is installed".to_string()
                } else {
                    "NFTables runtime is already installed".to_string()
                },
            },
            CrowdSecStepResult {
                step: CrowdSecBouncerInstallStep::Package,
                status: CrowdSecStepStatus::Completed,
                message: if package_installed {
                    "CrowdSec NFTables Firewall Bouncer package is installed".to_string()
                } else {
                    "CrowdSec NFTables Firewall Bouncer package is already installed".to_string()
                },
            },
            CrowdSecStepResult {
                step: CrowdSecBouncerInstallStep::NftablesBlacklistSets,
                status: CrowdSecStepStatus::Completed,
                message: "FWCloud CrowdSec NFTables blacklist sets are ready".to_string(),
            },
            CrowdSecStepResult {
                step: CrowdSecBouncerInstallStep::Configuration,
                status: CrowdSecStepStatus::Completed,
                message: "CrowdSec Firewall Bouncer is configured for FWCloud NFTables set-only"
                    .to_string(),
            },
            boolean_step(
                CrowdSecBouncerInstallStep::LegacyResources,
                legacy_resources_removed,
                "Legacy CrowdSec Firewall Bouncer resources are removed",
                "No legacy CrowdSec Firewall Bouncer resources were found",
            ),
            CrowdSecStepResult {
                step: CrowdSecBouncerInstallStep::Service,
                status: CrowdSecStepStatus::Completed,
                message: service_message.to_string(),
            },
        ],
        integration,
    })
}

async fn reconcile_non_selected_bouncer_backend(
    backend: CrowdSecFirewallBackend,
    progress: Option<&CrowdSecProgress>,
) -> Result<()> {
    let non_selected_backend = non_selected_firewall_backend(backend);
    if !packages::firewall_bouncer_package_is_present(non_selected_backend).await? {
        return Ok(());
    }

    emit_progress(
        progress,
        "Removing the non-selected CrowdSec Firewall Bouncer backend",
    );
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
    let backend = configured_backend()
        .await?
        .unwrap_or(CrowdSecFirewallBackend::Iptables);
    log::info!(
        "Disabling FWCloud CrowdSec Firewall Bouncer while preserving packages and FWCloud firewall data"
    );

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
    let configuration_removed = remove_bouncer_configuration().await?;
    emit_boolean_result(
        progress,
        configuration_removed,
        "FWCloud CrowdSec Firewall Bouncer configuration is removed",
        "FWCloud CrowdSec Firewall Bouncer configuration is already absent",
    );
    emit_progress(
        progress,
        "Removing CrowdSec NFTables Firewall Bouncer startup order",
    );
    let nftables_startup_order_removed = remove_nftables_bouncer_drop_in().await?;
    emit_boolean_result(
        progress,
        nftables_startup_order_removed,
        "CrowdSec NFTables Firewall Bouncer startup order is removed",
        "CrowdSec NFTables Firewall Bouncer startup order is already absent",
    );
    let pending_backend_removed = remove_managed_file(BOUNCER_PENDING_BACKEND_PATH).await?;
    emit_boolean_result(
        progress,
        pending_backend_removed,
        "Pending CrowdSec Firewall Bouncer backend is removed",
        "Pending CrowdSec Firewall Bouncer backend is already absent",
    );
    let (ipset_setup_step, blacklist_sets_step) = match backend {
        CrowdSecFirewallBackend::Iptables => {
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

            (
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
            )
        }
        CrowdSecFirewallBackend::Nftables => {
            emit_warning(
                progress,
                "FWCloud NFTables blacklist sets are preserved and are not managed by the agent",
            );
            (
                skipped_step(
                    CrowdSecBouncerUninstallStep::IpSetSetupService,
                    "FWCloud IPSet boot service does not apply to the NFTables backend",
                ),
                skipped_step(
                    CrowdSecBouncerUninstallStep::BlacklistIpSets,
                    "FWCloud NFTables blacklist sets are preserved and are not managed by the agent",
                ),
            )
        }
    };

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
                CrowdSecBouncerUninstallStep::NftablesStartupOrder,
                nftables_startup_order_removed,
                "CrowdSec NFTables Firewall Bouncer startup order is removed",
                "CrowdSec NFTables Firewall Bouncer startup order is already absent",
            ),
            ipset_setup_step,
            blacklist_sets_step,
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

async fn write_set_only_configuration(
    backend: CrowdSecFirewallBackend,
    api_key: &str,
) -> Result<()> {
    fs::create_dir_all(BOUNCER_CONFIG_DIRECTORY)
        .await
        .map_err(|_| {
            FwcError::crowdsec(
                FIREWALL_INTEGRATION_INVALID,
                "Unable to create CrowdSec Firewall Bouncer configuration directory",
            )
        })?;
    let contents = match backend {
        CrowdSecFirewallBackend::Iptables => {
            set_only_configuration_contents(&CrowdSecBouncerSetOnlyConfig::default(), api_key)
        }
        CrowdSecFirewallBackend::Nftables => nftables_set_only_configuration_contents(
            &CrowdSecNftablesSetOnlyConfig::default(),
            api_key,
        ),
    };
    write_bouncer_configuration(&contents)
}

async fn write_pending_backend(backend: CrowdSecFirewallBackend) -> Result<()> {
    fs::create_dir_all(BOUNCER_CONFIG_DIRECTORY)
        .await
        .map_err(|_| {
            FwcError::crowdsec(
                FIREWALL_INTEGRATION_INVALID,
                "Unable to create CrowdSec Firewall Bouncer configuration directory",
            )
        })?;
    fs::write(
        BOUNCER_PENDING_BACKEND_PATH,
        pending_backend_contents(backend),
    )
    .await
    .map_err(|_| {
        FwcError::crowdsec(
            FIREWALL_INTEGRATION_INVALID,
            "Unable to store pending CrowdSec Firewall Bouncer backend",
        )
    })
}

async fn clear_pending_backend() -> Result<()> {
    match fs::remove_file(BOUNCER_PENDING_BACKEND_PATH).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(FwcError::crowdsec(
            FIREWALL_INTEGRATION_INVALID,
            "Unable to clear pending CrowdSec Firewall Bouncer backend",
        )),
    }
}

async fn configured_backend() -> Result<Option<CrowdSecFirewallBackend>> {
    match fs::read_to_string(BOUNCER_CONFIG_PATH).await {
        Ok(configuration) => Ok(configuration_backend(&configuration)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(FwcError::crowdsec(
            FIREWALL_INTEGRATION_INVALID,
            "Unable to read CrowdSec Firewall Bouncer configuration",
        )),
    }
}

async fn bouncer_configuration_state(
    backend: CrowdSecFirewallBackend,
) -> Result<BouncerConfigurationState> {
    match fs::read_to_string(BOUNCER_CONFIG_PATH).await {
        Ok(configuration) if configuration_is_set_only(&configuration, backend) => {
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
    backend: CrowdSecFirewallBackend,
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
            match backend {
                CrowdSecFirewallBackend::Iptables => "FWCloud CrowdSec blacklist IPSet are missing",
                CrowdSecFirewallBackend::Nftables => {
                    "FWCloud CrowdSec blacklist NFTables sets are missing or incompatible"
                }
            }
            .to_string(),
        )
    } else if configuration_state == BouncerConfigurationState::Managed {
        (
            CrowdSecBouncerIntegrationState::ManagedConfiguration,
            match backend {
                CrowdSecFirewallBackend::Iptables => {
                    "CrowdSec Firewall Bouncer configuration is not FWCloud IPSet-only"
                }
                CrowdSecFirewallBackend::Nftables => {
                    "CrowdSec Firewall Bouncer configuration is not FWCloud NFTables set-only"
                }
            }
            .to_string(),
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
            match backend {
                CrowdSecFirewallBackend::Iptables => {
                    "CrowdSec Firewall Bouncer is updating FWCloud IPSet only"
                }
                CrowdSecFirewallBackend::Nftables => {
                    "CrowdSec Firewall Bouncer is updating FWCloud NFTables sets only"
                }
            }
            .to_string(),
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

fn configuration_backend(configuration: &str) -> Option<CrowdSecFirewallBackend> {
    configuration.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim() != "mode" {
            return None;
        }

        match value.trim().trim_matches('"') {
            "ipset" => Some(CrowdSecFirewallBackend::Iptables),
            "nftables" => Some(CrowdSecFirewallBackend::Nftables),
            _ => None,
        }
    })
}

fn pending_backend_contents(backend: CrowdSecFirewallBackend) -> &'static str {
    match backend {
        CrowdSecFirewallBackend::Iptables => "iptables\n",
        CrowdSecFirewallBackend::Nftables => "nftables\n",
    }
}

fn pending_backend_from_contents(contents: &str) -> Option<CrowdSecFirewallBackend> {
    match contents.trim() {
        "iptables" => Some(CrowdSecFirewallBackend::Iptables),
        "nftables" => Some(CrowdSecFirewallBackend::Nftables),
        _ => None,
    }
}

fn configuration_is_fwcloud_managed(configuration: &str) -> bool {
    configuration
        .lines()
        .any(|line| line.trim() == FWCLOUD_BOUNCER_CONFIGURATION_MARKER)
}

fn configuration_is_set_only(configuration: &str, backend: CrowdSecFirewallBackend) -> bool {
    let expected = match backend {
        CrowdSecFirewallBackend::Iptables => vec![
            ("mode", "ipset"),
            ("blacklists_ipv4", IPSET_V4_BLACKLIST),
            ("blacklists_ipv6", IPSET_V6_BLACKLIST),
            ("ipset_type", "hash:ip"),
        ],
        CrowdSecFirewallBackend::Nftables => vec![
            ("mode", "nftables"),
            ("set-only", "true"),
            ("table", NFTABLES_V4_TABLE),
            ("chain", NFTABLES_V4_CHAIN),
        ],
    };

    let expected_are_present = expected.iter().all(|(key, expected_value)| {
        configuration.lines().any(|line| {
            line.split_once(':').is_some_and(|(line_key, value)| {
                line_key.trim() == *key && value.trim().trim_matches('"') == *expected_value
            })
        })
    });

    expected_are_present
        && !configuration_contains_bouncer_rule_settings(configuration, backend)
        && (backend != CrowdSecFirewallBackend::Nftables
            || (configuration.contains("  ipv4:\n") && configuration.contains("  ipv6:\n")))
}

fn configuration_contains_bouncer_rule_settings(
    configuration: &str,
    backend: CrowdSecFirewallBackend,
) -> bool {
    match backend {
        CrowdSecFirewallBackend::Iptables => configuration
            .lines()
            .any(|line| line.trim_start().starts_with("iptables_chains:")),
        CrowdSecFirewallBackend::Nftables => configuration.lines().any(|line| {
            let trimmed_line = line.trim();
            trimmed_line.starts_with("nftables_hooks:") || trimmed_line == "set-only: false"
        }),
    }
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

fn skipped_step<T>(step: T, message: &str) -> CrowdSecStepResult<T> {
    CrowdSecStepResult {
        step,
        status: CrowdSecStepStatus::Skipped,
        message: message.to_string(),
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

pub async fn validate_nftables_blacklist_sets() -> Result<()> {
    let blacklist_sets = [
        ("ip", NFTABLES_V4_TABLE, IPSET_V4_BLACKLIST, "ipv4_addr"),
        ("ip6", NFTABLES_V6_TABLE, IPSET_V6_BLACKLIST, "ipv6_addr"),
    ];

    for (family, table, name, expected_type) in blacklist_sets {
        let output = run_nft(&["--json", "list", "set", family, table, name]).await?;
        let output_is_compatible = output.status.success()
            && nftables_blacklist_set_is_compatible(
                String::from_utf8_lossy(&output.stdout).as_ref(),
                family,
                table,
                name,
                expected_type,
            );

        if !output_is_compatible {
            return Err(FwcError::crowdsec(
                FIREWALL_INTEGRATION_INVALID,
                "FWCloud NFTables CrowdSec blacklist sets are missing or incompatible",
            ));
        }
    }

    Ok(())
}

async fn nftables_blacklist_sets_are_ready() -> Result<bool> {
    let ipv4 =
        blacklist_nftables_status("ip", NFTABLES_V4_TABLE, IPSET_V4_BLACKLIST, "ipv4_addr").await?;
    let ipv6 = blacklist_nftables_status("ip6", NFTABLES_V6_TABLE, IPSET_V6_BLACKLIST, "ipv6_addr")
        .await?;

    Ok(ipv4.exists && ipv6.exists)
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

async fn install_nftables_bouncer_drop_in() -> Result<()> {
    fs::create_dir_all(BOUNCER_IPSET_DROP_IN_DIRECTORY)
        .await
        .map_err(|_| {
            FwcError::crowdsec(
                FIREWALL_INTEGRATION_INVALID,
                "Unable to create CrowdSec Firewall Bouncer systemd drop-in directory",
            )
        })?;
    write_if_changed(
        BOUNCER_NFTABLES_DROP_IN_PATH,
        BOUNCER_NFTABLES_DROP_IN_CONTENT,
    )
    .await?;
    run_systemctl(
        &["daemon-reload"],
        "Unable to reload CrowdSec NFTables systemd configuration",
    )
    .await
}

async fn remove_nftables_bouncer_drop_in() -> Result<bool> {
    let removed = remove_managed_file(BOUNCER_NFTABLES_DROP_IN_PATH).await?;
    if !removed {
        return Ok(false);
    }

    run_systemctl(
        &["daemon-reload"],
        "Unable to reload CrowdSec NFTables systemd configuration",
    )
    .await?;
    Ok(true)
}

async fn enable_firewall_bouncer_service() -> Result<()> {
    run_systemctl(
        &["enable", "--now", FIREWALL_BOUNCER_SERVICE],
        "Unable to enable CrowdSec Firewall Bouncer service",
    )
    .await
}

async fn mask_firewall_bouncer_service() -> Result<()> {
    if systemd_unit_exists(FIREWALL_BOUNCER_SERVICE).await? {
        run_systemctl(
            &["stop", FIREWALL_BOUNCER_SERVICE],
            "Unable to stop CrowdSec Firewall Bouncer service",
        )
        .await?;
    }

    run_systemctl(
        &["mask", "--runtime", FIREWALL_BOUNCER_SERVICE],
        "Unable to temporarily block CrowdSec Firewall Bouncer service",
    )
    .await
}

async fn unmask_firewall_bouncer_service() -> Result<()> {
    run_systemctl(
        &["unmask", "--runtime", FIREWALL_BOUNCER_SERVICE],
        "Unable to restore CrowdSec Firewall Bouncer service",
    )
    .await
}

fn nftables_bouncer_service_action(service_was_running: bool) -> NftablesBouncerServiceAction {
    if service_was_running {
        NftablesBouncerServiceAction::Restart
    } else {
        NftablesBouncerServiceAction::Enable
    }
}

async fn reconcile_nftables_firewall_bouncer_service(
    action: NftablesBouncerServiceAction,
) -> Result<()> {
    match action {
        NftablesBouncerServiceAction::Enable => {
            run_systemctl(
                &["enable", "--now", FIREWALL_BOUNCER_SERVICE],
                "Unable to enable CrowdSec NFTables Firewall Bouncer service",
            )
            .await
        }
        NftablesBouncerServiceAction::Restart => {
            run_systemctl(
                &["restart", FIREWALL_BOUNCER_SERVICE],
                "Unable to restart CrowdSec NFTables Firewall Bouncer service",
            )
            .await
        }
    }
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

async fn run_nft(arguments: &[&str]) -> Result<std::process::Output> {
    if !Path::new(NFT_COMMAND).is_file() {
        return Err(FwcError::crowdsec(
            FIREWALL_INTEGRATION_INVALID,
            "NFTables is not available for CrowdSec Firewall Bouncer integration",
        ));
    }

    debug!(
        "Running CrowdSec NFTables command: {} {:?}",
        NFT_COMMAND, arguments
    );
    timeout(
        IPSET_COMMAND_TIMEOUT,
        Command::new(NFT_COMMAND).args(arguments).output(),
    )
    .await
    .map_err(|_| FwcError::crowdsec(OPERATION_TIMEOUT, "CrowdSec NFTables command timed out"))?
    .map_err(|_| {
        FwcError::crowdsec(
            FIREWALL_INTEGRATION_INVALID,
            "Unable to run FWCloud NFTables command",
        )
    })
}

fn nftables_blacklist_set_is_compatible(
    output: &str,
    family: &str,
    table: &str,
    name: &str,
    expected_type: &str,
) -> bool {
    serde_json::from_str::<Value>(output)
        .ok()
        .and_then(|value| value.get("nftables")?.as_array().cloned())
        .is_some_and(|entries| {
            entries.iter().any(|entry| {
                let Some(set) = entry.get("set") else {
                    return false;
                };

                set.get("family").and_then(Value::as_str) == Some(family)
                    && set.get("table").and_then(Value::as_str) == Some(table)
                    && set.get("name").and_then(Value::as_str) == Some(name)
                    && set.get("type").and_then(Value::as_str) == Some(expected_type)
            })
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

async fn reconcile_legacy_bouncer_resources(progress: Option<&CrowdSecProgress>) -> Result<bool> {
    if systemd_service_is_running(FIREWALL_BOUNCER_SERVICE).await? {
        emit_progress(
            progress,
            "Stopping CrowdSec Firewall Bouncer before legacy resource cleanup",
        );
        run_systemctl(
            &["stop", FIREWALL_BOUNCER_SERVICE],
            "Unable to stop CrowdSec Firewall Bouncer before legacy resource cleanup",
        )
        .await?;
        emit_success(
            progress,
            "CrowdSec Firewall Bouncer is stopped for legacy resource cleanup",
        );
    }

    emit_progress(
        progress,
        "Removing legacy CrowdSec Firewall Bouncer resources",
    );
    let resources_removed = cleanup_legacy_bouncer_resources().await?;
    emit_boolean_result(
        progress,
        resources_removed,
        "Legacy CrowdSec Firewall Bouncer resources are removed",
        "No legacy CrowdSec Firewall Bouncer resources were found",
    );

    Ok(resources_removed)
}

async fn validate_bouncer_integration(
    backend: CrowdSecFirewallBackend,
    progress: Option<&CrowdSecProgress>,
) -> Result<CrowdSecBouncerIntegrationStatus> {
    emit_progress(
        progress,
        "Validating FWCloud CrowdSec Firewall Bouncer integration",
    );
    let integration = status(backend).await?;

    match integration.state {
        CrowdSecBouncerIntegrationState::Ready => emit_success(progress, &integration.message),
        _ => emit_warning(progress, &integration.message),
    }

    Ok(integration)
}

pub async fn cleanup_legacy_bouncer_resources() -> Result<bool> {
    let mut resources_removed = false;

    for (command, save_command) in [
        (IPTABLES_COMMAND, IPTABLES_SAVE_COMMAND),
        (IP6TABLES_COMMAND, IP6TABLES_SAVE_COMMAND),
    ] {
        if !Path::new(command).is_file() || !Path::new(save_command).is_file() {
            continue;
        }

        let output = run_iptables_save(save_command).await?;
        let rules = String::from_utf8_lossy(&output.stdout);
        let Some(jump_chains) = legacy_bouncer_jump_chains(&rules) else {
            continue;
        };

        for chain in jump_chains {
            run_iptables(command, &["-D", chain, "-j", LEGACY_BOUNCER_CHAIN]).await?;
        }
        run_iptables(command, &["-F", LEGACY_BOUNCER_CHAIN]).await?;
        run_iptables(command, &["-X", LEGACY_BOUNCER_CHAIN]).await?;
        resources_removed = true;
    }

    if Path::new(IPSET_COMMAND).is_file() {
        let output = run_ipset(&["list", "-name"]).await?;
        if output.status.success() {
            for name in legacy_bouncer_ipset_names(&String::from_utf8_lossy(&output.stdout)) {
                let output = run_ipset(&["destroy", name]).await?;
                if !output.status.success() {
                    return Err(FwcError::crowdsec(
                        FIREWALL_INTEGRATION_INVALID,
                        "Unable to remove legacy CrowdSec Firewall Bouncer IPSet",
                    ));
                }
                resources_removed = true;
            }
        }
    }

    Ok(resources_removed)
}

fn legacy_bouncer_jump_chains(rules: &str) -> Option<Vec<&'static str>> {
    if !rules
        .lines()
        .any(|line| line.starts_with(&format!(":{LEGACY_BOUNCER_CHAIN} ")))
    {
        return None;
    }

    let chain_rules = rules
        .lines()
        .filter(|line| line.starts_with(&format!("-A {LEGACY_BOUNCER_CHAIN} ")))
        .collect::<Vec<_>>();
    if chain_rules.is_empty()
        || !chain_rules
            .iter()
            .all(|line| line.contains("--comment \"CrowdSec:"))
    {
        return None;
    }

    let jump_chains = LEGACY_BOUNCER_BASE_CHAINS
        .iter()
        .flat_map(|chain| {
            rules
                .lines()
                .filter(move |line| *line == format!("-A {chain} -j {LEGACY_BOUNCER_CHAIN}"))
                .map(move |_| *chain)
        })
        .collect::<Vec<_>>();

    (!jump_chains.is_empty()).then_some(jump_chains)
}

fn legacy_bouncer_ipset_names(output: &str) -> Vec<&str> {
    output
        .lines()
        .map(str::trim)
        .filter(|name| {
            [
                LEGACY_BOUNCER_IPSET_V4_PREFIX,
                LEGACY_BOUNCER_IPSET_V6_PREFIX,
            ]
            .iter()
            .any(|prefix| {
                name.strip_prefix(prefix).is_some_and(|suffix| {
                    !suffix.is_empty() && suffix.chars().all(|value| value.is_ascii_digit())
                })
            })
        })
        .collect()
}

async fn run_iptables_save(command: &str) -> Result<std::process::Output> {
    debug!(
        "Inspecting legacy CrowdSec Firewall Bouncer rules: {}",
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

    if output.status.success() {
        Ok(output)
    } else {
        Err(FwcError::crowdsec(
            FIREWALL_INTEGRATION_INVALID,
            "Unable to inspect firewall rules for CrowdSec integration",
        ))
    }
}

async fn run_iptables(command: &str, arguments: &[&str]) -> Result<()> {
    debug!(
        "Running legacy CrowdSec Firewall Bouncer cleanup command: {} {:?}",
        command, arguments
    );
    let output = timeout(
        IPSET_COMMAND_TIMEOUT,
        Command::new(command).args(arguments).output(),
    )
    .await
    .map_err(|_| {
        FwcError::crowdsec(
            OPERATION_TIMEOUT,
            "CrowdSec Firewall Bouncer cleanup command timed out",
        )
    })?
    .map_err(|_| {
        FwcError::crowdsec(
            FIREWALL_INTEGRATION_INVALID,
            "Unable to run CrowdSec Firewall Bouncer cleanup command",
        )
    })?;

    if output.status.success() {
        Ok(())
    } else {
        Err(FwcError::crowdsec(
            FIREWALL_INTEGRATION_INVALID,
            "Unable to remove legacy CrowdSec Firewall Bouncer firewall resources",
        ))
    }
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

async fn remove_bouncer_configuration() -> Result<bool> {
    let configuration_removed = remove_fwcloud_bouncer_configuration().await?;
    let legacy_configuration_removed =
        remove_managed_file(LEGACY_BOUNCER_CONFIG_OVERRIDE_PATH).await?;

    Ok(configuration_removed || legacy_configuration_removed)
}

async fn remove_fwcloud_bouncer_configuration() -> Result<bool> {
    match fs::read_to_string(BOUNCER_CONFIG_PATH).await {
        Ok(configuration) if configuration_is_fwcloud_managed(&configuration) => {
            remove_managed_file(BOUNCER_CONFIG_PATH).await
        }
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(FwcError::crowdsec(
            FIREWALL_INTEGRATION_INVALID,
            "Unable to read CrowdSec Firewall Bouncer configuration",
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
    let legacy_key = bouncer_api_key_from_path(LEGACY_BOUNCER_CONFIG_OVERRIDE_PATH).await?;
    if legacy_key.is_some() {
        return Ok(legacy_key);
    }

    match fs::read_to_string(BOUNCER_CONFIG_PATH).await {
        Ok(configuration) if configuration_is_fwcloud_managed(&configuration) => {
            bouncer_api_key_from_contents(&configuration)
        }
        Ok(_) => Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(FwcError::crowdsec(
            FIREWALL_INTEGRATION_INVALID,
            "Unable to read CrowdSec Firewall Bouncer configuration",
        )),
    }
}

async fn bouncer_api_key_from_path(path: &str) -> Result<Option<String>> {
    match fs::read_to_string(path).await {
        Ok(configuration) => bouncer_api_key_from_contents(&configuration),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(FwcError::crowdsec(
            FIREWALL_INTEGRATION_INVALID,
            "Unable to read CrowdSec Firewall Bouncer configuration",
        )),
    }
}

fn bouncer_api_key_from_contents(configuration: &str) -> Result<Option<String>> {
    configuration
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
        })
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

fn write_bouncer_configuration(contents: &str) -> Result<()> {
    let temporary_path = format!("{}.tmp", BOUNCER_CONFIG_PATH);
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
        .write_all(contents.as_bytes())
        .and_then(|_| configuration_file.sync_all())
        .map_err(|_| {
            FwcError::crowdsec(
                FIREWALL_INTEGRATION_INVALID,
                "Unable to write CrowdSec Firewall Bouncer configuration",
            )
        })?;
    std_fs::rename(&temporary_path, BOUNCER_CONFIG_PATH).map_err(|_| {
        FwcError::crowdsec(
            FIREWALL_INTEGRATION_INVALID,
            "Unable to install CrowdSec Firewall Bouncer configuration",
        )
    })?;

    match std_fs::remove_file(LEGACY_BOUNCER_CONFIG_OVERRIDE_PATH) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(FwcError::crowdsec(
            FIREWALL_INTEGRATION_INVALID,
            "Unable to remove legacy CrowdSec Firewall Bouncer configuration",
        )),
    }
}

fn set_only_configuration_contents(
    configuration: &CrowdSecBouncerSetOnlyConfig,
    api_key: &str,
) -> String {
    format!(
        "{FWCLOUD_BOUNCER_CONFIGURATION_MARKER}\nmode: {}\napi_url: http://127.0.0.1:8080/\napi_key: {}\ndisable_ipv6: false\nblacklists_ipv4: {}\nblacklists_ipv6: {}\nipset_type: hash:ip\n",
        configuration.mode,
        api_key,
        configuration.blacklists_ipv4,
        configuration.blacklists_ipv6,
    )
}

fn nftables_set_only_configuration_contents(
    configuration: &CrowdSecNftablesSetOnlyConfig,
    api_key: &str,
) -> String {
    format!(
        "{FWCLOUD_BOUNCER_CONFIGURATION_MARKER}\nmode: {}\napi_url: http://127.0.0.1:8080/\napi_key: {}\ndisable_ipv6: false\nnftables:\n  ipv4:\n    enabled: true\n    set-only: true\n    table: {}\n    chain: {}\n  ipv6:\n    enabled: true\n    set-only: true\n    table: {}\n    chain: {}\n",
        configuration.mode,
        api_key,
        configuration.ipv4_table,
        configuration.ipv4_chain,
        configuration.ipv6_table,
        configuration.ipv6_chain,
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
        bouncer_reconciliation_action, bouncer_register_response, bouncers_from_json,
        configuration_backend, configuration_is_fwcloud_managed, configuration_is_set_only,
        emit_boolean_result, firewall_rules_contain_unmanaged_crowdsec, integration_status,
        legacy_bouncer_ipset_names, legacy_bouncer_jump_chains,
        nftables_blacklist_set_is_compatible, nftables_bouncer_service_action,
        nftables_set_only_configuration_contents, non_selected_firewall_backend,
        pending_backend_contents, pending_backend_from_contents, pending_policy_status,
        reject_fwcloud_bouncer, select_active_backend, set_only_configuration_contents,
        validate_bouncer_name, BouncerConfigurationState, BouncerReconciliationAction,
        CrowdSecBouncerIntegrationState, CrowdSecBouncerSetOnlyConfig, CrowdSecBouncersResponse,
        CrowdSecFirewallBackend, CrowdSecIpSetStatus, CrowdSecNftablesSetOnlyConfig,
        NftablesBouncerServiceAction, BOUNCER_CONFIG_PATH, BOUNCER_NFTABLES_DROP_IN_CONTENT,
        BOUNCER_NFTABLES_DROP_IN_PATH, FWCLOUD_BOUNCER_NAME, IPSET_V4_BLACKLIST,
        IPSET_V6_BLACKLIST, NFTABLES_V4_TABLE, NFTABLES_V6_TABLE,
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

        assert!(configuration_is_set_only(
            &configuration,
            CrowdSecFirewallBackend::Iptables,
        ));
        assert!(!configuration_is_set_only(
            &configuration.replace("mode: ipset", "mode: iptables"),
            CrowdSecFirewallBackend::Iptables,
        ));
        assert!(!configuration_is_set_only(
            &format!("{configuration}iptables_chains:\n  - INPUT\n"),
            CrowdSecFirewallBackend::Iptables,
        ));
        assert!(configuration_is_fwcloud_managed(&configuration));
        assert!(!configuration_is_fwcloud_managed(
            "mode: iptables\napi_key: package-generated-key\n"
        ));
        assert_eq!(
            BOUNCER_CONFIG_PATH,
            "/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
        );
    }

    #[test]
    fn generates_nftables_set_only_configuration() {
        let configuration = nftables_set_only_configuration_contents(
            &CrowdSecNftablesSetOnlyConfig::default(),
            "secret",
        );

        assert!(configuration.contains("mode: nftables\n"));
        assert!(configuration.contains("api_key: secret\n"));
        assert!(configuration.contains("  ipv4:\n    enabled: true\n    set-only: true\n"));
        assert!(configuration.contains("    table: filter\n    chain: INPUT\n"));
        assert!(configuration.contains("  ipv6:\n    enabled: true\n    set-only: true\n"));
        assert!(configuration_is_set_only(
            &configuration,
            CrowdSecFirewallBackend::Nftables,
        ));
        assert_eq!(
            configuration_backend(&configuration),
            Some(CrowdSecFirewallBackend::Nftables)
        );
        assert!(!configuration_is_set_only(
            &configuration.replace("  ipv6:\n", ""),
            CrowdSecFirewallBackend::Nftables,
        ));
        assert!(!configuration_is_set_only(
            &configuration.replace("set-only: true", "set-only: false"),
            CrowdSecFirewallBackend::Nftables,
        ));
        assert!(!configuration_is_set_only(
            &format!("{configuration}nftables_hooks:\n  - input\n"),
            CrowdSecFirewallBackend::Nftables,
        ));
    }

    #[test]
    fn orders_the_nftables_bouncer_after_the_fwcloud_policy_service() {
        assert_eq!(
            BOUNCER_NFTABLES_DROP_IN_CONTENT,
            "[Unit]\nAfter=fwcloud.service\n"
        );
    }

    #[test]
    fn chooses_to_skip_pending_or_reconcile_the_bouncer() {
        assert_eq!(
            bouncer_reconciliation_action(false, CrowdSecFirewallBackend::Iptables, true),
            BouncerReconciliationAction::SkipCrowdSecNotInstalled
        );
        assert_eq!(
            bouncer_reconciliation_action(true, CrowdSecFirewallBackend::Nftables, false),
            BouncerReconciliationAction::PendingFirewallPolicy
        );
        assert_eq!(
            bouncer_reconciliation_action(true, CrowdSecFirewallBackend::Nftables, true),
            BouncerReconciliationAction::Reconcile
        );
        assert_eq!(
            bouncer_reconciliation_action(true, CrowdSecFirewallBackend::Iptables, false),
            BouncerReconciliationAction::Reconcile
        );
    }

    #[test]
    fn uses_a_dedicated_nftables_bouncer_drop_in() {
        assert_eq!(
            BOUNCER_NFTABLES_DROP_IN_PATH,
            "/etc/systemd/system/crowdsec-firewall-bouncer.service.d/fwcloud-nftables.conf"
        );
    }

    #[test]
    fn selects_the_configured_backend_before_package_detection() {
        assert_eq!(
            select_active_backend(Some(CrowdSecFirewallBackend::Iptables)),
            CrowdSecFirewallBackend::Iptables
        );
        assert_eq!(
            select_active_backend(Some(CrowdSecFirewallBackend::Nftables)),
            CrowdSecFirewallBackend::Nftables
        );
        assert_eq!(
            select_active_backend(None),
            CrowdSecFirewallBackend::Iptables
        );
    }

    #[test]
    fn stores_and_reads_a_pending_nftables_backend() {
        assert_eq!(
            pending_backend_from_contents(pending_backend_contents(
                CrowdSecFirewallBackend::Nftables
            )),
            Some(CrowdSecFirewallBackend::Nftables)
        );
        assert_eq!(pending_backend_from_contents("unknown"), None);
    }

    #[test]
    fn reports_a_pending_nftables_policy_without_managing_sets() {
        let status = pending_policy_status(CrowdSecFirewallBackend::Nftables);

        assert_eq!(
            status.state,
            CrowdSecBouncerIntegrationState::PendingFirewallPolicy
        );
        assert!(!status.ipv4_blacklist.exists);
        assert!(!status.ipv6_blacklist.exists);
        assert!(!status.service_running);
        assert!(!status.managed_configuration);
    }

    #[test]
    fn selects_the_opposite_backend_for_reconciliation() {
        assert_eq!(
            non_selected_firewall_backend(CrowdSecFirewallBackend::Iptables),
            CrowdSecFirewallBackend::Nftables
        );
        assert_eq!(
            non_selected_firewall_backend(CrowdSecFirewallBackend::Nftables),
            CrowdSecFirewallBackend::Iptables
        );
    }

    #[test]
    fn restarts_an_active_nftables_bouncer_after_reconciliation() {
        assert_eq!(
            nftables_bouncer_service_action(false),
            NftablesBouncerServiceAction::Enable
        );
        assert_eq!(
            nftables_bouncer_service_action(true),
            NftablesBouncerServiceAction::Restart
        );
    }

    #[test]
    fn recognizes_compatible_nftables_blacklist_sets() {
        let ipv4_set = r#"{
            "nftables": [{
                "set": {
                    "family": "ip",
                    "table": "filter",
                    "name": "crowdsec-blacklists",
                    "type": "ipv4_addr"
                }
            }]
        }"#;
        let ipv6_set = r#"{
            "nftables": [{
                "set": {
                    "family": "ip6",
                    "table": "filter",
                    "name": "crowdsec6-blacklists",
                    "type": "ipv6_addr"
                }
            }]
        }"#;

        assert!(nftables_blacklist_set_is_compatible(
            ipv4_set,
            "ip",
            NFTABLES_V4_TABLE,
            IPSET_V4_BLACKLIST,
            "ipv4_addr",
        ));
        assert!(nftables_blacklist_set_is_compatible(
            ipv6_set,
            "ip6",
            NFTABLES_V6_TABLE,
            IPSET_V6_BLACKLIST,
            "ipv6_addr",
        ));
        assert!(!nftables_blacklist_set_is_compatible(
            ipv4_set,
            "ip",
            NFTABLES_V4_TABLE,
            IPSET_V4_BLACKLIST,
            "ipv6_addr",
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
    fn selects_only_legacy_bouncer_chains_and_ipsets_for_cleanup() {
        let legacy_rules = ":CROWDSEC_CHAIN - [0:0]\n-A INPUT -j CROWDSEC_CHAIN\n-A CROWDSEC_CHAIN -m set --match-set crowdsec-blacklists-0 src -m comment --comment \"CrowdSec: CAPI\" -j DROP\n-A FORWARD -m set --match-set crowdsec-blacklists src -j DROP\n";
        let ipsets = "crowdsec-blacklists\ncrowdsec-blacklists-0\ncrowdsec-blacklists-23\ncrowdsec6-blacklists\ncrowdsec6-blacklists-1\nuser-crowdsec-blacklists-0\n";

        assert_eq!(
            legacy_bouncer_jump_chains(legacy_rules),
            Some(vec!["INPUT"])
        );
        assert_eq!(
            legacy_bouncer_ipset_names(ipsets),
            vec![
                "crowdsec-blacklists-0",
                "crowdsec-blacklists-23",
                "crowdsec6-blacklists-1",
            ]
        );
    }

    #[test]
    fn preserves_non_legacy_crowdsec_chains() {
        let rules =
            ":CROWDSEC_CHAIN - [0:0]\n-A INPUT -j CROWDSEC_CHAIN\n-A CROWDSEC_CHAIN -j DROP\n";

        assert_eq!(legacy_bouncer_jump_chains(rules), None);
    }

    #[test]
    fn reports_invalid_integration_without_serializing_a_key() {
        let status = integration_status(
            CrowdSecFirewallBackend::Iptables,
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
    fn reports_nftables_specific_integration_messages() {
        let status = integration_status(
            CrowdSecFirewallBackend::Nftables,
            ipset_status(IPSET_V4_BLACKLIST, true),
            ipset_status(IPSET_V6_BLACKLIST, true),
            BouncerConfigurationState::SetOnly,
            true,
            false,
        );

        assert_eq!(status.state, CrowdSecBouncerIntegrationState::Ready);
        assert_eq!(
            status.message,
            "CrowdSec Firewall Bouncer is updating FWCloud NFTables sets only"
        );
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
