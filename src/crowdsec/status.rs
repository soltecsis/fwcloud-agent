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

use std::time::Duration;

use log::debug;
use tokio::{process::Command, time::timeout};

use crate::{
    crowdsec::{
        bouncers, collections,
        command::CrowdSecCommand,
        decisions,
        errors::{FIREWALL_INTEGRATION_INVALID, OPERATION_TIMEOUT},
        lapi,
        models::{
            CrowdSecFirewallBackend, CrowdSecFirewallBouncerStatus,
            CrowdSecHealthState, CrowdSecHealthStatus, CrowdSecPackageStatus,
            CrowdSecServiceStatus, CrowdSecStatusCount, CrowdSecStatusResponse,
        },
        packages,
    },
    errors::{FwcError, Result},
};

const SYSTEMCTL_COMMAND: &str = "/usr/bin/systemctl";
const SERVICE_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

pub async fn status() -> Result<CrowdSecStatusResponse> {
    let packages = packages::package_status()
        .await
        .unwrap_or_else(|_| unavailable_package_status());
    let pending_bouncer_backend = bouncers::pending_backend().await.unwrap_or(None);
    let bouncer_backend = match pending_bouncer_backend {
        Some(backend) => backend,
        None => match bouncers::active_backend().await {
            Ok(backend) => backend,
            Err(_) => CrowdSecFirewallBackend::Iptables,
        },
    };
    let bouncer_status = match pending_bouncer_backend {
        Some(backend) => bouncers::pending_policy_status(backend),
        None => match bouncers::status(bouncer_backend).await {
            Ok(status) => status,
            Err(_) => unavailable_bouncer_status(),
        },
    };
    let (crowdsec_running, _) = crowdsec_service_status(&packages).await;
    let lapi_status = local_api_status().await;
    let active_decisions = active_decision_count().await;
    let installed_collections = installed_collection_count().await;
    let (ipv4_blacklist_entries, ipv6_blacklist_entries) =
        managed_blacklist_entry_counts(bouncer_backend).await;
    Ok(CrowdSecStatusResponse {
        crowdsec: CrowdSecServiceStatus {
            installed: packages.crowdsec_installed,
            running: crowdsec_running,
            version: crowdsec_version(packages.crowdsec_installed).await,
        },
        ipset_installed: packages.ipset_installed,
        lapi: lapi_status,
        firewall_bouncer: CrowdSecFirewallBouncerStatus {
            installed: packages.firewall_bouncer_installed(bouncer_backend),
            backend: bouncer_backend,
            integration: bouncer_status,
        },
        active_decisions,
        installed_collections,
        ipv4_blacklist_entries,
        ipv6_blacklist_entries,
    })
}

async fn managed_blacklist_entry_counts(
    backend: CrowdSecFirewallBackend,
) -> (CrowdSecStatusCount, CrowdSecStatusCount) {
    if backend == CrowdSecFirewallBackend::Nftables {
        return (
            non_ipset_count_status("CrowdSec Firewall Bouncer uses NFTables instead of IPSet"),
            non_ipset_count_status("CrowdSec Firewall Bouncer uses NFTables instead of IPSet"),
        );
    }

    (
        ipset_entry_count(bouncers::IPSET_V4_BLACKLIST, "IPv4").await,
        ipset_entry_count(bouncers::IPSET_V6_BLACKLIST, "IPv6").await,
    )
}

async fn ipset_entry_count(name: &str, address_family: &str) -> CrowdSecStatusCount {
    match bouncers::ipset_entry_count(name).await {
        Ok(count) => CrowdSecStatusCount {
            count: Some(count),
            limit: None,
            truncated: false,
            state: CrowdSecHealthState::Ready,
            message: format!("{count} entries in CrowdSec {address_family} blacklist IPSet"),
        },
        Err(_) => count_error_status(&format!(
            "Unable to count entries in CrowdSec {address_family} blacklist IPSet"
        )),
    }
}

fn non_ipset_count_status(message: &str) -> CrowdSecStatusCount {
    CrowdSecStatusCount {
        count: None,
        limit: None,
        truncated: false,
        state: CrowdSecHealthState::NotApplicable,
        message: message.to_string(),
    }
}

fn unavailable_package_status() -> CrowdSecPackageStatus {
    CrowdSecPackageStatus {
        crowdsec_installed: false,
        ipset_installed: false,
        iptables_firewall_bouncer_installed: false,
        nftables_firewall_bouncer_installed: false,
    }
}

fn unavailable_bouncer_status() -> bouncers::CrowdSecBouncerIntegrationStatus {
    bouncers::CrowdSecBouncerIntegrationStatus {
        state: bouncers::CrowdSecBouncerIntegrationState::Error,
        ipv4_blacklist: bouncers::CrowdSecIpSetStatus {
            name: bouncers::IPSET_V4_BLACKLIST,
            exists: false,
        },
        ipv6_blacklist: bouncers::CrowdSecIpSetStatus {
            name: bouncers::IPSET_V6_BLACKLIST,
            exists: false,
        },
        managed_configuration: false,
        unmanaged_firewall_rules: false,
        service_running: false,
        message: "Unable to determine CrowdSec Firewall Bouncer status".to_string(),
    }
}

async fn crowdsec_service_status(packages: &CrowdSecPackageStatus) -> (bool, Option<&'static str>) {
    if !packages.crowdsec_installed {
        return (false, None);
    }

    match service_is_running("crowdsec.service").await {
        Ok(running) => (running, None),
        Err(_) => (false, Some("Unable to determine CrowdSec service status")),
    }
}

async fn local_api_status() -> CrowdSecHealthStatus {
    debug!("Checking CrowdSec Local API reachability");
    let Ok(command) = CrowdSecCommand::cscli(&["lapi", "status"]) else {
        return health_error_status("Unable to prepare CrowdSec Local API status command");
    };
    let output = match command.execute_allow_failure().await {
        Ok(output) => output,
        Err(_) => return health_error_status("Unable to determine CrowdSec Local API status"),
    };

    if output.succeeded() {
        CrowdSecHealthStatus {
            state: CrowdSecHealthState::Ready,
            message: "CrowdSec Local API is reachable".to_string(),
        }
    } else if lapi::requires_machine_reauthentication(&output) {
        CrowdSecHealthStatus {
            state: CrowdSecHealthState::ReauthenticationRequired,
            message: "CrowdSec machine is no longer registered in the central Local API. Register and validate it again.".to_string(),
        }
    } else {
        CrowdSecHealthStatus {
            state: CrowdSecHealthState::Unavailable,
            message: "CrowdSec Local API is unavailable".to_string(),
        }
    }
}

fn health_error_status(message: &str) -> CrowdSecHealthStatus {
    CrowdSecHealthStatus {
        state: CrowdSecHealthState::Error,
        message: message.to_string(),
    }
}

async fn active_decision_count() -> CrowdSecStatusCount {
    debug!("Counting all active CrowdSec decisions");

    match decisions::total().await {
        Ok(count) => CrowdSecStatusCount {
            count: Some(count),
            limit: None,
            truncated: false,
            state: CrowdSecHealthState::Ready,
            message: format!("{count} active CrowdSec decisions"),
        },
        Err(_) => count_error_status("Unable to count active CrowdSec decisions"),
    }
}

async fn installed_collection_count() -> CrowdSecStatusCount {
    debug!("Counting installed CrowdSec collections");
    match collections::list(true).await {
        Ok(response) => {
            let count = response.collections.len() as u64;
            CrowdSecStatusCount {
                count: Some(count),
                limit: None,
                truncated: false,
                state: CrowdSecHealthState::Ready,
                message: format!("{count} CrowdSec collections are installed"),
            }
        }
        Err(_) => count_error_status("Unable to count installed CrowdSec collections"),
    }
}

fn count_error_status(message: &str) -> CrowdSecStatusCount {
    CrowdSecStatusCount {
        count: None,
        limit: None,
        truncated: false,
        state: CrowdSecHealthState::Error,
        message: message.to_string(),
    }
}

async fn crowdsec_version(installed: bool) -> Option<String> {
    if !installed {
        return None;
    }

    debug!("Reading CrowdSec version");
    let output = CrowdSecCommand::cscli(&["version"])
        .ok()?
        .execute_allow_failure()
        .await
        .ok()?;

    output.succeeded().then(|| {
        crowdsec_version_from_output(&format!("{}\n{}", output.stdout(), output.stderr()))
    })?
}

fn crowdsec_version_from_output(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let (_, version) = line.rsplit_once("version:")?;
        let version = version.trim();
        (!version.is_empty()).then(|| version.to_string())
    })
}

async fn service_is_running(service: &str) -> Result<bool> {
    debug!(
        "Checking CrowdSec systemd service state: {} is-active",
        service
    );
    let output = timeout(
        SERVICE_COMMAND_TIMEOUT,
        Command::new(SYSTEMCTL_COMMAND)
            .args(["is-active", "--quiet", service])
            .output(),
    )
    .await
    .map_err(|_| FwcError::crowdsec(OPERATION_TIMEOUT, "CrowdSec service command timed out"))?
    .map_err(|_| {
        FwcError::crowdsec(
            FIREWALL_INTEGRATION_INVALID,
            "Unable to run CrowdSec service command",
        )
    })?;

    Ok(output.status.success())
}

#[cfg(test)]
mod tests {
    use super::crowdsec_version_from_output;
    use crate::crowdsec::{
        bouncers::{
            CrowdSecBouncerIntegrationState, CrowdSecBouncerIntegrationStatus, CrowdSecIpSetStatus,
            IPSET_V4_BLACKLIST, IPSET_V6_BLACKLIST,
        },
        models::{
            CrowdSecFirewallBackend, CrowdSecFirewallBouncerStatus, CrowdSecHealthState,
            CrowdSecHealthStatus, CrowdSecServiceStatus, CrowdSecStatusCount,
            CrowdSecStatusResponse,
        },
    };

    fn ready_health() -> CrowdSecHealthStatus {
        CrowdSecHealthStatus {
            state: CrowdSecHealthState::Ready,
            message: "ready".to_string(),
        }
    }

    fn ready_count() -> CrowdSecStatusCount {
        CrowdSecStatusCount {
            count: Some(0),
            limit: None,
            truncated: false,
            state: CrowdSecHealthState::Ready,
            message: "ready".to_string(),
        }
    }

    fn ready_bouncer_status() -> CrowdSecBouncerIntegrationStatus {
        CrowdSecBouncerIntegrationStatus {
            state: CrowdSecBouncerIntegrationState::Ready,
            ipv4_blacklist: CrowdSecIpSetStatus {
                name: IPSET_V4_BLACKLIST,
                exists: true,
            },
            ipv6_blacklist: CrowdSecIpSetStatus {
                name: IPSET_V6_BLACKLIST,
                exists: true,
            },
            managed_configuration: false,
            unmanaged_firewall_rules: false,
            service_running: true,
            message: "ready".to_string(),
        }
    }

    #[test]
    fn reads_the_version_written_by_crowdsec_logger() {
        let output = "2026/07/28 10:00:00 version: v1.7.0\nCodename: test";

        assert_eq!(
            crowdsec_version_from_output(output).as_deref(),
            Some("v1.7.0")
        );
    }

    #[test]
    fn status_contract_does_not_include_credential_fields() {
        let response = CrowdSecStatusResponse {
            crowdsec: CrowdSecServiceStatus {
                installed: true,
                running: true,
                version: Some("v1.7.0".to_string()),
            },
            ipset_installed: true,
            lapi: ready_health(),
            firewall_bouncer: CrowdSecFirewallBouncerStatus {
                installed: true,
                backend: CrowdSecFirewallBackend::Iptables,
                integration: ready_bouncer_status(),
            },
            active_decisions: ready_count(),
            installed_collections: ready_count(),
            ipv4_blacklist_entries: ready_count(),
            ipv6_blacklist_entries: ready_count(),
        };

        let serialized = serde_json::to_string(&response).unwrap();
        assert!(!serialized.contains("community_blocklist"));
        assert!(!serialized.contains("warnings"));
        assert!(!serialized.contains("api_key"));
        assert!(!serialized.contains("enrollment_key"));
    }
}
