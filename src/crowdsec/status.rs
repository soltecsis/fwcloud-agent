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
        console, decisions,
        errors::{FIREWALL_INTEGRATION_INVALID, OPERATION_TIMEOUT},
        models::{
            CrowdSecConsoleState, CrowdSecConsoleStatusResponse, CrowdSecDecisionsQuery,
            CrowdSecFirewallBackend, CrowdSecFirewallBouncerStatus, CrowdSecHealthState,
            CrowdSecHealthStatus, CrowdSecPackageStatus, CrowdSecServiceStatus,
            CrowdSecStatusCount, CrowdSecStatusResponse, CrowdSecStatusWarning,
        },
        packages,
    },
    errors::{FwcError, Result},
};

const SYSTEMCTL_COMMAND: &str = "/usr/bin/systemctl";
const SERVICE_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const DECISION_COUNT_LIMIT: u32 = 100;

pub async fn status() -> Result<CrowdSecStatusResponse> {
    let (packages, package_status_error) = match packages::package_status().await {
        Ok(packages) => (packages, None),
        Err(_) => (
            unavailable_package_status(),
            Some("Unable to determine CrowdSec package status"),
        ),
    };
    let (pending_bouncer_backend, pending_bouncer_error) = match bouncers::pending_backend().await {
        Ok(backend) => (backend, None),
        Err(_) => (
            None,
            Some("Unable to determine pending CrowdSec Firewall Bouncer backend"),
        ),
    };
    let (bouncer_backend, bouncer_backend_error) = match pending_bouncer_backend {
        Some(backend) => (backend, None),
        None => match bouncers::active_backend().await {
            Ok(backend) => (backend, None),
            Err(_) => (
                CrowdSecFirewallBackend::Iptables,
                Some("Unable to determine CrowdSec Firewall Bouncer backend"),
            ),
        },
    };
    let (bouncer_status, bouncer_status_error) = match pending_bouncer_backend {
        Some(backend) => (bouncers::pending_policy_status(backend), None),
        None => match bouncers::status(bouncer_backend).await {
            Ok(status) => (status, None),
            Err(_) => (
                unavailable_bouncer_status(),
                Some("Unable to determine CrowdSec Firewall Bouncer status"),
            ),
        },
    };
    let (crowdsec_running, service_status_error) = crowdsec_service_status(&packages).await;
    let lapi_status = local_api_status().await;
    let community_blocklist_status = community_blocklist_status().await;
    let active_decisions = active_decision_count().await;
    let installed_collections = installed_collection_count().await;
    let warnings = status_warnings(
        &packages,
        bouncer_backend,
        crowdsec_running,
        &lapi_status,
        &community_blocklist_status,
        &bouncer_status,
        &active_decisions,
        &installed_collections,
        package_status_error,
        service_status_error,
        pending_bouncer_error
            .or(bouncer_backend_error)
            .or(bouncer_status_error),
    );

    Ok(CrowdSecStatusResponse {
        crowdsec: CrowdSecServiceStatus {
            installed: packages.crowdsec_installed,
            running: crowdsec_running,
            version: crowdsec_version(packages.crowdsec_installed).await,
        },
        ipset_installed: packages.ipset_installed,
        lapi: lapi_status,
        community_blocklist: community_blocklist_status,
        firewall_bouncer: CrowdSecFirewallBouncerStatus {
            installed: packages.firewall_bouncer_installed(bouncer_backend),
            backend: bouncer_backend,
            integration: bouncer_status,
        },
        active_decisions,
        installed_collections,
        warnings,
    })
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

fn status_warnings(
    packages: &CrowdSecPackageStatus,
    bouncer_backend: CrowdSecFirewallBackend,
    crowdsec_running: bool,
    lapi: &CrowdSecHealthStatus,
    community_blocklist: &CrowdSecHealthStatus,
    integration: &bouncers::CrowdSecBouncerIntegrationStatus,
    active_decisions: &CrowdSecStatusCount,
    installed_collections: &CrowdSecStatusCount,
    package_status_error: Option<&str>,
    service_status_error: Option<&str>,
    bouncer_status_error: Option<&str>,
) -> Vec<CrowdSecStatusWarning> {
    let mut warnings = Vec::new();

    if let Some(message) = package_status_error {
        warnings.push(CrowdSecStatusWarning {
            component: "packages".to_string(),
            message: message.to_string(),
        });
    } else if !packages.crowdsec_installed {
        warnings.push(CrowdSecStatusWarning {
            component: "crowdsec".to_string(),
            message: "CrowdSec package is not installed".to_string(),
        });
    } else if let Some(message) = service_status_error {
        warnings.push(CrowdSecStatusWarning {
            component: "crowdsec".to_string(),
            message: message.to_string(),
        });
    } else if !crowdsec_running {
        warnings.push(CrowdSecStatusWarning {
            component: "crowdsec".to_string(),
            message: "CrowdSec service is not running".to_string(),
        });
    }

    if package_status_error.is_none()
        && integration.state != bouncers::CrowdSecBouncerIntegrationState::PendingFirewallPolicy
        && !packages.firewall_bouncer_installed(bouncer_backend)
    {
        warnings.push(CrowdSecStatusWarning {
            component: "firewall_bouncer".to_string(),
            message: "CrowdSec Firewall Bouncer package is not installed".to_string(),
        });
    }

    if package_status_error.is_none()
        && bouncer_backend == CrowdSecFirewallBackend::Iptables
        && !packages.ipset_installed
    {
        warnings.push(CrowdSecStatusWarning {
            component: "ipset".to_string(),
            message: "IPSet package is not installed".to_string(),
        });
    }

    if let Some(message) = bouncer_status_error {
        warnings.push(CrowdSecStatusWarning {
            component: "firewall_bouncer".to_string(),
            message: message.to_string(),
        });
    } else if integration.state != bouncers::CrowdSecBouncerIntegrationState::Ready {
        warnings.push(CrowdSecStatusWarning {
            component: "firewall_bouncer".to_string(),
            message: integration.message.clone(),
        });
    }

    append_health_warning(&mut warnings, "lapi", lapi);
    append_health_warning(&mut warnings, "community_blocklist", community_blocklist);
    append_count_warning(&mut warnings, "active_decisions", active_decisions);
    append_count_warning(
        &mut warnings,
        "installed_collections",
        installed_collections,
    );

    warnings
}

fn append_count_warning(
    warnings: &mut Vec<CrowdSecStatusWarning>,
    component: &str,
    count: &CrowdSecStatusCount,
) {
    if !matches!(
        count.state,
        CrowdSecHealthState::Ready | CrowdSecHealthState::Unknown
    ) {
        warnings.push(CrowdSecStatusWarning {
            component: component.to_string(),
            message: count.message.clone(),
        });
    }
}

fn append_health_warning(
    warnings: &mut Vec<CrowdSecStatusWarning>,
    component: &str,
    health: &CrowdSecHealthStatus,
) {
    if !matches!(
        health.state,
        CrowdSecHealthState::Ready | CrowdSecHealthState::Unknown
    ) {
        warnings.push(CrowdSecStatusWarning {
            component: component.to_string(),
            message: health.message.clone(),
        });
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
    } else {
        CrowdSecHealthStatus {
            state: CrowdSecHealthState::Unavailable,
            message: "CrowdSec Local API is unavailable".to_string(),
        }
    }
}

async fn community_blocklist_status() -> CrowdSecHealthStatus {
    match console::status().await {
        Ok(status) => health_status_from_console(status),
        Err(_) => health_error_status("Unable to determine Community Blocklist status"),
    }
}

fn health_status_from_console(status: CrowdSecConsoleStatusResponse) -> CrowdSecHealthStatus {
    let state = match status.state {
        CrowdSecConsoleState::NotConfigured => CrowdSecHealthState::NotConfigured,
        CrowdSecConsoleState::PendingApproval => CrowdSecHealthState::Unknown,
        CrowdSecConsoleState::Connected => CrowdSecHealthState::Ready,
        CrowdSecConsoleState::Error => CrowdSecHealthState::Error,
    };

    CrowdSecHealthStatus {
        state,
        message: status.message,
    }
}

fn health_error_status(message: &str) -> CrowdSecHealthStatus {
    CrowdSecHealthStatus {
        state: CrowdSecHealthState::Error,
        message: message.to_string(),
    }
}

async fn active_decision_count() -> CrowdSecStatusCount {
    debug!(
        "Counting local CrowdSec decisions with a maximum of {} entries",
        DECISION_COUNT_LIMIT
    );
    let query = CrowdSecDecisionsQuery {
        limit: Some(DECISION_COUNT_LIMIT),
        ..Default::default()
    };

    match decisions::list(&query).await {
        Ok(response) => {
            let count = response.decisions.len() as u64;
            let truncated = count == DECISION_COUNT_LIMIT as u64;
            CrowdSecStatusCount {
                count: Some(count),
                limit: Some(DECISION_COUNT_LIMIT as u64),
                truncated,
                state: CrowdSecHealthState::Ready,
                message: if truncated {
                    format!("At least {count} local active CrowdSec decisions")
                } else {
                    format!("{count} local active CrowdSec decisions")
                },
            }
        }
        Err(_) => count_error_status("Unable to count local active CrowdSec decisions"),
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
    use super::{
        crowdsec_version_from_output, status_warnings, unavailable_bouncer_status,
        unavailable_package_status,
    };
    use crate::crowdsec::{
        bouncers,
        bouncers::{
            CrowdSecBouncerIntegrationState, CrowdSecBouncerIntegrationStatus, CrowdSecIpSetStatus,
            IPSET_V4_BLACKLIST, IPSET_V6_BLACKLIST,
        },
        models::{
            CrowdSecFirewallBackend, CrowdSecFirewallBouncerStatus, CrowdSecHealthState,
            CrowdSecHealthStatus, CrowdSecPackageStatus, CrowdSecServiceStatus,
            CrowdSecStatusCount, CrowdSecStatusResponse,
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
    fn represents_partial_health_failures_as_warnings() {
        let packages = unavailable_package_status();
        let bouncer = unavailable_bouncer_status();
        let warnings = status_warnings(
            &packages,
            CrowdSecFirewallBackend::Iptables,
            false,
            &ready_health(),
            &ready_health(),
            &bouncer,
            &ready_count(),
            &ready_count(),
            Some("Unable to determine CrowdSec package status"),
            None,
            Some("Unable to determine CrowdSec Firewall Bouncer status"),
        );

        assert_eq!(warnings.len(), 2);
        assert_eq!(warnings[0].component, "packages");
        assert_eq!(warnings[1].component, "firewall_bouncer");
    }

    #[test]
    fn does_not_require_ipset_for_the_nftables_bouncer() {
        let packages = CrowdSecPackageStatus {
            crowdsec_installed: true,
            ipset_installed: false,
            iptables_firewall_bouncer_installed: false,
            nftables_firewall_bouncer_installed: true,
        };
        let warnings = status_warnings(
            &packages,
            CrowdSecFirewallBackend::Nftables,
            true,
            &ready_health(),
            &ready_health(),
            &ready_bouncer_status(),
            &ready_count(),
            &ready_count(),
            None,
            None,
            None,
        );

        assert!(warnings.iter().all(|warning| warning.component != "ipset"));
    }

    #[test]
    fn reports_pending_nftables_policy_without_a_missing_package_warning() {
        let packages = CrowdSecPackageStatus {
            crowdsec_installed: true,
            ipset_installed: false,
            iptables_firewall_bouncer_installed: false,
            nftables_firewall_bouncer_installed: false,
        };
        let pending = bouncers::pending_policy_status(CrowdSecFirewallBackend::Nftables);
        let warnings = status_warnings(
            &packages,
            CrowdSecFirewallBackend::Nftables,
            true,
            &ready_health(),
            &ready_health(),
            &pending,
            &ready_count(),
            &ready_count(),
            None,
            None,
            None,
        );

        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].component, "firewall_bouncer");
        assert_eq!(warnings[0].message, pending.message);
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
            community_blocklist: ready_health(),
            firewall_bouncer: CrowdSecFirewallBouncerStatus {
                installed: true,
                backend: CrowdSecFirewallBackend::Iptables,
                integration: ready_bouncer_status(),
            },
            active_decisions: ready_count(),
            installed_collections: ready_count(),
            warnings: vec![],
        };

        let serialized = serde_json::to_string(&response).unwrap();
        assert!(!serialized.contains("api_key"));
        assert!(!serialized.contains("enrollment_key"));
    }
}
