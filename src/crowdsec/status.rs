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
    let packages = packages::package_status().await?;
    let bouncer_status = bouncers::status().await?;
    let crowdsec_running =
        packages.crowdsec_installed && service_is_running("crowdsec.service").await?;
    let lapi_status = local_api_status().await;
    let community_blocklist_status = community_blocklist_status().await;
    let active_decisions = active_decision_count().await;
    let installed_collections = installed_collection_count().await;
    let warnings = status_warnings(
        &packages,
        crowdsec_running,
        &lapi_status,
        &community_blocklist_status,
        &bouncer_status,
        &active_decisions,
        &installed_collections,
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
            installed: packages.firewall_bouncer_installed,
            backend: CrowdSecFirewallBackend::Iptables,
            integration: bouncer_status,
        },
        active_decisions,
        installed_collections,
        warnings,
    })
}

fn status_warnings(
    packages: &CrowdSecPackageStatus,
    crowdsec_running: bool,
    lapi: &CrowdSecHealthStatus,
    community_blocklist: &CrowdSecHealthStatus,
    integration: &bouncers::CrowdSecBouncerIntegrationStatus,
    active_decisions: &CrowdSecStatusCount,
    installed_collections: &CrowdSecStatusCount,
) -> Vec<CrowdSecStatusWarning> {
    let mut warnings = Vec::new();

    if !packages.crowdsec_installed {
        warnings.push(CrowdSecStatusWarning {
            component: "crowdsec".to_string(),
            message: "CrowdSec package is not installed".to_string(),
        });
    } else if !crowdsec_running {
        warnings.push(CrowdSecStatusWarning {
            component: "crowdsec".to_string(),
            message: "CrowdSec service is not running".to_string(),
        });
    }

    if !packages.firewall_bouncer_installed {
        warnings.push(CrowdSecStatusWarning {
            component: "firewall_bouncer".to_string(),
            message: "CrowdSec Firewall Bouncer package is not installed".to_string(),
        });
    }

    if !packages.ipset_installed {
        warnings.push(CrowdSecStatusWarning {
            component: "ipset".to_string(),
            message: "IPSet package is not installed".to_string(),
        });
    }

    if integration.state != bouncers::CrowdSecBouncerIntegrationState::Ready {
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
