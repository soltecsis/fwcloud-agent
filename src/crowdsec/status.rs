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
        bouncers,
        command::CrowdSecCommand,
        console,
        errors::{FIREWALL_INTEGRATION_INVALID, OPERATION_TIMEOUT},
        models::{
            CrowdSecConsoleState, CrowdSecConsoleStatusResponse, CrowdSecFirewallBackend,
            CrowdSecFirewallBouncerStatus, CrowdSecHealthState, CrowdSecHealthStatus,
            CrowdSecServiceStatus, CrowdSecStatusCount, CrowdSecStatusResponse,
        },
        packages,
    },
    errors::{FwcError, Result},
};

const SYSTEMCTL_COMMAND: &str = "/usr/bin/systemctl";
const SERVICE_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

pub async fn status() -> Result<CrowdSecStatusResponse> {
    let packages = packages::package_status().await?;
    let bouncer_status = bouncers::status().await?;
    let lapi_status = local_api_status().await;
    let community_blocklist_status = community_blocklist_status().await;

    Ok(CrowdSecStatusResponse {
        crowdsec: CrowdSecServiceStatus {
            installed: packages.crowdsec_installed,
            running: packages.crowdsec_installed && service_is_running("crowdsec.service").await?,
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
        active_decisions: pending_count_status("Active decision count is not collected yet"),
        installed_collections: pending_count_status(
            "Installed collection count is not collected yet",
        ),
        warnings: vec![],
    })
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

fn pending_count_status(message: &str) -> CrowdSecStatusCount {
    CrowdSecStatusCount {
        count: None,
        state: CrowdSecHealthState::Unknown,
        message: message.to_string(),
    }
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
