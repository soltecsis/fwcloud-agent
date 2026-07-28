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
        errors::{FIREWALL_INTEGRATION_INVALID, OPERATION_TIMEOUT},
        models::{
            CrowdSecFirewallBackend, CrowdSecFirewallBouncerStatus, CrowdSecHealthState,
            CrowdSecHealthStatus, CrowdSecServiceStatus, CrowdSecStatusCount,
            CrowdSecStatusResponse,
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

    Ok(CrowdSecStatusResponse {
        crowdsec: CrowdSecServiceStatus {
            installed: packages.crowdsec_installed,
            running: packages.crowdsec_installed && service_is_running("crowdsec.service").await?,
            version: crowdsec_version(packages.crowdsec_installed).await,
        },
        ipset_installed: packages.ipset_installed,
        lapi: pending_health_status("Local API status is not collected yet"),
        community_blocklist: pending_health_status(
            "Community Blocklist status is not collected yet",
        ),
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

fn pending_health_status(message: &str) -> CrowdSecHealthStatus {
    CrowdSecHealthStatus {
        state: CrowdSecHealthState::Unknown,
        message: message.to_string(),
    }
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
