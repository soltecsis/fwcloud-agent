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

use log::{debug, info};
use tokio::{process::Command, time::timeout};

use crate::{
    crowdsec::{
        errors::{COMMAND_FAILED, OPERATION_TIMEOUT},
        models::{
            CrowdSecDataRetention, CrowdSecStepResult, CrowdSecStepStatus,
            CrowdSecUninstallResponse, CrowdSecUninstallStep,
        },
        packages,
    },
    errors::{FwcError, Result},
};

const SERVICE_COMMAND_TIMEOUT: Duration = Duration::from_secs(60);

pub async fn uninstall() -> Result<CrowdSecUninstallResponse> {
    info!("Uninstalling CrowdSec services and packages while preserving data");

    let mut steps = Vec::new();
    steps.push(
        disable_service(
            CrowdSecUninstallStep::FirewallBouncerService,
            "crowdsec-firewall-bouncer.service",
        )
        .await?,
    );
    steps.push(disable_service(CrowdSecUninstallStep::CrowdSecService, "crowdsec.service").await?);
    steps.push(packages::uninstall_packages().await?);

    info!("CrowdSec uninstall completed while preserving data");

    Ok(CrowdSecUninstallResponse {
        data_retention: CrowdSecDataRetention::Preserve,
        steps,
    })
}

async fn disable_service(
    step: CrowdSecUninstallStep,
    service: &str,
) -> Result<CrowdSecStepResult<CrowdSecUninstallStep>> {
    if !service_exists(service).await? {
        return Ok(CrowdSecStepResult {
            step,
            status: CrowdSecStepStatus::Skipped,
            message: format!("CrowdSec service is already absent: {}", service),
        });
    }

    run_systemctl(&["disable", "--now", service]).await?;

    Ok(CrowdSecStepResult {
        step,
        status: CrowdSecStepStatus::Completed,
        message: format!("CrowdSec service is disabled and stopped: {}", service),
    })
}

async fn service_exists(service: &str) -> Result<bool> {
    let output =
        run_systemctl_allow_failure(&["show", "--property=LoadState", "--value", service]).await?;

    Ok(output.status.success() && String::from_utf8_lossy(&output.stdout).trim() != "not-found")
}

async fn run_systemctl(arguments: &[&str]) -> Result<()> {
    let output = run_systemctl_allow_failure(arguments).await?;

    if output.status.success() {
        Ok(())
    } else {
        Err(FwcError::crowdsec(
            COMMAND_FAILED,
            "CrowdSec service command failed",
        ))
    }
}

async fn run_systemctl_allow_failure(arguments: &[&str]) -> Result<std::process::Output> {
    debug!(
        "Running CrowdSec service command: /usr/bin/systemctl {:?}",
        arguments
    );

    timeout(
        SERVICE_COMMAND_TIMEOUT,
        Command::new("/usr/bin/systemctl").args(arguments).output(),
    )
    .await
    .map_err(|_| FwcError::crowdsec(OPERATION_TIMEOUT, "CrowdSec service command timed out"))?
    .map_err(|_| FwcError::crowdsec(COMMAND_FAILED, "Unable to run CrowdSec service command"))
}
