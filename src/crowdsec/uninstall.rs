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
        bouncer,
        errors::{COMMAND_FAILED, OPERATION_TIMEOUT, UNINSTALL_CONFIRMATION_REQUIRED},
        models::{
            CrowdSecDataRetention, CrowdSecStepResult, CrowdSecStepStatus,
            CrowdSecUninstallResponse, CrowdSecUninstallStep,
        },
        packages,
    },
    errors::{FwcError, Result},
};

const SERVICE_COMMAND_TIMEOUT: Duration = Duration::from_secs(60);

pub fn require_confirmation(confirm: bool) -> Result<()> {
    if confirm {
        Ok(())
    } else {
        Err(FwcError::crowdsec(
            UNINSTALL_CONFIRMATION_REQUIRED,
            "CrowdSec uninstall requires confirm: true",
        ))
    }
}

pub async fn uninstall() -> Result<CrowdSecUninstallResponse> {
    info!("Uninstalling CrowdSec services and packages while preserving data");

    let mut steps = Vec::new();
    let bouncer_uninstall = bouncer::uninstall().await?;
    steps.push(bouncer_uninstall_step(&bouncer_uninstall));
    steps.push(disable_service(CrowdSecUninstallStep::CrowdSecService, "crowdsec.service").await?);
    steps.push(packages::uninstall_packages().await?);

    info!("CrowdSec uninstall completed while preserving data");

    Ok(CrowdSecUninstallResponse {
        data_retention: CrowdSecDataRetention::Preserve,
        steps,
    })
}

fn bouncer_uninstall_step(
    response: &crate::crowdsec::models::CrowdSecBouncerUninstallResponse,
) -> CrowdSecStepResult<CrowdSecUninstallStep> {
    let cleaned = response
        .steps
        .iter()
        .any(|step| step.status == CrowdSecStepStatus::Completed);

    CrowdSecStepResult {
        step: CrowdSecUninstallStep::FirewallBouncerService,
        status: if cleaned {
            CrowdSecStepStatus::Completed
        } else {
            CrowdSecStepStatus::Skipped
        },
        message: if cleaned {
            "FWCloud CrowdSec Firewall Bouncer is disabled and cleaned up".to_string()
        } else {
            "FWCloud CrowdSec Firewall Bouncer is already absent".to_string()
        },
    }
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

#[cfg(test)]
mod tests {
    use super::require_confirmation;
    use crate::{crowdsec::errors::UNINSTALL_CONFIRMATION_REQUIRED, errors::FwcError};

    #[test]
    fn uninstall_requires_explicit_confirmation() {
        assert!(require_confirmation(true).is_ok());

        let error = require_confirmation(false).unwrap_err();
        assert!(matches!(
            error,
            FwcError::CrowdSec {
                code: UNINSTALL_CONFIRMATION_REQUIRED,
                ..
            }
        ));
    }
}
