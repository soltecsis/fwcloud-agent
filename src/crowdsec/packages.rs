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
use tokio::{fs, process::Command, time::timeout};

use crate::{
    crowdsec::{
        errors::{COMMAND_FAILED, OPERATION_TIMEOUT, UNSUPPORTED_OS},
        models::{
            CrowdSecInstallStep, CrowdSecStepResult, CrowdSecStepStatus, CrowdSecUninstallStep,
        },
        secrets::redact_sensitive_text,
    },
    errors::{FwcError, Result},
};

const CROWDSEC_PACKAGES: &[&str] = &["crowdsec", "ipset"];
const CROWDSEC_REMOVABLE_PACKAGES: &[&str] = &["crowdsec-firewall-bouncer-iptables", "crowdsec"];
const COMMAND_TIMEOUT: Duration = Duration::from_secs(300);
const OS_RELEASE_PATH: &str = "/etc/os-release";
const APT_KEYRING_DIRECTORY: &str = "/etc/apt/keyrings";
const APT_KEYRING_PATH: &str = "/etc/apt/keyrings/crowdsec_crowdsec-archive-keyring.gpg";
const APT_KEYRING_TEMP_PATH: &str = "/etc/apt/keyrings/crowdsec_crowdsec-archive-keyring.gpg.tmp";
const APT_REPOSITORY_PATH: &str = "/etc/apt/sources.list.d/crowdsec_crowdsec.list";
const RPM_REPOSITORY_PATH: &str = "/etc/yum.repos.d/crowdsec_crowdsec.repo";
const CROWDSEC_GPG_KEY_URL: &str = "https://packagecloud.io/crowdsec/crowdsec/gpgkey";
const CROWDSEC_APT_REPOSITORY: &str = "deb [signed-by=/etc/apt/keyrings/crowdsec_crowdsec-archive-keyring.gpg] https://packagecloud.io/crowdsec/crowdsec/any any main\ndeb-src [signed-by=/etc/apt/keyrings/crowdsec_crowdsec-archive-keyring.gpg] https://packagecloud.io/crowdsec/crowdsec/any any main\n";
const CROWDSEC_RPM_REPOSITORY: &str = "[crowdsec_crowdsec]\nname=crowdsec_crowdsec\nbaseurl=https://packagecloud.io/crowdsec/crowdsec/rpm_any/rpm_any/$basearch\nrepo_gpgcheck=1\ngpgcheck=1\nenabled=1\ngpgkey=https://packagecloud.io/crowdsec/crowdsec/gpgkey\n       https://packagecloud.io/crowdsec/crowdsec/gpgkey/crowdsec-crowdsec-EDE2C695EC9A5A5C.pub.gpg\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackageManager {
    Apt,
    Dnf,
    Yum,
}

pub async fn install_packages() -> Result<Vec<CrowdSecStepResult<CrowdSecInstallStep>>> {
    let package_manager = detect_package_manager().await?;
    configure_repository(package_manager).await?;

    let mut installed_packages = Vec::new();
    let mut already_installed_packages = Vec::new();

    for package in CROWDSEC_PACKAGES {
        if package_is_installed(package_manager, package).await? {
            already_installed_packages.push(*package);
        } else {
            install_package(package_manager, package).await?;
            installed_packages.push(*package);
        }
    }

    let package_message = match (
        installed_packages.is_empty(),
        already_installed_packages.is_empty(),
    ) {
        (true, false) => "CrowdSec packages are already installed".to_string(),
        (false, true) => format!(
            "Installed CrowdSec packages: {}",
            installed_packages.join(", ")
        ),
        (false, false) => format!(
            "Installed CrowdSec packages: {}; already installed: {}",
            installed_packages.join(", "),
            already_installed_packages.join(", ")
        ),
        (true, true) => "No CrowdSec packages were requested".to_string(),
    };

    Ok(vec![
        CrowdSecStepResult {
            step: CrowdSecInstallStep::Repository,
            status: CrowdSecStepStatus::Completed,
            message: "CrowdSec package repository is configured".to_string(),
        },
        CrowdSecStepResult {
            step: CrowdSecInstallStep::Packages,
            status: CrowdSecStepStatus::Completed,
            message: package_message,
        },
    ])
}

pub async fn uninstall_packages() -> Result<CrowdSecStepResult<CrowdSecUninstallStep>> {
    let package_manager = detect_package_manager().await?;
    let mut removed_packages = Vec::new();
    let mut absent_packages = Vec::new();

    for package in CROWDSEC_REMOVABLE_PACKAGES {
        if package_is_installed(package_manager, package).await? {
            remove_package(package_manager, package).await?;
            removed_packages.push(*package);
        } else {
            absent_packages.push(*package);
        }
    }

    let message = package_removal_message(&removed_packages, &absent_packages);

    Ok(CrowdSecStepResult {
        step: CrowdSecUninstallStep::Packages,
        status: CrowdSecStepStatus::Completed,
        message,
    })
}

async fn detect_package_manager() -> Result<PackageManager> {
    let os_release = fs::read_to_string(OS_RELEASE_PATH).await.map_err(|_| {
        FwcError::crowdsec(UNSUPPORTED_OS, "Unable to identify the operating system")
    })?;
    let distribution = os_release_value(&os_release, "ID").unwrap_or_default();

    package_manager_for_os_release(
        &distribution,
        command_exists("/usr/bin/apt-get"),
        command_exists("/usr/bin/dnf"),
        command_exists("/usr/bin/yum"),
    )
    .ok_or_else(|| {
        FwcError::crowdsec(
            UNSUPPORTED_OS,
            "CrowdSec installation is not supported on this system",
        )
    })
}

fn package_manager_for_os_release(
    distribution: &str,
    apt_available: bool,
    dnf_available: bool,
    yum_available: bool,
) -> Option<PackageManager> {
    match distribution {
        "debian" | "ubuntu" if apt_available => Some(PackageManager::Apt),
        "rhel" | "centos" | "rocky" | "fedora" if dnf_available => Some(PackageManager::Dnf),
        "rhel" | "centos" | "rocky" | "fedora" if yum_available => Some(PackageManager::Yum),
        _ => None,
    }
}

fn package_removal_message(removed_packages: &[&str], absent_packages: &[&str]) -> String {
    match (removed_packages.is_empty(), absent_packages.is_empty()) {
        (true, false) => "CrowdSec packages are already absent".to_string(),
        (false, true) => format!("Removed CrowdSec packages: {}", removed_packages.join(", ")),
        (false, false) => format!(
            "Removed CrowdSec packages: {}; already absent: {}",
            removed_packages.join(", "),
            absent_packages.join(", ")
        ),
        (true, true) => "No CrowdSec packages were requested for removal".to_string(),
    }
}

async fn configure_repository(package_manager: PackageManager) -> Result<()> {
    match package_manager {
        PackageManager::Apt => configure_apt_repository().await,
        PackageManager::Dnf | PackageManager::Yum => {
            write_if_changed(RPM_REPOSITORY_PATH, CROWDSEC_RPM_REPOSITORY).await?;
            Ok(())
        }
    }
}

async fn configure_apt_repository() -> Result<()> {
    if apt_repository_is_configured().await {
        return run_command("/usr/bin/apt-get", &["update"]).await;
    }

    install_package(PackageManager::Apt, "curl").await?;
    install_package(PackageManager::Apt, "gnupg").await?;
    fs::create_dir_all(APT_KEYRING_DIRECTORY).await?;

    run_command(
        "/usr/bin/curl",
        &[
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--output",
            APT_KEYRING_TEMP_PATH,
            CROWDSEC_GPG_KEY_URL,
        ],
    )
    .await?;
    run_command(
        "/usr/bin/gpg",
        &[
            "--dearmor",
            "--yes",
            "--output",
            APT_KEYRING_PATH,
            APT_KEYRING_TEMP_PATH,
        ],
    )
    .await?;
    fs::remove_file(APT_KEYRING_TEMP_PATH).await?;
    write_if_changed(APT_REPOSITORY_PATH, CROWDSEC_APT_REPOSITORY).await?;
    run_command("/usr/bin/apt-get", &["update"]).await
}

async fn package_is_installed(package_manager: PackageManager, package: &str) -> Result<bool> {
    let (program, arguments): (&str, Vec<&str>) = match package_manager {
        PackageManager::Apt => (
            "/usr/bin/dpkg-query",
            vec!["--show", "--showformat=${db:Status-Status}", package],
        ),
        PackageManager::Dnf | PackageManager::Yum => ("/usr/bin/rpm", vec!["--query", package]),
    };

    let output = run_command_allow_failure(program, &arguments).await?;

    match package_manager {
        PackageManager::Apt => Ok(output.status.success()
            && String::from_utf8_lossy(&output.stdout).trim() == "installed"),
        PackageManager::Dnf | PackageManager::Yum => Ok(output.status.success()),
    }
}

async fn install_package(package_manager: PackageManager, package: &str) -> Result<()> {
    let (program, arguments): (&str, Vec<&str>) = match package_manager {
        PackageManager::Apt => ("/usr/bin/apt-get", vec!["install", "--yes", package]),
        PackageManager::Dnf => ("/usr/bin/dnf", vec!["install", "--assumeyes", package]),
        PackageManager::Yum => ("/usr/bin/yum", vec!["install", "--assumeyes", package]),
    };

    run_command(program, &arguments).await
}

async fn remove_package(package_manager: PackageManager, package: &str) -> Result<()> {
    let (program, arguments): (&str, Vec<&str>) = match package_manager {
        PackageManager::Apt => ("/usr/bin/apt-get", vec!["remove", "--yes", package]),
        PackageManager::Dnf => ("/usr/bin/dnf", vec!["remove", "--assumeyes", package]),
        PackageManager::Yum => ("/usr/bin/yum", vec!["remove", "--assumeyes", package]),
    };

    run_command(program, &arguments).await
}

async fn run_command(program: &str, arguments: &[&str]) -> Result<()> {
    let output = run_command_allow_failure(program, arguments).await?;

    if output.status.success() {
        debug!(
            "CrowdSec package command completed: {} {:?}",
            program, arguments
        );
        Ok(())
    } else {
        debug!(
            "CrowdSec package command failed: {} {:?} (exit code: {:?}, stdout: {}, stderr: {})",
            program,
            arguments,
            output.status.code(),
            redact_sensitive_text(&String::from_utf8_lossy(&output.stdout)),
            redact_sensitive_text(&String::from_utf8_lossy(&output.stderr)),
        );
        Err(FwcError::crowdsec(
            COMMAND_FAILED,
            "CrowdSec package command failed",
        ))
    }
}

async fn run_command_allow_failure(
    program: &str,
    arguments: &[&str],
) -> Result<std::process::Output> {
    debug!(
        "Running CrowdSec package command: {} {:?}",
        program, arguments
    );

    timeout(
        COMMAND_TIMEOUT,
        Command::new(program).args(arguments).output(),
    )
    .await
    .map_err(|_| {
        debug!(
            "CrowdSec package command timed out: {} {:?}",
            program, arguments
        );
        FwcError::crowdsec(OPERATION_TIMEOUT, "CrowdSec package command timed out")
    })?
    .map_err(|error| {
        debug!(
            "Unable to run CrowdSec package command: {} {:?} ({})",
            program, arguments, error
        );
        FwcError::crowdsec(COMMAND_FAILED, "Unable to run CrowdSec package command")
    })
}

async fn write_if_changed(path: &str, contents: &str) -> Result<()> {
    match fs::read_to_string(path).await {
        Ok(current_contents) if current_contents == contents => Ok(()),
        Ok(_) | Err(_) => fs::write(path, contents).await.map_err(FwcError::from),
    }
}

async fn apt_repository_is_configured() -> bool {
    fs::metadata(APT_KEYRING_PATH).await.is_ok()
        && matches!(
            fs::read_to_string(APT_REPOSITORY_PATH).await,
            Ok(contents) if contents == CROWDSEC_APT_REPOSITORY
        )
}

fn command_exists(path: &str) -> bool {
    std::path::Path::new(path).is_file()
}

fn os_release_value(os_release: &str, key: &str) -> Option<String> {
    os_release.lines().find_map(|line| {
        let (line_key, value) = line.split_once('=')?;

        (line_key == key).then(|| value.trim_matches('"').to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::{package_manager_for_os_release, package_removal_message, PackageManager};

    #[test]
    fn selects_supported_package_managers() {
        assert_eq!(
            package_manager_for_os_release("ubuntu", true, false, false),
            Some(PackageManager::Apt)
        );
        assert_eq!(
            package_manager_for_os_release("rocky", false, true, true),
            Some(PackageManager::Dnf)
        );
        assert_eq!(
            package_manager_for_os_release("centos", false, false, true),
            Some(PackageManager::Yum)
        );
        assert_eq!(
            package_manager_for_os_release("alpine", false, false, false),
            None
        );
    }

    #[test]
    fn removal_message_reports_idempotent_results() {
        assert_eq!(
            package_removal_message(&[], &["crowdsec"]),
            "CrowdSec packages are already absent"
        );
        assert_eq!(
            package_removal_message(&["crowdsec"], &["crowdsec-firewall-bouncer-iptables"]),
            "Removed CrowdSec packages: crowdsec; already absent: crowdsec-firewall-bouncer-iptables"
        );
    }
}
