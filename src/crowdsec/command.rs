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
    crowdsec::errors::{COMMAND_FAILED, INVALID_COMMAND, OPERATION_TIMEOUT},
    crowdsec::secrets::redact_sensitive_text,
    errors::{FwcError, Result},
};

pub const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub struct CrowdSecCommand {
    args: Vec<String>,
}

pub struct CrowdSecCommandOutput {
    stdout: String,
    stderr: String,
}

impl CrowdSecCommandOutput {
    pub(crate) fn stdout(&self) -> &str {
        &self.stdout
    }

    pub fn redacted_stdout(&self) -> String {
        redact_sensitive_text(&self.stdout)
    }

    pub fn redacted_stderr(&self) -> String {
        redact_sensitive_text(&self.stderr)
    }
}

impl CrowdSecCommand {
    pub fn cscli(args: &[&str]) -> Result<Self> {
        if args.is_empty()
            || args
                .iter()
                .any(|arg| arg.is_empty() || arg.len() > 256 || arg.chars().any(char::is_control))
        {
            return Err(FwcError::crowdsec(
                INVALID_COMMAND,
                "Invalid CrowdSec command argument",
            ));
        }

        Ok(Self {
            args: args.iter().map(|arg| (*arg).to_string()).collect(),
        })
    }

    pub async fn execute(self) -> Result<CrowdSecCommandOutput> {
        let output = timeout(
            DEFAULT_COMMAND_TIMEOUT,
            Command::new("cscli").args(&self.args).output(),
        )
        .await
        .map_err(|_| FwcError::crowdsec(OPERATION_TIMEOUT, "CrowdSec command timed out"))??;

        if !output.status.success() {
            if self.has_safe_diagnostic_output() {
                debug!(
                    "CrowdSec collection command failed (exit code: {:?}, stdout: {}, stderr: {})",
                    output.status.code(),
                    redact_sensitive_text(&String::from_utf8_lossy(&output.stdout)),
                    redact_sensitive_text(&String::from_utf8_lossy(&output.stderr)),
                );
            }

            return Err(FwcError::crowdsec(
                COMMAND_FAILED,
                "CrowdSec command failed",
            ));
        }

        Ok(CrowdSecCommandOutput {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }

    fn has_safe_diagnostic_output(&self) -> bool {
        matches!(
            self.args.first().map(String::as_str),
            Some("collections") | Some("hub")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::CrowdSecCommand;
    use crate::{crowdsec::errors::INVALID_COMMAND, errors::FwcError};

    #[test]
    fn rejects_empty_control_and_oversized_arguments() {
        let oversized_argument = "a".repeat(257);

        for args in [
            vec![],
            vec![""],
            vec!["invalid\nargument"],
            vec![oversized_argument.as_str()],
        ] {
            let error = CrowdSecCommand::cscli(&args).unwrap_err();
            assert!(matches!(
                error,
                FwcError::CrowdSec {
                    code: INVALID_COMMAND,
                    ..
                }
            ));
        }
    }

    #[test]
    fn preserves_valid_arguments_as_separate_values() {
        let command =
            CrowdSecCommand::cscli(&["collections", "install", "crowdsecurity/sshd"]).unwrap();

        assert_eq!(
            command.args,
            vec!["collections", "install", "crowdsecurity/sshd"]
        );
    }
}
