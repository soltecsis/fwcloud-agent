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

use serde::Deserialize;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use validator::Validate;

use crate::errors::{FwcError, Result};
use crate::CommandExecutor;

#[derive(Deserialize, Validate)]
pub struct OpenVPNDir {
    #[validate(regex(
        path = "crate::utils::myregex::ABSOLUTE_PATH",
        message = "Invalid directory path"
    ))]
    dir: String,
}

#[derive(Deserialize, Validate)]
pub struct OpenVPNDirConfig {
    #[validate(regex(
        path = "crate::utils::myregex::ABSOLUTE_PATH",
        message = "Invalid directory path"
    ))]
    dir: String,
    #[validate(regex(
        path = "crate::utils::myregex::LINUX_USER_GROUP",
        message = "Invalid owner"
    ))]
    owner: String,
    #[validate(regex(
        path = "crate::utils::myregex::LINUX_USER_GROUP",
        message = "Invalid group"
    ))]
    group: String,
    #[validate(regex(
        path = "crate::utils::myregex::FILE_PERMISSIONS",
        message = "Invalid directory permissions"
    ))]
    mode: String,
}

impl OpenVPNDirConfig {
    pub fn create_with_executor(&self, commands: &dyn CommandExecutor) -> Result<()> {
        self.validate()?;

        fs::create_dir_all(&self.dir)?;

        let owner_group = format!("{}:{}", self.owner, self.group);
        commands.run("chown", &[&owner_group, &self.dir])?;

        let mode = u32::from_str_radix(&self.mode, 8)
            .map_err(|_| FwcError::Internal("Invalid directory permissions"))?;
        let mut perms = fs::metadata(&self.dir)?.permissions();
        perms.set_mode(mode);
        fs::set_permissions(&self.dir, perms)?;

        Ok(())
    }
}

impl OpenVPNDir {
    pub fn remove_if_empty(&self) -> Result<()> {
        self.validate()?;

        match fs::remove_dir(&self.dir) {
            Ok(()) => Ok(()),
            Err(error)
                if error.kind() == ErrorKind::NotFound
                    || error.kind() == ErrorKind::DirectoryNotEmpty =>
            {
                Ok(())
            }
            Err(error) => Err(FwcError::IOError(error)),
        }
    }
}

#[cfg(test)]
#[path = "openvpn_dir_tests.rs"]
mod tests;
