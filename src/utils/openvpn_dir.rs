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
use crate::utils::cmd::run_cmd;

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
    pub fn create(&self) -> Result<()> {
        self.validate()?;

        fs::create_dir_all(&self.dir)?;

        let owner_group = format!("{}:{}", self.owner, self.group);
        run_cmd("chown", &[&owner_group, &self.dir])?;

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
mod tests {
    use super::*;
    use std::fs::File;
    use std::path::Path;
    use uuid::Uuid;

    fn tmp_dir() -> String {
        format!("/tmp/fwcloud-agent-openvpn-dir-{}", Uuid::new_v4())
    }

    fn dir_config(dir: String, group: &str) -> OpenVPNDirConfig {
        OpenVPNDirConfig {
            dir,
            owner: String::from("root"),
            group: String::from(group),
            mode: String::from("750"),
        }
    }

    #[test]
    fn validate_accepts_linux_group_names() {
        let config = dir_config(String::from("/etc/openvpn/ccd"), "nogroup");
        assert!(config.validate().is_ok());

        let config = dir_config(String::from("/etc/openvpn/ccd"), "domain_users$");
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_rejects_group_names_not_matching_api_schema() {
        let config = dir_config(String::from("/etc/openvpn/ccd"), "domain.users");
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_relative_paths() {
        let config = dir_config(String::from("etc/openvpn/ccd"), "nogroup");
        assert!(config.validate().is_err());
    }

    #[test]
    fn remove_if_empty_removes_empty_directory() -> Result<()> {
        let dir = tmp_dir();
        fs::create_dir(&dir)?;

        let openvpn_dir = OpenVPNDir { dir: dir.clone() };
        openvpn_dir.remove_if_empty()?;

        assert!(!Path::new(&dir).exists());

        Ok(())
    }

    #[test]
    fn remove_if_empty_ignores_non_empty_directory() -> Result<()> {
        let dir = tmp_dir();
        fs::create_dir(&dir)?;
        File::create(format!("{dir}/client"))?;

        let openvpn_dir = OpenVPNDir { dir: dir.clone() };
        openvpn_dir.remove_if_empty()?;

        assert!(Path::new(&dir).exists());

        fs::remove_file(format!("{dir}/client"))?;
        fs::remove_dir(dir)?;

        Ok(())
    }

    #[test]
    fn remove_if_empty_ignores_missing_directory() -> Result<()> {
        let dir = tmp_dir();

        let openvpn_dir = OpenVPNDir { dir };
        openvpn_dir.remove_if_empty()?;

        Ok(())
    }
}
