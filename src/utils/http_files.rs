/*
    Copyright 2025 SOLTECSIS SOLUCIONES TECNOLOGICAS, SLU
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

use actix_multipart::{Field, Multipart};
use actix_web::{web, HttpResponse};
use chrono::Local;
use futures::{StreamExt, TryStreamExt};
use log::{debug, error};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::{io::Write, os::unix::prelude::PermissionsExt};
use uuid::Uuid;
use validator::Validate;

use crate::config::Config;
use crate::errors::{FwcError, Result};
use crate::utils::cmd::{run_cmd, run_cmd_ws};

use super::ws::WsData;

struct FileData {
    src_path: String,
    src_name: String,
    dst_path: String,
    dst_name: String,
    size: usize,
}

struct PolicyBackup {
    script_path: String,
    backup_path: PathBuf,
}

#[derive(Validate)]
pub struct HttpFiles {
    tmp_dir: &'static str,
    dst_dir: String,
    create_dst_dir: bool,
    files: Vec<FileData>,
    #[validate(regex(
        path = "crate::utils::myregex::FILE_PERMISSIONS",
        message = "Invalid file permissions"
    ))]
    perms: String,
    perms_u32: u32,
    max_files: u32,
    max_file_size: usize,
    expected_files: u32,
    n_files: u32,
    ws_id: Uuid,
    ws_id_buf: String,
    policy_backup_name: Option<String>,
    accept_policy_backup_name: bool,
}

impl HttpFiles {
    pub fn restore_named_policy(
        cfg: &Config,
        script_path: &str,
        backup_name: &str,
        ws_id: Option<Uuid>,
    ) -> Result<HttpResponse> {
        let backup =
            Self::named_policy_backup(&cfg.fwcloud_script_paths, script_path, backup_name)?;

        let mut files = Self::new(cfg.tmp_dir, false);
        if let Some(ws_id) = ws_id {
            if ws_id.is_nil() || !cfg.ws_map.lock().unwrap().contains_key(&ws_id) {
                return Err(FwcError::WebSocketIdNotFound);
            }
            files.ws_id = ws_id;
        }

        Self::restore_policy_script(&backup)?;
        let result = files.run_policy_command(script_path, "start", cfg, false);
        files.finish_websocket(cfg);
        result
    }

    fn named_policy_backup(
        script_paths: &[String],
        script_path: &str,
        backup_name: &str,
    ) -> Result<PolicyBackup> {
        if !script_paths.iter().any(|path| path == script_path) {
            return Err(FwcError::BadRequest(String::from(
                "Invalid policy script path",
            )));
        }

        let backup_path = Path::new(script_path).with_file_name(backup_name);
        let metadata = fs::symlink_metadata(&backup_path)?;
        if !metadata.file_type().is_file() {
            return Err(FwcError::BadRequest(String::from("Invalid policy backup")));
        }

        Ok(PolicyBackup {
            script_path: script_path.to_owned(),
            backup_path,
        })
    }

    pub fn new(tmp_dir: &'static str, create_dst_dir: bool) -> Self {
        HttpFiles {
            tmp_dir,
            dst_dir: String::from(""),
            create_dst_dir,
            files: Vec::new(),
            perms: String::from("640"),
            perms_u32: 420,
            max_files: 1000,
            max_file_size: 10_485_760, // Ten megabytes.
            expected_files: 0,
            n_files: 0,
            ws_id: Uuid::nil(),
            ws_id_buf: String::from(""),
            policy_backup_name: None,
            accept_policy_backup_name: false,
        }
    }

    pub async fn files_upload(&mut self, payload: Multipart) -> Result<()> {
        self.extract_multipart_data(payload).await?;
        self.check_data()?;
        self.move_tmp_files()?;

        Ok(())
    }

    pub async fn fwcloud_script(
        &mut self,
        payload: Multipart,
        cfg: &web::Data<Arc<Config>>,
    ) -> Result<HttpResponse> {
        self.expected_files = 1;
        self.accept_policy_backup_name = true;
        self.extract_multipart_data(payload).await?;
        self.check_data()?;

        if let Some(name) = &self.policy_backup_name {
            if !Self::valid_policy_backup_name(name) {
                return Err(FwcError::BadRequest(String::from(
                    "Invalid policy backup name",
                )));
            }
        }

        if self.files[0].dst_name != "fwcloud.sh" {
            return Err(FwcError::NotExpectedFileName);
        }

        self.move_tmp_files()?;

        let policy_backup = self.backup_policy_script(cfg)?;

        // Install de FWCloud script.
        if let Err(err) = self.run_policy_command(&self.files[0].dst_path, "install", cfg, false) {
            return self
                .recover_policy(policy_backup.as_ref(), cfg, "install", err)
                .await;
        }

        // Load policy.
        let script_path = cfg
            .fwcloud_script_paths
            .iter()
            .find(|file| Path::new(file).is_file())
            .ok_or(FwcError::Internal("Installed policy script not found"));
        let script_path = match script_path {
            Ok(script_path) => script_path,
            Err(err) => {
                return self
                    .recover_policy(policy_backup.as_ref(), cfg, "install", err)
                    .await
            }
        };

        let res: HttpResponse = match self.run_policy_command(script_path, "start", cfg, true) {
            Ok(start_res) => start_res,
            Err(err) => {
                return self
                    .recover_policy(policy_backup.as_ref(), cfg, "start", err)
                    .await
            }
        };

        if self.ws_id != Uuid::nil() {
            self.remove_websocket(cfg);
        }

        if self.policy_backup_name.is_some() {
            return Ok(HttpResponse::Ok().json(serde_json::json!({
                "backup_name": policy_backup.as_ref().map(|_| self.policy_backup_name.as_deref().unwrap()),
                "script_path": policy_backup.as_ref().map(|backup| &backup.script_path),
                "recovery_status": "not_needed",
            })));
        }

        Ok(res)
    }

    pub(crate) fn valid_policy_backup_name(name: &str) -> bool {
        name.len() == 25
            && name.starts_with("fwcloud-")
            && name.ends_with(".sh")
            && name.as_bytes()[8..22].iter().all(u8::is_ascii_digit)
    }

    fn backup_policy_script(&self, cfg: &Config) -> Result<Option<PolicyBackup>> {
        let backup_name = self
            .policy_backup_name
            .clone()
            .unwrap_or_else(|| format!("fwcloud-{}.sh", Local::now().format("%Y%m%d%H%M%S")));

        Self::backup_policy_script_from_paths(&cfg.fwcloud_script_paths, &backup_name)
    }

    fn backup_policy_script_from_paths(
        script_paths: &[String],
        backup_name: &str,
    ) -> Result<Option<PolicyBackup>> {
        for file in script_paths.iter() {
            let script_path = Path::new(file);
            if !script_path.is_file() {
                continue;
            }

            let backup_path = script_path.with_file_name(backup_name);
            if backup_path.exists() {
                return Err(FwcError::Internal("Policy backup file already exists"));
            }

            fs::rename(script_path, &backup_path)?;

            return Ok(Some(PolicyBackup {
                script_path: file.clone(),
                backup_path,
            }));
        }

        Ok(None)
    }

    async fn recover_policy(
        &self,
        policy_backup: Option<&PolicyBackup>,
        cfg: &Config,
        failed_action: &str,
        original_error: FwcError,
    ) -> Result<HttpResponse> {
        let policy_backup = match policy_backup {
            Some(policy_backup) => policy_backup,
            None => {
                self.push_websocket_message(
                    cfg,
                    "error",
                    format!(
                        "ERROR: Policy {failed_action} failed and no previous policy is available."
                    ),
                );
                self.finish_websocket(cfg);
                return self.policy_failure(original_error, "unavailable");
            }
        };

        self.push_websocket_message(
            cfg,
            "error",
            format!("ERROR: Policy {failed_action} failed. Restoring previous policy."),
        );

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let recovery_result: Result<()> = (|| {
            Self::restore_policy_script(policy_backup)?;
            self.push_websocket_message(
                cfg,
                "info",
                String::from("Previous policy restored. Loading policy."),
            );
            self.run_policy_command(&policy_backup.script_path, "start", cfg, false)?;

            Ok(())
        })();

        match recovery_result {
            Ok(()) => {
                self.push_websocket_message(cfg, "info", String::from("Previous policy loaded."));
                self.finish_websocket(cfg);
                self.policy_failure(original_error, "restored")
            }
            Err(err) => {
                error!("Policy recovery failed: {}", err);
                self.push_websocket_message(
                    cfg,
                    "error",
                    format!("ERROR: Policy recovery failed: {err}"),
                );
                self.finish_websocket(cfg);
                self.policy_failure(err, "failed")
            }
        }
    }

    fn policy_failure(&self, error: FwcError, recovery_status: &str) -> Result<HttpResponse> {
        if self.policy_backup_name.is_some() {
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "message": error.to_string(),
                "recovery_status": recovery_status,
            })));
        }
        Err(error)
    }

    fn restore_policy_script(policy_backup: &PolicyBackup) -> Result<()> {
        let script_path = Path::new(&policy_backup.script_path);
        if script_path.is_file() {
            fs::remove_file(script_path)?;
        }
        fs::rename(&policy_backup.backup_path, script_path)?;

        Ok(())
    }

    fn push_websocket_message(&self, cfg: &Config, message_type: &str, message: String) {
        if self.ws_id == Uuid::nil() {
            return;
        }

        debug!("Locking ws map mutex (thread id: {})", thread_id::get());
        let ws_data = cfg.ws_map.lock().unwrap().get(&self.ws_id).cloned();
        debug!("Releasing ws map mutex (thread id: {})", thread_id::get());

        if let Some(ws_data) = ws_data {
            debug!("Locking ws data mutex (thread id: {})", thread_id::get());
            ws_data.lock().unwrap().lines.push(
                serde_json::json!({
                    "fwcloud_agent_progress": true,
                    "type": message_type,
                    "message": message,
                })
                .to_string(),
            );
            debug!("Releasing ws data mutex (thread id: {})", thread_id::get());
        }
    }

    fn finish_websocket(&self, cfg: &Config) {
        if self.ws_id == Uuid::nil() {
            return;
        }

        debug!("Locking ws map mutex (thread id: {})", thread_id::get());
        let ws_data = cfg.ws_map.lock().unwrap().get(&self.ws_id).cloned();
        debug!("Releasing ws map mutex (thread id: {})", thread_id::get());

        if let Some(ws_data) = ws_data {
            debug!("Locking ws data mutex (thread id: {})", thread_id::get());
            ws_data.lock().unwrap().finished = true;
            debug!("Releasing ws data mutex (thread id: {})", thread_id::get());
        }

        self.remove_websocket(cfg);
    }

    fn remove_websocket(&self, cfg: &Config) {
        debug!("Locking ws map mutex (thread id: {})", thread_id::get());
        cfg.ws_map.lock().unwrap().remove(&self.ws_id);
        debug!("Releasing ws map mutex (thread id: {})", thread_id::get());
    }

    fn run_policy_command(
        &self,
        script_path: &str,
        action: &str,
        cfg: &Config,
        finish_ws: bool,
    ) -> Result<HttpResponse> {
        if self.ws_id == Uuid::nil() {
            return run_cmd("sh", &[script_path, action]);
        }

        let ws_data: Arc<Mutex<WsData>>;
        {
            debug!("Locking ws map mutex (thread id: {})", thread_id::get());
            let ws_map = cfg.ws_map.lock().unwrap();
            ws_data = ws_map
                .get(&self.ws_id)
                .ok_or(FwcError::WebSocketIdNotFound)?
                .clone();
            debug!("Releasing ws map mutex (thread id: {})", thread_id::get());
        }

        run_cmd_ws("sh", &[script_path, action], &ws_data, finish_ws)
    }

    async fn extract_multipart_data(&mut self, mut payload: Multipart) -> Result<()> {
        // iterate over multipart stream
        while let Ok(Some(mut field)) = payload.try_next().await {
            let content_type = field.content_disposition();

            let filename = sanitize_filename::sanitize(
                content_type.expect("filename").get_filename().unwrap_or(""),
            );
            if filename.is_empty() {
                let name = content_type
                    .expect("filename")
                    .get_name()
                    .unwrap_or("")
                    .to_string();
                self.extract_field_data(field, name).await?;
                continue;
            }

            // Parameter for destination dir (dst_dir) must go before any file contents in the
            // multipart stream.
            if self.dst_dir.is_empty() {
                return Err(FwcError::DstDirFirst);
            }

            // Apply controls over the amount of files before getting the next file.
            self.n_files += 1;
            if self.max_files > 0 && self.n_files > self.max_files {
                return Err(FwcError::TooManyFiles);
            }
            if self.expected_files > 0 && self.n_files > self.expected_files {
                return Err(FwcError::MoreFilesThanExpected);
            }

            let random_file_name = Uuid::new_v4();
            let mut file_data = FileData {
                src_path: format!("{}/{}.tmp", self.tmp_dir, random_file_name),
                src_name: format!("{random_file_name}.tmp"),
                dst_path: format!("{}/{}", self.dst_dir, filename),
                dst_name: filename,
                size: 0,
            };

            // File::create is blocking operation, use threadpool
            let file_path = file_data.src_path.clone();
            let mut f = web::block(|| std::fs::File::create(file_path))
                .await?
                .unwrap();

            // Field in turn is stream of *Bytes* object
            while let Some(chunk) = field.next().await {
                let data = chunk.unwrap();

                // File size control.
                file_data.size += data.len();
                if self.max_file_size > 0 && file_data.size > self.max_file_size {
                    return Err(FwcError::TooBigFile);
                }

                // filesystem operations are blocking, we have to use threadpool
                f = web::block(move || f.write_all(&data).map(|_| f))
                    .await?
                    .unwrap();
            }

            self.files.push(file_data);
        }

        Ok(())
    }

    async fn extract_field_data(&mut self, mut field: Field, name: String) -> Result<()> {
        // We only accept these NO file parameter in the multipart stream and it must be the destination directory.
        let buf: &mut String = if name == "dst_dir" {
            &mut self.dst_dir
        } else if name == "perms" {
            self.perms.clear();
            &mut self.perms
        } else if name == "ws_id" {
            &mut self.ws_id_buf
        } else if name == "backup_name" && self.accept_policy_backup_name {
            self.policy_backup_name.get_or_insert_with(String::new)
        } else {
            return Err(FwcError::NotAllowedParameter);
        };

        // Field in turn is stream of *Bytes* object
        while let Some(chunk) = field.next().await {
            let data = chunk.unwrap();
            for byte in data {
                buf.push(byte as char);
            }
        }

        // Verify that destination directory exists.
        // The parameter dst_dir must go before any file into the multipart stream.
        // If the destination directory doesn't exists we will response with error before processing the files
        // data.
        if name == "dst_dir" && !Path::new(&self.dst_dir).is_dir() {
            // If destination directory doesn't exists.
            if self.create_dst_dir {
                // Create the destination directory if it doesn't exists.
                fs::create_dir_all(&self.dst_dir)?;
            } else {
                return Err(FwcError::DirNotFound);
            }
        }

        // If we receive a WebSocket id verify that it is a valid one.
        if name == "ws_id" {
            match Uuid::parse_str(&self.ws_id_buf) {
                Ok(id) => self.ws_id = id,
                Err(_e) => return Err(FwcError::WebSocketIdBad),
            }
        }

        Ok(())
    }

    fn move_tmp_files(&mut self) -> Result<()> {
        for file_data in self.files.iter() {
            fs::copy(&file_data.src_path, &file_data.dst_path)?;
            fs::remove_file(&file_data.src_path)?;

            let mut perms = fs::metadata(&file_data.dst_path)?.permissions();
            perms.set_mode(self.perms_u32);
            fs::set_permissions(&file_data.dst_path, perms)?;
        }

        Ok(())
    }

    fn check_data(&mut self) -> Result<()> {
        // Validate data using the Validator crate and the marco annotations over struct fields.
        self.validate()?;

        // Destination directory parameter is mandatory.
        if self.dst_dir.is_empty() {
            return Err(FwcError::Internal(
                "Destination directory parameter not found in multipart/form-data stream",
            ));
        }

        if self.files.is_empty() {
            return Err(FwcError::AtLeastOneFile);
        }

        if self.n_files < self.expected_files {
            return Err(FwcError::LessFilesThanExpected);
        }

        self.perms_to_u32();

        Ok(())
    }

    fn perms_to_u32(&mut self) {
        let d0 = (self.perms.as_bytes()[0] as u32) - 48;
        let d1 = (self.perms.as_bytes()[1] as u32) - 48;
        let d2 = (self.perms.as_bytes()[2] as u32) - 48;

        self.perms_u32 = (d0 * 64) + (d1 * 8) + d2;
    }
}

// Make sure that temporary files are removed after the HttpFiles object instance goes out of scope.
impl Drop for HttpFiles {
    fn drop(&mut self) {
        for file_data in self.files.iter() {
            let src = format!("{}/{}", self.tmp_dir, file_data.src_name);

            // Ignore the Result enum returned by the remove_file method.
            let _ = fs::remove_file(&src);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn create_tmp_dir() -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("fwcloud-agent-http-files-{}", Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();

        path
    }

    #[test]
    fn unix_permissions_to_u32() {
        let mut item = HttpFiles::new("", false);

        item.perms = String::from("777");
        item.perms_to_u32();
        assert_eq!(item.perms_u32, 511);

        item.perms = String::from("644");
        item.perms_to_u32();
        assert_eq!(item.perms_u32, 420);

        item.perms = String::from("650");
        item.perms_to_u32();
        assert_eq!(item.perms_u32, 424);
    }

    #[test]
    fn policy_backup_name_requires_timestamped_basename() {
        assert!(HttpFiles::valid_policy_backup_name(
            "fwcloud-20261116153045.sh"
        ));
        assert!(!HttpFiles::valid_policy_backup_name(
            "../fwcloud-20261116153045.sh"
        ));
        assert!(!HttpFiles::valid_policy_backup_name(
            "fwcloud-2026111615304x.sh"
        ));
        assert!(!HttpFiles::valid_policy_backup_name(""));
    }

    #[test]
    fn coordinated_installation_failure_remains_an_error_response() {
        let mut files = HttpFiles::new("", false);
        files.policy_backup_name = Some(String::from("fwcloud-20261116153045.sh"));
        let response = files
            .policy_failure(FwcError::CmdExitStatusNotZero, "restored")
            .unwrap();
        assert_eq!(
            response.status(),
            actix_web::http::StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn policy_backup_renames_existing_script() {
        let tmp_dir = create_tmp_dir();
        let script_path = tmp_dir.join("fwcloud.sh");
        let backup_path = tmp_dir.join("fwcloud-20261116153045.sh");
        fs::write(&script_path, "previous policy").unwrap();

        let backup = HttpFiles::backup_policy_script_from_paths(
            &[script_path.to_string_lossy().to_string()],
            "fwcloud-20261116153045.sh",
        )
        .unwrap()
        .unwrap();

        assert_eq!(backup.script_path, script_path.to_string_lossy());
        assert_eq!(backup.backup_path, backup_path);
        assert!(!script_path.exists());
        assert_eq!(fs::read_to_string(&backup_path).unwrap(), "previous policy");

        fs::remove_dir_all(tmp_dir).unwrap();
    }

    #[test]
    fn policy_backup_skips_first_installation() {
        let tmp_dir = create_tmp_dir();
        let script_path = tmp_dir.join("fwcloud.sh");

        let backup = HttpFiles::backup_policy_script_from_paths(
            &[script_path.to_string_lossy().to_string()],
            "fwcloud-20261116153045.sh",
        )
        .unwrap();

        assert!(backup.is_none());

        fs::remove_dir_all(tmp_dir).unwrap();
    }

    #[test]
    fn policy_backup_does_not_overwrite_existing_backup() {
        let tmp_dir = create_tmp_dir();
        let script_path = tmp_dir.join("fwcloud.sh");
        let backup_path = tmp_dir.join("fwcloud-20261116153045.sh");
        fs::write(&script_path, "previous policy").unwrap();
        fs::write(&backup_path, "existing backup").unwrap();

        let result = HttpFiles::backup_policy_script_from_paths(
            &[script_path.to_string_lossy().to_string()],
            "fwcloud-20261116153045.sh",
        );

        assert!(matches!(
            result,
            Err(FwcError::Internal("Policy backup file already exists"))
        ));
        assert_eq!(fs::read_to_string(&script_path).unwrap(), "previous policy");
        assert_eq!(fs::read_to_string(&backup_path).unwrap(), "existing backup");

        fs::remove_dir_all(tmp_dir).unwrap();
    }

    #[test]
    fn policy_restore_replaces_failed_script() {
        let tmp_dir = create_tmp_dir();
        let script_path = tmp_dir.join("fwcloud.sh");
        let backup_path = tmp_dir.join("fwcloud-20261116153045.sh");
        fs::write(&script_path, "failed policy").unwrap();
        fs::write(&backup_path, "previous policy").unwrap();
        let policy_backup = PolicyBackup {
            script_path: script_path.to_string_lossy().to_string(),
            backup_path: backup_path.clone(),
        };

        HttpFiles::restore_policy_script(&policy_backup).unwrap();

        assert!(!backup_path.exists());
        assert_eq!(fs::read_to_string(&script_path).unwrap(), "previous policy");

        fs::remove_dir_all(tmp_dir).unwrap();
    }

    #[test]
    fn named_policy_backup_requires_configured_path_and_regular_file() {
        let tmp_dir = create_tmp_dir();
        let script_path = tmp_dir.join("fwcloud.sh");
        let script = script_path.to_string_lossy().to_string();
        let backup_name = "fwcloud-20261116153045.sh";
        let backup_path = tmp_dir.join(backup_name);
        fs::write(&backup_path, "previous policy").unwrap();

        assert!(HttpFiles::named_policy_backup(&[], &script, backup_name).is_err());
        assert!(HttpFiles::named_policy_backup(&[script.clone()], &script, backup_name).is_ok());
        fs::remove_file(&backup_path).unwrap();
        assert!(HttpFiles::named_policy_backup(&[script.clone()], &script, backup_name).is_err());
        std::os::unix::fs::symlink(&script_path, &backup_path).unwrap();
        assert!(HttpFiles::named_policy_backup(&[script.clone()], &script, backup_name).is_err());

        fs::remove_dir_all(tmp_dir).unwrap();
    }
}
