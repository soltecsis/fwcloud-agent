/*
    Copyright 2023 SOLTECSIS SOLUCIONES TECNOLOGICAS, SLU
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
use futures::{StreamExt, TryStreamExt};
use log::debug;
use std::fs;
use std::path::Path;
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
}

impl HttpFiles {
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
        self.extract_multipart_data(payload).await?;
        self.check_data()?;

        if self.files[0].dst_name != "fwcloud.sh" {
            return Err(FwcError::NotExpectedFileName);
        }

        self.move_tmp_files()?;

        // Install de FWCloud script.
        let mut res: HttpResponse;
        if self.ws_id != Uuid::nil() {
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
            res = run_cmd_ws(
                "sh",
                &[&self.files[0].dst_path[..], "install"],
                &ws_data,
                false,
            )?;
        } else {
            res = run_cmd("sh", &[&self.files[0].dst_path[..], "install"])?;
        }

        // Load policy.
        for file in cfg.fwcloud_script_paths.iter() {
            if Path::new(file).is_file() {
                if self.ws_id != Uuid::nil() {
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
                    res = run_cmd_ws("sh", &[&file[..], "start"], &ws_data, true)?;
                    {
                        debug!("Locking ws map mutex (thread id: {})", thread_id::get());
                        let mut ws_map = cfg.ws_map.lock().unwrap();
                        ws_map.remove(&self.ws_id);
                        debug!("Releasing ws map mutex (thread id: {})", thread_id::get());
                    }
                } else {
                    res = run_cmd("sh", &[&file[..], "start"])?;
                }
                break;
            }
        }

        Ok(res)
    }

    async fn extract_multipart_data(&mut self, mut payload: Multipart) -> Result<()> {
        // iterate over multipart stream
        while let Ok(Some(mut field)) = payload.try_next().await {
            let content_type = field.content_disposition();

            let filename = sanitize_filename::sanitize(content_type.get_filename().unwrap_or(""));
            if filename.is_empty() {
                let name = content_type.get_name().unwrap_or("").to_string();
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
        let buf: &mut String;
        if name == "dst_dir" {
            buf = &mut self.dst_dir;
        } else if name == "perms" {
            self.perms.clear();
            buf = &mut self.perms;
        } else if name == "ws_id" {
            buf = &mut self.ws_id_buf;
        } else {
            return Err(FwcError::NotAllowedParameter);
        }

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
}
