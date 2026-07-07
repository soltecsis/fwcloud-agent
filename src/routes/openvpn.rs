/*
    Copyright 2022 SOLTECSIS SOLUCIONES TECNOLOGICAS, SLU
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

use actix_multipart::Multipart;
use actix_web::{delete, get, http::header, post, put, web, HttpResponse};
use log::debug;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

use crate::config::Config;
use crate::utils::files_list::FilesList;
use crate::utils::http_files::HttpFiles;
use crate::utils::openvpn_dir::{OpenVPNDir, OpenVPNDirConfig};

use crate::errors::{FwcError, Result};
use crate::workers::openvpn_status_collector::{
    OpenVPNStCollector, OpenVPNStatusSamplingConfig as PersistedOpenVPNStatusSamplingConfig,
};
use crate::workers::WorkersChannels;
use thread_id;

#[derive(Deserialize)]
struct OpenVPNStatusSamplingConfig {
    enabled: bool,
    status_files: Vec<String>,
}

#[derive(Serialize)]
struct OpenVPNStatusSamplingConfigResponse {
    accepted: bool,
    enabled: bool,
    status_files: Vec<String>,
}

impl OpenVPNStatusSamplingConfig {
    fn normalized_status_files(&self) -> Result<Vec<String>> {
        if self.enabled && self.status_files.is_empty() {
            return Err(FwcError::BadRequest(String::from(
                "OpenVPN status sampling requires at least one status file when enabled",
            )));
        }

        let mut status_files: Vec<String> = vec![];

        for status_file in self.status_files.iter() {
            let status_file = status_file.trim();

            if status_file.is_empty() {
                return Err(FwcError::BadRequest(String::from(
                    "OpenVPN status file path cannot be empty",
                )));
            }

            if !Path::new(status_file).is_absolute() {
                return Err(FwcError::BadRequest(format!(
                    "OpenVPN status file path must be absolute: {status_file}"
                )));
            }

            if !status_files.contains(&String::from(status_file)) {
                status_files.push(String::from(status_file));
            }
        }

        Ok(status_files)
    }
}

//use std::{thread, time};

#[post("/openvpn/files/upload")]
async fn files_upload(payload: Multipart, cfg: web::Data<Arc<Config>>) -> Result<HttpResponse> {
    // Mutex scope start.
    {
        debug!("Locking OpenVPN mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.openvpn);
        let _mutex_data = mutex.lock().await;
        debug!("OpenVPN mutex locked (thread id: {})", thread_id::get());

        // Only for debug purposes. It is useful for verify that the mutex makes its work.
        //thread::sleep(time::Duration::from_millis(10_000));

        HttpFiles::new(cfg.tmp_dir, true)
            .files_upload(payload)
            .await?;

        debug!("Releasing OpenVPN mutex (thread id: {})", thread_id::get());
    }

    Ok(HttpResponse::Ok().finish())
}

#[put("/openvpn/dirs/ensure")]
async fn dir_ensure(
    openvpn_dir: web::Json<OpenVPNDirConfig>,
    cfg: web::Data<Arc<Config>>,
) -> Result<HttpResponse> {
    // Mutex scope start.
    {
        debug!("Locking OpenVPN mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.openvpn);
        let _mutex_data = mutex.lock().await;
        debug!("OpenVPN mutex locked (thread id: {})", thread_id::get());

        openvpn_dir.create()?;

        debug!("Releasing OpenVPN mutex (thread id: {})", thread_id::get());
    } // Mutex scope end.

    Ok(HttpResponse::Ok().finish())
}

#[delete("/openvpn/dirs/remove-empty")]
async fn dir_remove_empty(
    openvpn_dir: web::Json<OpenVPNDir>,
    cfg: web::Data<Arc<Config>>,
) -> Result<HttpResponse> {
    // Mutex scope start.
    {
        debug!("Locking OpenVPN mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.openvpn);
        let _mutex_data = mutex.lock().await;
        debug!("OpenVPN mutex locked (thread id: {})", thread_id::get());

        openvpn_dir.remove_if_empty()?;

        debug!("Releasing OpenVPN mutex (thread id: {})", thread_id::get());
    } // Mutex scope end.

    Ok(HttpResponse::Ok().finish())
}

#[delete("/openvpn/files/remove")]
async fn files_remove(
    files_list: web::Json<FilesList>,
    cfg: web::Data<Arc<Config>>,
) -> Result<HttpResponse> {
    // Mutex scope start.
    {
        debug!("Locking OpenVPN mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.openvpn);
        let _mutex_data = mutex.lock().await;
        debug!("OpenVPN mutex locked (thread id: {})", thread_id::get());

        files_list.remove()?;

        debug!("Releasing OpenVPN mutex (thread id: {})", thread_id::get());
    } // Mutex scope end.

    Ok(HttpResponse::Ok().finish())
}

#[put("/openvpn/files/read")]
async fn files_read(
    files_list: web::Json<FilesList>,
    cfg: web::Data<Arc<Config>>,
) -> Result<HttpResponse> {
    debug!("Locking OpenVPN mutex (thread id: {})", thread_id::get());
    let mutex = Arc::clone(&cfg.mutex.openvpn);
    let _mutex_data = mutex.lock().await;
    debug!("OpenVPN mutex locked (thread id: {})", thread_id::get());

    if !files_list.dir_exists() {
        return Err(FwcError::DirNotFound);
    }

    if files_list.len() != 1 {
        return Err(FwcError::OnlyOneFileExpected);
    }

    let data = files_list.dump(0)?;
    let body = data.join("\n");

    debug!("Releasing OpenVPN mutex (thread id: {})", thread_id::get());

    let mut resp = HttpResponse::Ok().body(body);
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/plain"),
    );

    Ok(resp)
}

#[put("/openvpn/files/sha256")]
async fn files_sha256(
    mut files_list: web::Json<FilesList>,
    cfg: web::Data<Arc<Config>>,
) -> Result<HttpResponse> {
    let result: String;

    // Mutex scope start.
    {
        debug!("Locking OpenVPN mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.openvpn);
        let _mutex_data = mutex.lock().await;
        debug!("OpenVPN mutex locked (thread id: {})", thread_id::get());

        result = if files_list.dir_exists() {
            // If no files supplied then compute the sha256 has of all files into the directory.
            if files_list.len() == 0 {
                files_list.get_files_in_dir()?;
            }
            files_list.sha256(true)?
        } else {
            // If the dir doesn't exists return an empty result.
            String::from("file,sha256\n")
        };

        debug!("Releasing OpenVPN mutex (thread id: {})", thread_id::get());
    } // Mutex scope end.

    let mut resp = HttpResponse::Ok().body(result);
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/csv"),
    );

    Ok(resp)
}

/*
  curl -k -i -X PUT -H 'X-API-Key: **************************' \
    -H "Content-Type: application/json" \
    -d '{"dir":"/etc/openvpn", "files":["openvpn-status.log"]}' \
    https://localhost:33033/api/v1/openvpn/get/status
*/
#[put("/openvpn/get/status")]
async fn get_status(
    mut files_list: web::Json<FilesList>,
    cfg: web::Data<Arc<Config>>,
) -> Result<HttpResponse> {
    let mut result: Vec<String>;

    // Mutex scope start.
    {
        debug!("Locking OpenVPN mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.openvpn);
        let _mutex_data = mutex.lock().await;
        debug!("OpenVPN mutex locked (thread id: {})", thread_id::get());

        // Only one OpenVPN status file must be indicated in the request.
        if files_list.len() != 1 {
            return Err(FwcError::OnlyOneFileExpected);
        }

        let file_name =
            format!("{}/{}.data", files_list.dir(), files_list.name(0)).replace('/', "_");
        files_list.chdir(cfg.data_dir);
        files_list.rename(0, &file_name);

        result = files_list.head_remove(0, cfg.openvpn_status_request_max_lines)?;
        result.insert(
            0,
            String::from(
                "Timestamp,Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since",
            ),
        );

        debug!("Releasing OpenVPN mutex (thread id: {})", thread_id::get());
    } // Mutex scope end.

    let mut resp = HttpResponse::Ok().body(result.join("\n"));
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/csv"),
    );

    Ok(resp)
}

#[put("/openvpn/update/status")]
async fn update_status(workers_channels: web::Data<WorkersChannels>) -> Result<HttpResponse> {
    workers_channels.openvpn_st_collector.send(1)?;
    Ok(HttpResponse::Ok().finish())
}

#[put("/openvpn/status/sampling")]
async fn status_sampling_update(
    config: web::Json<OpenVPNStatusSamplingConfig>,
    cfg: web::Data<Arc<Config>>,
    collector: web::Data<OpenVPNStCollector>,
) -> Result<HttpResponse> {
    let status_files = if config.enabled {
        config.normalized_status_files()?
    } else {
        vec![]
    };

    {
        debug!("Locking OpenVPN mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.openvpn);
        let _mutex_data = mutex.lock().await;
        debug!("OpenVPN mutex locked (thread id: {})", thread_id::get());

        collector.replace_status_files(&status_files, cfg.tmp_dir, cfg.data_dir);
        PersistedOpenVPNStatusSamplingConfig {
            enabled: config.enabled,
            status_files: status_files.clone(),
        }
        .save(cfg.etc_dir)?;

        debug!("Releasing OpenVPN mutex (thread id: {})", thread_id::get());
    }

    Ok(
        HttpResponse::Ok().json(OpenVPNStatusSamplingConfigResponse {
            accepted: true,
            enabled: config.enabled,
            status_files,
        }),
    )
}

#[get("/openvpn/status/sampling")]
async fn status_sampling_show(cfg: web::Data<Arc<Config>>) -> Result<HttpResponse> {
    let persisted_config: PersistedOpenVPNStatusSamplingConfig;

    {
        debug!("Locking OpenVPN mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.openvpn);
        let _mutex_data = mutex.lock().await;
        debug!("OpenVPN mutex locked (thread id: {})", thread_id::get());

        persisted_config = PersistedOpenVPNStatusSamplingConfig::load_or_create(cfg.etc_dir)?;

        debug!("Releasing OpenVPN mutex (thread id: {})", thread_id::get());
    }

    Ok(
        HttpResponse::Ok().json(OpenVPNStatusSamplingConfigResponse {
            accepted: true,
            enabled: persisted_config.enabled,
            status_files: persisted_config.status_files,
        }),
    )
}

#[put("/openvpn/get/status/rt")]
async fn get_status_rt(files_list: web::Json<FilesList>) -> Result<HttpResponse> {
    // Only one OpenVPN status file must be indicated in the request.
    if files_list.len() != 1 {
        return Err(FwcError::OnlyOneFileExpected);
    }

    let result = files_list.dump(0)?;

    let mut resp = HttpResponse::Ok().body(result.join("\n"));
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/plain"),
    );

    Ok(resp)
}
