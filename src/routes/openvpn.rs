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
use actix_web::{delete, http::header, post, put, web, HttpResponse};
use log::debug;
use std::sync::Arc;

use crate::config::Config;
use crate::utils::files_list::FilesList;
use crate::utils::http_files::HttpFiles;

use crate::errors::{FwcError, Result};
use crate::workers::WorkersChannels;
use thread_id;

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
    }

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
    } // Mutex scope end.

    Ok(HttpResponse::Ok().finish())
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
