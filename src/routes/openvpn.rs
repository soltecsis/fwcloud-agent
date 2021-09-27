/*
    Copyright 2021 SOLTECSIS SOLUCIONES TECNOLOGICAS, SLU
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

use std::sync::Arc;

use actix_web::http::header;
use actix_web::{HttpResponse, post, delete, put, web};
use actix_multipart::Multipart;
use log::debug;

use crate::config::Config;
use crate::utils::http_files::HttpFiles;
use crate::utils::files_list::FilesList;

use crate::errors::Result;
//use std::{thread, time};
use thread_id;


#[post("/files/upload")]
pub async fn files_upload(payload: Multipart, cfg: web::Data<Arc<Config>>) -> Result<HttpResponse> {
  debug!("Locking OpenVPM mutex (thread id: {}) ...", thread_id::get());
  let mutex = Arc::clone(&cfg.mutex.openvpn);
  let mutex_data = mutex.lock().unwrap();
  debug!("OpenVPN mutex locked (thread id: {})!", thread_id::get());

  // Only for debug purposes. It is useful for verify that the mutex makes its work.
  //thread::sleep(time::Duration::from_millis(10_000));

  HttpFiles::new(cfg.tmp_dir.clone()).files_upload(payload).await?; 

  debug!("Unlocking OpenVPM mutex (thread id: {}) ...", thread_id::get());
  drop(mutex_data);
  debug!("OpenVPN mutex unlocked (thread id: {})!", thread_id::get());

  Ok(HttpResponse::Ok().finish())
}


#[delete("/files/remove")]
pub async fn files_remove(files_list: web::Json<FilesList>, cfg: web::Data<Arc<Config>>) -> Result<HttpResponse> {
  debug!("Locking OpenVPM mutex (thread id: {}) ...", thread_id::get());
  let mutex = Arc::clone(&cfg.mutex.openvpn);
  let mutex_data = mutex.lock().unwrap();
  debug!("OpenVPN mutex locked (thread id: {})!", thread_id::get());

  files_list.remove()?;

  debug!("Unlocking OpenVPM mutex (thread id: {}) ...", thread_id::get());
  drop(mutex_data);
  debug!("OpenVPN mutex unlocked (thread id: {})!", thread_id::get());

  Ok(HttpResponse::Ok().finish())
}


#[put("/files/sha256")]
pub async fn files_sha256(mut files_list: web::Json<FilesList>, cfg: web::Data<Arc<Config>>) -> Result<HttpResponse> {
  debug!("Locking OpenVPM mutex (thread id: {}) ...", thread_id::get());
  let mutex = Arc::clone(&cfg.mutex.openvpn);
  let mutex_data = mutex.lock().unwrap();
  debug!("OpenVPN mutex locked (thread id: {})!", thread_id::get());

  // In no files supplied then compute the sha256 has of all files into the directory.
  if files_list.len() == 0 {
    files_list.get_files_in_dir()?;
  }
  let result = files_list.sha256()?;

  debug!("Unlocking OpenVPM mutex (thread id: {}) ...", thread_id::get());
  drop(mutex_data);
  debug!("OpenVPN mutex unlocked (thread id: {})!", thread_id::get());

  let mut resp = HttpResponse::Ok().body(result);
  resp.headers_mut().insert(
    header ::CONTENT_TYPE,
    header::HeaderValue::from_static("text/csv"),
  );

  Ok(resp)
}
