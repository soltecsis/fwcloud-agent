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

use actix_web::{HttpResponse, post, web};
use actix_multipart::Multipart;
use log::debug;

use crate::config::Config;
use crate::utils::http_files::HttpFiles;

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

  HttpFiles::new(cfg.tmp_dir.clone()).process(payload).await?; 

  debug!("Unlocking OpenVPM mutex (thread id: {}) ...", thread_id::get());
  drop(mutex_data);
  debug!("OpenVPN mutex unlocked (thread id: {})!", thread_id::get());

  Ok(HttpResponse::Ok().finish())
}
