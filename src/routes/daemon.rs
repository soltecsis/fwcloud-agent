/*
    Copyright 2024 SOLTECSIS SOLUCIONES TECNOLOGICAS, SLU
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
use actix_web::{post, web, HttpResponse};
use log::debug;
use std::sync::Arc;

use crate::config::Config;
use crate::errors::Result;
use crate::utils::http_files::HttpFiles;

#[post("/daemon/config/upload")]
async fn config_upload(payload: Multipart, cfg: web::Data<Arc<Config>>) -> Result<HttpResponse> {
    // Mutex scope start.
    {
        debug!("Locking daemon mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.daemon);
        let _mutex_data = mutex.lock().await;
        debug!("Daemon mutex locked (thread id: {})", thread_id::get());

        HttpFiles::new(cfg.tmp_dir, true)
            .files_upload(payload)
            .await?;

        debug!("Releasing daemon mutex (thread id: {})", thread_id::get());
    }

    Ok(HttpResponse::Ok().finish())
}
