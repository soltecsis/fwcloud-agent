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
use actix_web::{post, web, HttpResponse};
use log::debug;
use std::sync::Arc;

use crate::config::Config;
use crate::utils::http_files::HttpFiles;

use crate::errors::Result;

#[post("/fwcloud_script/upload")]
async fn upload_and_run(payload: Multipart, cfg: web::Data<Arc<Config>>) -> Result<HttpResponse> {
    debug!(
        "Locking FWCloud Script mutex (thread id: {}) ...",
        thread_id::get()
    );
    let mutex = Arc::clone(&cfg.mutex.fwcloud_script);
    let mutex_data = mutex.lock().await;
    debug!(
        "FWCloud Script mutex locked (thread id: {})!",
        thread_id::get()
    );

    let res = HttpFiles::new(cfg.tmp_dir, false)
        .fwcloud_script(payload, &cfg.fwcloud_script_paths)
        .await?;

    debug!(
        "Unlocking FWCloud Script mutex (thread id: {}) ...",
        thread_id::get()
    );
    drop(mutex_data);
    debug!(
        "FWCloud Script mutex unlocked (thread id: {})!",
        thread_id::get()
    );

    Ok(res)
}
