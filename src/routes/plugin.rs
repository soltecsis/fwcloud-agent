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

use std::sync::Arc;

use actix_web::{post, web, HttpResponse};
use log::debug;
use serde::{Deserialize, Serialize};
use validator::Validate;
use uuid::Uuid;

use crate::config::Config;
use crate::utils::cmd::{run_cmd, run_cmd_ws};
use crate::errors::{Result, FwcError};

//use std::{thread, time};

#[derive(Deserialize, Serialize, Validate)]
pub struct Plugin {
    #[validate(regex(
        path = "crate::utils::myregex::PLUGINS_NAMES",
        message = "Invalid plugin name"
    ))]
    pub name: String,

    #[validate(regex(
        path = "crate::utils::myregex::PLUGINS_ACTIONS",
        message = "Invalid plugin action"
    ))]
    pub action: String,

    pub ws_id: Option<Uuid>
}

/*
  curl -k -i -X POST -H 'X-API-Key: **************************' \
    -H "Content-Type: application/json" \
    -d '{"name":"test", "action":"enable"}' \
    https://localhost:33033/api/v1/plugin
*/
#[post("/plugin")]
async fn plugin(plugin: web::Json<Plugin>, cfg: web::Data<Arc<Config>>) -> Result<HttpResponse> {
    // Validate input.
    plugin.validate()?;

    debug!(
        "Locking FWCloud plugins mutex (thread id: {}) ...",
        thread_id::get()
    );
    let mutex = Arc::clone(&cfg.mutex.plugins);
    let mutex_data = mutex.lock().await;
    debug!(
        "FWCloud plugins mutex locked (thread id: {})!",
        thread_id::get()
    );

    // Only for debug purposes. It is useful for verify that the mutex makes its work.
    //thread::sleep(time::Duration::from_millis(10_000));
    let cmd = "sh";
    let argv0 = format!("{}/{}/{}.sh", cfg.plugins_dir, plugin.name, plugin.name);
    let args = [
        argv0.as_str(),
        plugin.action.as_str(),
    ];

    let res = match plugin.ws_id {
        Some(id) => {
            let ws_map = cfg.ws_map.lock().unwrap(); 
            let ws_data = ws_map.get(&id).ok_or(FwcError::WebSocketIdNotFound)?;
            run_cmd_ws(cmd, &args, ws_data)?
        },
        None => run_cmd(cmd, &args)?
    };

    debug!(
        "Unlocking FWCloud plugins mutex (thread id: {}) ...",
        thread_id::get()
    );
    drop(mutex_data);
    debug!(
        "FWCloud plugins mutex unlocked (thread id: {})!",
        thread_id::get()
    );

    Ok(res)
}