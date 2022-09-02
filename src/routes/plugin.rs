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
use uuid::Uuid;
use validator::Validate;

use crate::config::Config;
use crate::errors::{FwcError, Result};
use crate::utils::cmd::{run_cmd, run_cmd_ws};

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

    pub ws_id: Option<Uuid>, // Optional parameter
}

/*
  curl -k -i -X POST -H 'X-API-Key: **************************' \
    -H "Content-Type: application/json" \
    -d '{"name":"test", "action":"enable"}' \
    https://localhost:33033/api/v1/plugin
*/
#[post("/plugin")]
async fn plugin(plugin: web::Json<Plugin>, cfg: web::Data<Arc<Config>>) -> Result<HttpResponse> {
    plugin.validate()?; // Validate input.

    let cmd = "sh";
    let argv0 = format!("{}/{}/{}.sh", cfg.plugins_dir, plugin.name, plugin.name);
    let args = [argv0.as_str(), plugin.action.as_str()];
    let res: HttpResponse;

    // Mutex scope start.
    {
        debug!("Locking plugins mutex (thread id: {})", thread_id::get());
        let mutex = Arc::clone(&cfg.mutex.plugins);
        let _mutex_data = mutex.lock().unwrap();
        debug!("Plugins mutex locked (thread id: {})", thread_id::get());

        // If the websocket id is present in the Plugin Json data received in the request, then
        // stream the command input to the websocket. If not, the command output will be sent
        // as a whole when the command execution finishes.
        res = match plugin.ws_id {
            Some(id) => {
                let mut ws_map = cfg.ws_map.lock().unwrap();
                let ws_data = ws_map.get(&id).ok_or(FwcError::WebSocketIdNotFound)?;
                let res = run_cmd_ws(cmd, &args, ws_data)?;
                ws_map.remove(&id);
                res
            }
            None => run_cmd(cmd, &args)?,
        };
    } // Mutex scope end.

    Ok(res)
}
