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

use actix_web::{get, web, HttpResponse, HttpRequest};
use actix_web_actors::ws;
use log::{debug, error};
use std::sync::{Arc, Mutex};
use validator::Validate;

use crate::config::Config;
use crate::errors::{FwcError, Result};
use crate::utils::cmd::{CmdOutputData, CmdWebSocket, run_cmd_rt_output};

#[derive(Validate)]
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
}

/*
    curl -v -k -i -X --http1.1 GET -H 'X-API-Key: **************************' \
        --header "Connection: Upgrade" \
        --header "Upgrade: websocket" \
        --header "Host: localhost:33033" \
        --header "Origin: https://localhost:33033" \
        --header "Sec-WebSocket-Key: ****************" \
        --header "Sec-WebSocket-Version: 13" \
        http://localhost:33033/api/v1/plugin/test/enable
 */
#[get("/plugin/{name}/{action}")]
async fn plugin(req: HttpRequest, stream: web::Payload, info: web::Path<(String, String)>, cfg: web::Data<Arc<Config>>) ->  Result<HttpResponse> {
    // URL path validation.
    let (name, action) = info.into_inner();
    let plugin = Plugin {
        name,
        action
    };
    plugin.validate()?;

    let output = CmdOutputData {
        lines: vec![],
        finished: false

    };
    let output = Arc::new(Mutex::new(output));
    let output_clone = Arc::clone(&output);
    
    let res = match ws::start(CmdWebSocket { output }, &req, stream) {
        Ok(data) => data,
        Err(e) => { 
            error!("{}",e); 
            return Err(FwcError::Internal(
                "Upgrading to WebSocket connection",
            ));
        }
    };

    run_cmd_rt_output(
        "sh",
        &[
            format!("{}/{}/{}.sh", cfg.plugins_dir, plugin.name, plugin.name),
            plugin.action,
        ],
        cfg,
        output_clone
    );

    Ok(res)
}
