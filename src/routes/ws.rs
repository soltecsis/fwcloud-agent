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
use std::{thread, sync::Arc, time::Duration};
use uuid::Uuid;

use crate::config::Config;
use crate::errors::{Result, FwcError};
use crate::utils::ws::FwcAgentWs;

/*
    curl -v -k -i -X --http1.1 GET -H 'X-API-Key: **************************' \
        --header "Connection: Upgrade" \
        --header "Upgrade: websocket" \
        --header "Host: localhost:33033" \
        --header "Origin: https://localhost:33033" \
        --header "Sec-WebSocket-Key: ****************" \
        --header "Sec-WebSocket-Version: 13" \
        https://localhost:33033/api/v1/ws
*/
/* 
    IMPORTANT: Use HTTP/1.1, if not, wss (WebSocket Secure) communication
    doesn't go. For this reason we must use the option --http1.1 in the
    example curl command.
 */
#[get("/ws")]
async fn websocket(req: HttpRequest, stream: web::Payload, cfg: web::Data<Arc<Config>>) -> Result<HttpResponse> {
    let new_ws = FwcAgentWs::new(Arc::clone(&cfg.ws_map));
    Ok(ws::start(new_ws, &req, stream)?)
}


/*
    curl -v -k -i -X GET -H 'X-API-Key: **************************' \
        https://localhost:33033/api/v1/ws/test/c29d8913-7599-4638-9c8c-266c5d97d3e2/30
*/
#[get("/ws/test/{id}/{seconds}")]
async fn websocket_test(info: web::Path<(Uuid, u16)>, cfg: web::Data<Arc<Config>>) -> Result<HttpResponse> {
    let (id, mut seconds) = info.into_inner();

    let ws_map = cfg.ws_map.lock().unwrap(); 
    let ws_data = ws_map.get(&id).ok_or(FwcError::WebSocketIdNotFound)?;
        
    while seconds > 0 {
        {
            ws_data.lock().unwrap().lines.push(format!("{} seconds left\n",seconds));
        }
        seconds -= 1;
        thread::sleep(Duration::from_secs(1));
    }
    {
        ws_data.lock().unwrap().finished = true;
    }

    Ok(HttpResponse::Ok().finish())
}
