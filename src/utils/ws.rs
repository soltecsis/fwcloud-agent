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

use actix::{Actor, AsyncContext, SpawnHandle, StreamHandler};
use actix_web_actors::ws::{self, CloseReason};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};
use uuid::Uuid;
use log::debug;

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const POLLING_INTERVAL: Duration = Duration::from_millis(100);

pub struct WsData {
    pub created_at: SystemTime,
    pub lines: Vec<String>,
    pub finished: bool,
}

pub struct FwcAgentWs {
    id: Uuid,
    heart_beat_handler: Option<SpawnHandle>,
    pub data: Arc<Mutex<WsData>>,
}

impl FwcAgentWs {
    pub fn new(
        map: Arc<std::sync::Mutex<HashMap<Uuid, Arc<std::sync::Mutex<WsData>>>>>,
    ) -> FwcAgentWs {
        let new_ws = FwcAgentWs {
            id: Uuid::new_v4(),
            heart_beat_handler: None,
            data: Arc::new(Mutex::new(WsData {
                created_at: SystemTime::now(),
                lines: vec![],
                finished: false,
            })),
        };

        let data_clone = Arc::clone(&new_ws.data);
        map.lock().unwrap().insert(new_ws.get_id(), data_clone);

        new_ws
    }

    pub fn get_id(&self) -> Uuid {
        self.id
    }

    fn send_lines(&self, ctx: &mut ws::WebsocketContext<Self>) {
        let handle = self.heart_beat_handler.unwrap();
        let id = self.get_id();

        ctx.run_interval(POLLING_INTERVAL, move |act, ctx| {
            let mut data = act.data.lock().unwrap();
            while !data.lines.is_empty() {
                debug!("Sending to websocket (id: {}): {})", id, data.lines[0]);
                ctx.text(data.lines[0].as_str());
                data.lines.remove(0);
            }

            if data.finished {
                debug!("Closing websocket (id: {})", id);
                ctx.close(Some(CloseReason {
                    code: ws::CloseCode::Normal,
                    description: Some(String::from("Closing websocket connection")),
                }));
                ctx.cancel_future(ctx.handle());

                // IMPORTANT: Cancel the future for the heart beat task. If not, the websocket will not be closed until
                // the next run of this task. This causes a delay in all the communications. For example,
                // if we have the HEARTBEAT_INTERVAL as 5 seconds, the FWCloud-UI can wait a maximum of
                // 5 seconds after the request has finished.
                ctx.cancel_future(handle);
            }
        });
    }

    fn heart_beat(&mut self, ctx: &mut ws::WebsocketContext<Self>) {
        self.heart_beat_handler = Some(ctx.run_interval(HEARTBEAT_INTERVAL, move |act, ctx| {
            if act.data.lock().unwrap().finished {
                ctx.cancel_future(ctx.handle());
            } else {
                ctx.ping(b"PING\n");
            }
        }));
    }
}

impl Actor for FwcAgentWs {
    type Context = ws::WebsocketContext<Self>;

    // Start the heartbeat process for this connection
    fn started(&mut self, ctx: &mut Self::Context) {
        // The first message will be the id of the websocket connection.
        ctx.text(format!("{}", self.id));

        self.heart_beat(ctx);
        self.send_lines(ctx);
    }
}

/// Handler for ws::Message message
impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for FwcAgentWs {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        match msg {
            Ok(ws::Message::Ping(msg)) => ctx.pong(&msg),
            //Ok(ws::Message::Text(text)) => ctx.text(text),
            //Ok(ws::Message::Binary(bin)) => ctx.binary(bin),
            Ok(ws::Message::Close(reason)) => {
                ctx.close(reason);
                ctx.cancel_future(ctx.handle());
            }
            _ => (),
        }
    }
}
