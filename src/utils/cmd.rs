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


use actix_web::{http::header, HttpResponse, web};
use actix::{Actor, StreamHandler, AsyncContext, SpawnHandle};
use actix_web_actors::ws::{self, CloseReason};
use subprocess::{Exec, Redirection};
use std::{time::Duration, sync::{Arc, Mutex}, thread};
use log::{error, debug};

use crate::errors::FwcError;
use crate::config::Config;

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const POLLING_INTERVAL: Duration = Duration::from_millis(100);

pub struct CmdOutputData {
    pub lines: Vec<String>,
    pub finished: bool
}

pub struct CmdWebSocket {
    pub output: Arc<Mutex<CmdOutputData>>
}

impl CmdWebSocket {
    fn send_lines(&self, ctx: &mut ws::WebsocketContext<Self>) {
        ctx.run_interval(POLLING_INTERVAL, move |act, ctx| {
            {
                let mut output = act.output.lock().unwrap();
                while ! output.lines.is_empty() {
                    ctx.text(output.lines[0].as_str());
                    output.lines.remove(0);
                }

                if output.finished {
                    ctx.close(Some(CloseReason {
                        code: ws::CloseCode::Normal,
                        description: Some(String::from("Closing websocket connection"))
                    }));
                    ctx.cancel_future(ctx.handle());
                }
            }
        });
    }


    fn heart_beat(&self, ctx: &mut ws::WebsocketContext<Self>) {
        ctx.run_interval(HEARTBEAT_INTERVAL, move |act, ctx| {
            {
                let output = act.output.lock().unwrap();
                if output.finished { 
                    ctx.cancel_future(ctx.handle());
                }
            }

            ctx.ping(b"PING\n");
        });
    }
}


impl Actor for CmdWebSocket {
    type Context = ws::WebsocketContext<Self>;

    // Start the heartbeat process for this connection
    fn started(&mut self, ctx: &mut Self::Context) {
        self.heart_beat(ctx);
        self.send_lines(ctx);
    }
}

/// Handler for ws::Message message
impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for CmdWebSocket {
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


pub fn run_cmd(cmd: &str, args: &[&str]) -> Result<HttpResponse, FwcError> {
    let output = Exec::cmd(cmd)
        .args(args)
        .stdout(Redirection::Pipe)
        .stderr(Redirection::Merge)
        .capture()?
        .stdout_str();

    let mut res = HttpResponse::Ok().body(output);
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/plain"),
    );

    Ok(res)
}

//pub fn run_cmd_rt_output(cmd: &str, args: &[&str]) {
pub fn run_cmd_rt_output(cmd: &str, args: &[String], cfg: web::Data<Arc<Config>>, output: Arc<Mutex<CmdOutputData>>) {
    let cmd = Arc::new(String::from(cmd));
    let mut args2 = vec![];
    for arg in args.iter() {
        args2.push(String::from(arg));
    }
    let args = Arc::new(args2);

    thread::spawn(move || {
        // debug!(
        //     "Locking FWCloud plugins mutex (thread id: {}) ...",
        //     thread_id::get()
        // );
        // let mutex = Arc::clone(&cfg.mutex.plugins);
        // let mutex_data = mutex.lock().await;
        // debug!(
        //     "FWCloud plugins mutex locked (thread id: {})!",
        //     thread_id::get()
        // );
    
        //let args = [String::from(args[0].clone()), String::from("disable")];
        let popen = Exec::cmd(cmd.as_str())
            .args(&args)
            .stdout(Redirection::Pipe)
            .stderr(Redirection::Merge) // Redirect stderr too stdout.
            .popen();

        let mut popen = match popen {
            Ok(data) => data,
            Err(e) => {
                error!("Error: {}", e);
                return;
            }
        };

        let mut communicator = popen.communicate_start(Option::None)
            .limit_size(1); // IMPORTANT: Read the output byte by byte.

        let mut line = String::new();
        loop {
            let (stdout, _stderr) = match communicator.read_string() {
                Ok(data) => data,
                Err(e) => {
                    error!("Subprocess communication error: {}", e.to_string()); 
                    break;
                }
            };
            
            // Remember that with .stderr(Redirection::Merge) we have redirected 
            // the stderr output to stdout. Then we will have all the output in stdout.
            let data = match stdout {
                Some(data) => data,
                None => String::new()
            };      
            
            // Finish when no more input data.
            if data.len() == 0 { 
                let mut output = output.lock().unwrap();
                output.finished = true;
                break;
            }

            let c = data.chars().nth(0).unwrap();
            if c == '\r' {  // Ignore '\r' characters.
                continue;
            }
            if c != '\n' {
                line.push(c);
                continue;
            }

            {
                let mut output = output.lock().unwrap();
                output.lines.push(line);
            }

            line = String::new();
        }

        // debug!(
        //     "Unlocking FWCloud plugins mutex (thread id: {}) ...",
        //     thread_id::get()
        // );
        // drop(mutex_data);
        // debug!(
        //     "FWCloud plugins mutex unlocked (thread id: {})!",
        //     thread_id::get()
        // );        
    });
}
