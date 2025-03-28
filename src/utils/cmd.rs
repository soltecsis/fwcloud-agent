/*
    Copyright 2025 SOLTECSIS SOLUCIONES TECNOLOGICAS, SLU
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

use actix_web::{http::header, HttpResponse};
use log::debug;
use log::error;
use std::sync::{Arc, Mutex};
use std::{thread, time::Duration};
use subprocess::{Exec, Redirection};

use crate::errors::{FwcError, Result};
use crate::utils::ws::WsData;

pub fn run_cmd(cmd: &str, args: &[&str]) -> Result<HttpResponse> {
    let output = Exec::cmd(cmd)
        .args(args)
        .stdout(Redirection::Pipe)
        .stderr(Redirection::Merge)
        .capture()?;

    if !output.exit_status.success() && cmd != "systemctl" {
        // If the process doesn't exits with exit status 0.
        error!("Error: Command exit status not 0");
        return Err(FwcError::CmdExitStatusNotZero);
    }

    let mut res = HttpResponse::Ok().body(output.stdout_str());
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/plain"),
    );

    Ok(res)
}

pub fn run_cmd_ws(
    cmd: &str,
    args: &[&str],
    ws_data: &Arc<Mutex<WsData>>,
    finish_ws: bool,
) -> Result<HttpResponse> {
    let popen = Exec::cmd(cmd)
        .args(args)
        .stdout(Redirection::Pipe)
        .stderr(Redirection::Merge) // Redirect stderr too stdout.
        .popen();

    let mut popen = match popen {
        Ok(data) => data,
        Err(e) => {
            error!("Error: {}", e);
            return Err(FwcError::Internal("Popen error"));
        }
    };

    let mut communicator = popen.communicate_start(Option::None).limit_size(1); // IMPORTANT: Read the output byte by byte.

    let mut previous_char_is_cr = false;
    let mut line_u8: Vec<u8> = Vec::new();
    loop {
        let (stdout, _stderr) = match communicator.read() {
            Ok(data) => data,
            Err(e) => {
                error!("Subprocess communication error: {}", e);
                break;
            }
        };

        // Remember that with .stderr(Redirection::Merge) we have redirected
        // the stderr output to stdout. Then we will have all the output in stdout.
        let data = stdout.unwrap_or_default();

        // Finish when no more input data.
        if data.is_empty() {
            if finish_ws {
                debug!("Locking ws data mutex (thread id: {})", thread_id::get());
                ws_data.lock().unwrap().finished = true;
                debug!("Releasing ws data mutex (thread id: {})", thread_id::get());
            }
            break;
        }

        let c = data[0];
        // \n == 10
        // \r == 13
        if c != 13 && c != 10 {
            line_u8.push(c);
            continue;
        }

        // We have already added the line to the lines buffer due to the '\r' character.
        // With this code we avoid adding an empty line when we found a sequence of '\r' and '\n' characters.
        // \n == 10
        if c == 10 && previous_char_is_cr {
            previous_char_is_cr = false;
            continue;
        }

        {
            debug!("Locking ws data mutex (thread id: {})", thread_id::get());
            ws_data
                .lock()
                .unwrap()
                .lines
                .push(String::from_utf8_lossy(&line_u8).to_string());
            debug!("Releasing ws data mutex (thread id: {})", thread_id::get());
        }

        line_u8 = Vec::new();
        // \r == 13
        previous_char_is_cr = c == 13;
    }

    if popen.wait()?.success() {
        Ok(HttpResponse::Ok().finish())
    } else {
        error!("Error: Command exit status not 0");

        // A little pause for allow that all the websocket messages arrive to the
        // user interface before sending the error response to the API.
        thread::sleep(Duration::from_millis(300));

        Err(FwcError::CmdExitStatusNotZero)
    }
}
