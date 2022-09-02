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

use actix_web::{http::header, HttpResponse};
use log::error;
use std::sync::{Arc, Mutex};
use subprocess::{Exec, Redirection};

use crate::errors::{FwcError, Result};
use crate::utils::ws::WsData;

pub fn run_cmd(cmd: &str, args: &[&str]) -> Result<HttpResponse> {
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

pub fn run_cmd_ws(cmd: &str, args: &[&str], ws_data: &Arc<Mutex<WsData>>) -> Result<HttpResponse> {
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
            None => String::new(),
        };

        // Finish when no more input data.
        if data.is_empty() {
            ws_data.lock().unwrap().finished = true;
            break;
        }

        let c = data.chars().next().unwrap();
        if c != '\r' && c != '\n' {
            line.push(c);
            continue;
        }

        // We have already added the line to the lines buffer due to the '\r' character.
        // With this code we avoid adding an empty line when we found a sequence of '\r' and '\n' characters.
        if c == '\n' && previous_char_is_cr {
            previous_char_is_cr = false;
            continue;
        }

        {
            ws_data.lock().unwrap().lines.push(line);
        }

        line = String::new();
        if c == '\r' {
            previous_char_is_cr = true;
        } else {
            previous_char_is_cr = false;
        }
    }

    Ok(HttpResponse::Ok().finish())
}
