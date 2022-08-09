/*
    Copyright 2021 SOLTECSIS SOLUCIONES TECNOLOGICAS, SLU
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

use crate::errors::Result;
use actix_web::{http::header, HttpResponse};
use subprocess::{Exec, Redirection};
use std::{thread, time};

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

pub fn run_cmd_rt_output(cmd: &str, args: &[&str]) -> Result<HttpResponse> {
    let output = String::from("TESTING");

    let mut popen = Exec::cmd(cmd)
        .args(args)
        .popen()?;

    loop {
        // Check if process is still running.
        // Important, do it at the beginning of the loop, these way we will be able
        // to capture the process output after it has finished its execution.
        let finished = match popen.poll() {
            Some(_exit_code) => true,
            None => false
        };

        // Even if the process has already finished its execution, print its last output.
        let (stdout, stderr) = popen.communicate(Option::None)?;
        
        match stdout {
            Some(data) => { if data.len() > 0 { println!("stdout: {}",data) } }
            None => ()
        };      
        match stderr {
            Some(data) => { if data.len() > 0 { println!("stderr: {}",data) } }
            None => ()
        };      
        
        // Pause for avoid CPU intensive polling.
        thread::sleep(time::Duration::from_millis(100));

        if finished { break }
    }


    let mut res = HttpResponse::Ok().body(output);
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/plain"),
    );

    Ok(res)
}
