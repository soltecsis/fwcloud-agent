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


use actix_web::{http::header, HttpResponse, web::Bytes};
use subprocess::{Exec, Redirection};
use async_stream::stream;
use crate::errors::FwcError;
use log::{error};

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

pub fn run_cmd_rt_output(cmd: &str, args: &[&str]) -> Result<HttpResponse, FwcError> {
    let s = stream! {
        //for i in 0..20 {
        //    println!("{}",i);
        //    yield Ok::<Bytes, FwcError>(Bytes::from(format!("{}\n",i)));
        //    thread::sleep(time::Duration::from_millis(1000));
        //}
        let mut popen = Exec::cmd("sh")
            .args(&["plugins/test/test.sh","enable"])
            .stdout(Redirection::Pipe)
            .stderr(Redirection::Merge) // Redirect stderr too stdout.
            .popen()?;

        let mut communicator = popen.communicate_start(Option::None)
            .limit_size(1); // Read the output byte by byte.

        loop {
            let (stdout, _stderr) = match communicator.read_string() {
                Ok(data) => data,
                Err(e) => {
                    error!("Subprocess communication error: {}", e.to_string()); 
                    return;
                    //break;
                }
            };
            
            // Remember that with .stderr(Redirection::Merge) we have redirected 
            // the stderr output to stdout. Then we will have all the output in stdout.
            let output = match stdout {
                Some(data) => data,
                None => String::from("")
            };      
            
            // Finish when no more input data.
            if output.len() == 0 { 
                //break;
                return; 
            }

            print!("{}",output);
            yield Ok::<Bytes, FwcError>(Bytes::from(output))
        }
    };

    let res = HttpResponse::Ok()
        .content_type("text/plain")
        //.streaming(Box::pin(stream));
        .streaming(Box::pin(s));
        //.body("TEST");

    Ok(res)
}
