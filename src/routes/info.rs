/*
    Copyright 2023 SOLTECSIS SOLUCIONES TECNOLOGICAS, SLU
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
use actix_web::{get, http::header::ContentType, HttpResponse};
use serde::Serialize;
use sysinfo::System;

use crate::errors::Result;

#[derive(Serialize)]
struct Info {
    fwc_agent_version: &'static str,
    host_name: String,
    system_name: String,
    os_version: String,
    kernel_version: String,
}

/*
  curl -v -k -i -X GET -H 'X-API-Key: **************************' https://localhost:33033/api/v1/info
*/
#[get("/info")]
async fn info() -> Result<HttpResponse> {
    let info = Info {
        fwc_agent_version: env!("CARGO_PKG_VERSION"),
        host_name: System::host_name().unwrap_or("".to_owned()),
        system_name: System::name().unwrap_or("".to_owned()),
        os_version: System::os_version().unwrap_or("".to_owned()),
        kernel_version: System::kernel_version().unwrap_or("".to_owned()),
    };

    Ok(HttpResponse::Ok()
        .content_type(ContentType::json())
        .body(serde_json::to_string(&info).unwrap_or_else(|_| String::from(""))))
}
