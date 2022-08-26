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
use actix_web::{get, HttpResponse, http::header::ContentType};
use serde::Serialize;

use crate::errors::Result;

#[derive(Serialize)]
struct Info {
    fwc_agent_version: &'static str
}

/*
  curl -v -k -i -X GET -H 'X-API-Key: **************************' https://localhost:33033/api/v1/info
*/
#[get("/info")]
async fn info() -> Result<HttpResponse> {
  let info = Info {
    fwc_agent_version: env!("CARGO_PKG_VERSION")
  };

  Ok(HttpResponse::Ok()
    .content_type(ContentType::json())
    .body(serde_json::to_string(&info).unwrap_or(String::from(""))))
}
