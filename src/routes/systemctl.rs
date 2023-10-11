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
use crate::utils::cmd::run_cmd;
use actix_web::{post, web, HttpResponse};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::errors::Result;

#[derive(Deserialize, Serialize, Validate)]
pub struct Systemctl {
    #[validate(regex(
        path = "crate::utils::myregex::SYSTEMCTL_COMMANDS",
        message = "Invalid systemctl command"
    ))]
    pub command: String,
    #[validate(regex(
        path = "crate::utils::myregex::SYSTEMCTL_SERVICES",
        message = "Invalid systemctl service"
    ))]
    pub service: String,
}

/*
  curl -k -i -X POST -H 'X-API-Key: **************************' \
    -H "Content-Type: application/json" \
    -d '{"action":"status", "service":"openvpn"}' \
    https://localhost:33033/api/v1/systemctl
*/
#[post("/systemctl")]
async fn systemctl(systemctl: web::Json<Systemctl>) -> Result<HttpResponse> {
    systemctl.validate()?; // Validate input.

    run_cmd(
        "systemctl",
        &[systemctl.command.as_ref(), systemctl.service.as_ref()],
    )
}
