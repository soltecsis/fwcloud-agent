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

mod ping;
mod fwcloud_script;
mod openvpn;
mod interfaces;
mod iptables_save;

use actix_web::web;

pub fn routes_setup(config: &mut web::ServiceConfig) {
    config.service(web::scope("/api/v1")
        .service(ping::ping)

        .service(web::scope("/fwcloud_script/")
            .service(fwcloud_script::upload_and_run)
        )

        .service(web::scope("/openvpn/")
            .service(openvpn::files_upload)
            .service(openvpn::files_remove)
            .service(openvpn::files_sha256)
            .service(openvpn::get_status)
        )

        .service(web::scope("/interfaces/")
            .service(interfaces::info)
        )

        .service(web::scope("/iptables-save/")
            .service(iptables_save::data)
        )
    );
}
