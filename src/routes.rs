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

mod daemon;
mod fwcloud_script;
mod info;
mod interfaces;
mod ipsec;
mod iptables_save;
mod openvpn;
mod ping;
pub mod plugin;
pub mod systemctl;
mod wireguard;
mod ws;

use actix_web::web;

pub fn routes_setup(config: &mut web::ServiceConfig) {
    config.service(
        web::scope("/api/v1")
            .service(ping::ping)
            .service(info::info)
            // FWCloud script.
            .service(fwcloud_script::upload_and_run)
            // OpenVPN.
            .service(openvpn::files_upload)
            .service(openvpn::files_remove)
            .service(openvpn::files_sha256)
            .service(openvpn::get_status)
            .service(openvpn::update_status)
            .service(openvpn::get_status_rt)
            // WireGuard.
            .service(wireguard::files_upload)
            .service(wireguard::files_remove)
            // IPSec.
            .service(ipsec::files_upload)
            .service(ipsec::files_remove)
            // Interfaces.
            .service(interfaces::info)
            // IPTables save.
            .service(iptables_save::data)
            // Plugins.
            .service(plugin::plugin)
            // Systemctl.
            .service(systemctl::systemctl)
            // Daemon.
            .service(daemon::config_upload)
            // WebSocket.
            .service(ws::websocket)
            .service(ws::websocket_test),
    );
}
