/*
    Copyright 2026 SOLTECSIS SOLUCIONES TECNOLOGICAS, SLU
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

mod crowdsec;
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
            // CrowdSec.
            .service(crowdsec::crowdsec_status)
            .service(crowdsec::crowdsec_collections)
            .service(crowdsec::install_crowdsec_collection)
            .service(crowdsec::remove_crowdsec_collection)
            .service(crowdsec::update_crowdsec_collections)
            .service(crowdsec::crowdsec_console_status)
            .service(crowdsec::enroll_crowdsec_console)
            .service(crowdsec::crowdsec_decisions)
            .service(crowdsec::delete_crowdsec_decision)
            .service(crowdsec::flush_crowdsec_decisions)
            .service(crowdsec::crowdsec_alerts)
            .service(crowdsec::configure_crowdsec_central_lapi)
            .service(crowdsec::issue_crowdsec_lapi_preflight_token)
            .service(crowdsec::crowdsec_lapi_ping)
            .service(crowdsec::preflight_crowdsec_lapi)
            .service(crowdsec::crowdsec_lapi_machines)
            .service(crowdsec::validate_crowdsec_lapi_machine)
            .service(crowdsec::remove_crowdsec_lapi_machine)
            .service(crowdsec::register_crowdsec_lapi_bouncer)
            .service(crowdsec::crowdsec_bouncers)
            .service(crowdsec::register_crowdsec_bouncer)
            .service(crowdsec::remove_crowdsec_bouncer)
            .service(crowdsec::install_crowdsec)
            .service(crowdsec::uninstall_crowdsec)
            .service(crowdsec::install_crowdsec_bouncer)
            .service(crowdsec::uninstall_crowdsec_bouncer)
            // FWCloud script.
            .service(fwcloud_script::upload_and_run)
            // OpenVPN.
            .service(openvpn::dir_ensure)
            .service(openvpn::dir_remove_empty)
            .service(openvpn::files_upload)
            .service(openvpn::files_remove)
            .service(openvpn::files_sha256)
            .service(openvpn::get_status)
            .service(openvpn::update_status)
            .service(openvpn::status_sampling_update)
            .service(openvpn::status_sampling_show)
            .service(openvpn::get_status_rt)
            .service(openvpn::files_read)
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
