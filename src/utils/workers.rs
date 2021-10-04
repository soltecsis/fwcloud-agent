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

use std::thread;
use thread_id;
use std::sync::Arc;
use log::info;

use crate::config::Config;

struct OpenVPNStFile {
    st_file: String,
    data_file: String,
    last_update: String
}
  
fn create_files_list(cfg: Arc<Config>) -> Vec<OpenVPNStFile> {
    let mut openvpn_status_files: Vec<OpenVPNStFile> = vec![];

    // Create the list of OpenVPN status files.
    if cfg.openvpn_status_files_list.len() > 1 {
        let files: Vec<&str> = cfg.openvpn_status_files_list.split(",").collect();
        for file in files.into_iter() {
            openvpn_status_files.push( OpenVPNStFile {
                st_file: String::from(file),
                data_file: format!("{}/{}.data",cfg.data_dir,file.replace("/", "_")),
                last_update: String::from("")
            });
        }  
    }

    openvpn_status_files
}

pub fn openvpn_status_collector(cfg: Arc<Config>) {
    thread::spawn(move || {
        info!("Starting OpenVPN status data collector thread (id: {})", thread_id::get());
        let mut openvpn_status_files = create_files_list(cfg);

        for item in openvpn_status_files.iter_mut() {
            item.last_update = String::from("safa");
        }
    });
}
