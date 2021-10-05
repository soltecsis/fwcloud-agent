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

use std::{fs, fs::File, thread, time};
use thread_id;
use std::sync::Arc;
use log::{info, warn, error};
use std::io::{BufReader, BufRead, Write};
use chrono::NaiveDateTime;

use crate::config::Config;

struct OpenVPNStFile {
    st_file: String,
    tmp_file: String,
    data_file: String,
    last_update: i64
}
  
fn generate_files_list(cfg: Arc<Config>) -> Vec<OpenVPNStFile> {
    let mut openvpn_status_files: Vec<OpenVPNStFile> = vec![];

    // Create the list of OpenVPN status files.
    if cfg.openvpn_status_files_list.len() > 1 {
        let files: Vec<&str> = cfg.openvpn_status_files_list.split(",").collect();
        for file in files.into_iter() {
            openvpn_status_files.push( OpenVPNStFile {
                st_file: String::from(file),
                tmp_file: format!("{}/{}.tmp",cfg.tmp_dir,file.replace("/", "_")),
                data_file: format!("{}/{}.data",cfg.data_dir,file.replace("/", "_")),
                last_update: 0
            });
        }  
    }

    openvpn_status_files
}

fn collect_status_data(item: &mut OpenVPNStFile) -> std::io::Result<()> {
    // Copy tye current OpenVPN status data into a temporary file.
    fs::copy(&item.st_file,&item.tmp_file)?;

    // Open temporary file for reading and data file for writing.
    let f = File::open(&item.tmp_file)?;
    let reader = BufReader::new(&f);
    let mut writer = fs::OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(&item.data_file)?;

    let mut current_update: i64 = 0;
    for (n, l) in reader.lines().enumerate().skip(1) {
        let line = l?;
        
        if n > 2 { 
            // End of the OpenVPN status data.
            if &line[..] == "ROUTING TABLE" { break }

            writeln!(writer, "{},{}", current_update, line)?;
            continue;                    
        }

        // Line header for the status data: Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
        if n == 2 { continue }

        // If we arrive here we must be over the update info line.
        if &line[0..8] != "Updated," {
            error!("Bad OpenVPN status file ({}): update line not found",item.st_file);
            break;
        }

        // Get the update timestamp of the current status file and compare it with the
        // previous one in order to see if we have new data into it.
        current_update = match NaiveDateTime::parse_from_str(&line[8..], "%a %b %e %T %Y") {
            Ok(date_time) => date_time.timestamp(),
            Err(e) => { 
                error!("Bad OpenVPN status file ({}): invalid updated date ({})",item.st_file,e);
                break;
            }
        };

        if current_update == item.last_update {
            warn!("No new OpenVPN status data found in file: {}",item.st_file);
            break;
        }    
    }
    
    // Update the last timestamp for the next iteration.
    item.last_update = current_update;

    // Remove the temporary file.
    fs::remove_file(&item.tmp_file)?;

    Ok(())
}

pub fn openvpn_status_collector(cfg: Arc<Config>) {
    let sampling_interval = cfg.openvpn_status_sampling_interval;

    thread::spawn(move || {
        info!("Starting OpenVPN status data collector thread (id: {})", thread_id::get());
        let mut openvpn_status_files = generate_files_list(cfg);
        
        loop {
            // Pause between samplings.
            thread::sleep(time::Duration::from_secs(sampling_interval));

            for item in openvpn_status_files.iter_mut() {
                match collect_status_data(item) {
                    Ok(_) => (),
                    Err(e) => error!("Collecting OpenVPN status data from file: {} ({}) ",item.st_file,e)
                }
            }
        }
    });
}
