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

use std::{fs, fs::File, sync::Mutex, thread, time};
use thread_id;
use std::sync::Arc;
use log::{info, warn, error, debug};
use std::io::{BufReader, BufRead, Write};
use chrono::NaiveDateTime;

use crate::config::Config;

struct OpenVPNStFile {
    st_file: String,
    tmp_file: String,
    data_file: String,
    last_update: i64
}

struct OpenVPNStCollectorInner {
    openvpn_status_files: Vec<OpenVPNStFile>,
    sampling_interval: u64
}
pub struct OpenVPNStCollector { 
    inner: Arc<Mutex<OpenVPNStCollectorInner>> 
}


impl OpenVPNStCollectorInner {
    pub fn new(cfg: &Config) -> Self { 
        let mut data = OpenVPNStCollectorInner {
            openvpn_status_files: vec![],
            sampling_interval: cfg.openvpn_status_sampling_interval
        }; 

        // Create the list of OpenVPN status files.
        if cfg.openvpn_status_files_list.len() > 1 {
            let files: Vec<&str> = cfg.openvpn_status_files_list.split(",").collect();
            for file in files.into_iter() {
                data.openvpn_status_files.push( OpenVPNStFile {
                    st_file: String::from(file),
                    tmp_file: format!("{}/{}.tmp",cfg.tmp_dir,file.replace("/", "_")),
                    data_file: format!("{}/{}.data",cfg.data_dir,file.replace("/", "_")),
                    last_update: 0
                });
            }
        }

        data
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

    pub fn collect_all_files_data(&mut self) {
        for item in self.openvpn_status_files.iter_mut() {
            debug!("Collecting OpenVPN status data from file: {}",item.st_file);
            match OpenVPNStCollectorInner::collect_status_data(item) {
                Ok(_) => (),
                Err(e) => error!("Collecting OpenVPN status data from file: {} ({}) ",item.st_file,e)
            }
        }

    }
}


impl OpenVPNStCollector {
    pub fn new(cfg: &Config) -> Self {
        OpenVPNStCollector { 
            inner: Arc::new(Mutex::new(OpenVPNStCollectorInner::new(cfg))) 
        } 
    }

    pub fn start(&self, cfg: Arc<Config>) {
        let local_self = self.inner.clone();

        thread::spawn(move || {
            info!("Starting OpenVPN status data collector thread (id: {})", thread_id::get());

            loop {
                debug!("Locking OpenVPM mutex (thread id: {}) ...", thread_id::get());
                let mutex = Arc::clone(&cfg.mutex.openvpn);
                let mutex_data = mutex.lock().unwrap();
                debug!("OpenVPN mutex locked (thread id: {})!", thread_id::get());
              
                let mut collector = local_self.lock().unwrap();
                collector.collect_all_files_data();

                debug!("Unlocking OpenVPM mutex (thread id: {}) ...", thread_id::get());
                drop(mutex_data);
                debug!("OpenVPN mutex unlocked (thread id: {})!", thread_id::get());

                // Pause between samplings.
                thread::sleep(time::Duration::from_secs(collector.sampling_interval));
            }
        });
    }
}