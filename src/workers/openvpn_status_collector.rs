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

use chrono::prelude::*;
use futures::executor::block_on;

use log::{debug, error, info};
use std::io::{BufRead, BufReader, Write};
use std::sync::mpsc::{self, Sender};
use std::sync::Arc;
use std::{fs, fs::File, path::Path, sync::Mutex, thread, time};
use thread_id;

use crate::config::Config;

const FORMAT_STR_OLD: &str = "%a %b %e %H:%M:%S %Y";
const FORMAT_STR_NEW: &str = "%Y-%m-%d %H:%M:%S";

struct OpenVPNStFile {
    st_file: String,
    tmp_file: String,
    cache_file: String,
    last_update: u64,
}

struct OpenVPNStCollectorInner {
    openvpn_status_files: Vec<OpenVPNStFile>,
    max_size: usize,
    sampling_interval: u64,
}
pub struct OpenVPNStCollector {
    inner: Arc<Mutex<OpenVPNStCollectorInner>>,
}

impl OpenVPNStCollectorInner {
    pub fn new(cfg: &Config) -> Self {
        let mut data = OpenVPNStCollectorInner {
            openvpn_status_files: vec![],
            max_size: cfg.openvpn_status_cache_max_size,
            sampling_interval: cfg.openvpn_status_sampling_interval,
        };

        // Create the list of OpenVPN status files.
        for file in cfg.openvpn_status_files.iter() {
            data.openvpn_status_files.push(OpenVPNStFile {
                st_file: String::from(file),
                tmp_file: format!("{}/{}.tmp", cfg.tmp_dir, file.replace('/', "_")),
                cache_file: format!("{}/{}.data", cfg.data_dir, file.replace('/', "_")),
                last_update: 0,
            });
        }

        data
    }

    /// This function will convert datetime string that it receives in the amounts os seconds since `UNIX_EPOCH`.
    ///
    /// `UNIX_EPOCH` is a constant in the Rust programming language that represents the starting
    /// point of the Unix epoch, which is a reference point for measuring time in many operating systems,
    /// including Unix-like systems. The Unix epoch refers to the point in time when the system's internal
    /// clock was set to zero, typically occurring at midnight on January 1, 1970, Coordinated Universal Time (UTC).
    ///
    /// Since `OpenVPN 2.5` the datetime string format used in the `openvpn-status.log` file has changed.
    /// Before to this version the format was like this `Fri Jul 21 14:35:56 2023`, and the new format is
    /// like this `2023-07-21 15:02:00`. This functions support both formats.
    fn convert_to_seconds_since_unix_epoch(datetime_str: &str) -> Option<u64> {
        match NaiveDateTime::parse_from_str(datetime_str, FORMAT_STR_NEW) {
            Ok(parsed_datetime) => Some(parsed_datetime.and_utc().timestamp() as u64),
            Err(_err) => match NaiveDateTime::parse_from_str(datetime_str, FORMAT_STR_OLD) {
                Ok(parsed_datetime) => Some(parsed_datetime.and_utc().timestamp() as u64),
                Err(_err) => None,
            },
        }
    }

    fn collect_status_data(item: &mut OpenVPNStFile, max_size: usize) -> std::io::Result<()> {
        if Path::new(&item.cache_file).is_file()
            && fs::metadata(&item.cache_file)?.len() > max_size as u64
        {
            error!("OpenVPN status cache file for '{}' too big", item.st_file);
            return Ok(());
        }

        // Copy the current OpenVPN status data into a temporary file.
        fs::copy(&item.st_file, &item.tmp_file)?;

        // Open temporary file for reading and data file for writing.
        let f = File::open(&item.tmp_file)?;
        let reader = BufReader::new(&f);
        let mut writer = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&item.cache_file)?;

        let mut current_update: u64 = 0;
        for (n, l) in reader.lines().enumerate().skip(1) {
            let line = l?;

            if n > 2 {
                // End of the OpenVPN status data.
                if &line[..] == "ROUTING TABLE" {
                    break;
                }

                // Convert the Connected Since date string to timestamp.
                let data: Vec<&str> = line.split(',').collect();
                match OpenVPNStCollectorInner::convert_to_seconds_since_unix_epoch(data[4]) {
                    Some(connected_since) => {
                        writeln!(
                            writer,
                            "{},{},{}",
                            current_update,
                            data[..4].join(","),
                            connected_since
                        )?;
                    }
                    None => {
                        error!("Bad datetime string in OpenVPN status file in line {n}");
                    }
                }

                continue;
            }

            // Line header for the status data: Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
            if n == 2 {
                continue;
            }

            // If we arrive here we must be over the update info line.
            if &line[0..8] != "Updated," {
                error!(
                    "Bad OpenVPN status file ({}): update line not found",
                    item.st_file
                );
                break;
            }

            // Get the update timestamp of the current status file and compare it with the
            // previous one in order to see if we have new data into it.
            match OpenVPNStCollectorInner::convert_to_seconds_since_unix_epoch(&line[8..]) {
                Some(ts) => {
                    current_update = ts;
                }
                None => {
                    error!("Bad datetime string in OpenVPN status file in Updated line");
                    break;
                }
            }

            // Skip the first sampling cycle, this way we avoid collect that of an OpenVPN status
            // file that doesn't change in time (for example, because the OpenVPN server is not running).
            if item.last_update == 0 {
                break;
            }

            if current_update == item.last_update {
                debug!("No new OpenVPN status data found in file: {}", item.st_file);
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
            debug!("Collecting OpenVPN status data from file: {}", item.st_file);
            match OpenVPNStCollectorInner::collect_status_data(item, self.max_size) {
                Ok(_) => (),
                Err(e) => {
                    /* If the default openvpn status log file doesn't exists then only display error
                    at the debug level. This simplifies the setup because we can leave the default value
                    for OPENVPN_STATUS_FILES and not full the logs with repetitive messages when the default file
                    doesn't exists. */
                    if item.st_file == "/etc/openvpn/openvpn-status.log"
                        && e.to_string() == "No such file or directory (os error 2)"
                    {
                        debug!(
                            "Collecting OpenVPN status data from file: {} ({}) ",
                            item.st_file, e
                        )
                    } else {
                        error!(
                            "Collecting OpenVPN status data from file: {} ({}) ",
                            item.st_file, e
                        )
                    }
                }
            }
        }
    }

    pub fn len(&self) -> usize {
        self.openvpn_status_files.len()
    }
}

impl OpenVPNStCollector {
    pub fn new(cfg: &Config) -> Self {
        OpenVPNStCollector {
            inner: Arc::new(Mutex::new(OpenVPNStCollectorInner::new(cfg))),
        }
    }

    pub fn start(&self, cfg: Arc<Config>) -> Sender<u8> {
        let local_self = self.inner.clone();

        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            block_on(async {
                info!(
                    "Starting OpenVPN status data collector thread (id: {})",
                    thread_id::get()
                );
                if local_self.lock().unwrap().len() == 0 {
                    info!("List of OpenVPN status files is empty")
                }

                loop {
                    let pause: u64;

                    // Start of mutex scope.
                    {
                        debug!("Locking OpenVPN mutex (thread id: {})", thread_id::get());
                        let mutex = Arc::clone(&cfg.mutex.openvpn);
                        let _mutex_data = mutex.lock().await;
                        debug!("OpenVPN mutex locked (thread id: {})", thread_id::get());

                        // Only for debug purposes. It is useful for verify that the mutex makes its work.
                        //thread::sleep(time::Duration::from_millis(10_000));

                        let mut collector = local_self.lock().unwrap();
                        collector.collect_all_files_data();
                        pause = collector.sampling_interval;

                        debug!("Releasing OpenVPN mutex (thread id: {})", thread_id::get());
                    } // End of mutex scope.

                    // Pause between samplings.
                    for _n in 0..pause {
                        thread::sleep(time::Duration::from_secs(1));

                        let cmd = rx.try_recv().unwrap_or(0);
                        if cmd == 1 {
                            debug!("OpenVPN status data update requested");
                            break;
                        }
                    }
                }
            })
        });

        tx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::Result;
    use rand::Rng;
    use serial_test::serial;
    use std::env;
    use uuid::Uuid;

    fn collector_factory(
        env_list: Vec<(&str, String)>,
        change_paths: bool,
    ) -> OpenVPNStCollectorInner {
        for v in env_list.iter() {
            env::set_var(v.0, &v.1);
        }

        env::set_var("API_KEY", "d64c88318c8f213f427af857d0013f93");
        let cfg = Arc::new(Config::new().unwrap());

        for v in env_list.iter() {
            env::remove_var(v.0);
        }

        let mut collector = OpenVPNStCollectorInner::new(&cfg);

        if change_paths {
            for inx in 0..collector.len() {
                collector.openvpn_status_files[inx].tmp_file = collector.openvpn_status_files[inx]
                    .tmp_file
                    .replace("./tmp/", "./tests/playground/tmp/");
                collector.openvpn_status_files[inx].cache_file = collector.openvpn_status_files
                    [inx]
                    .cache_file
                    .replace("./data/", "./tests/playground/data/");
            }
        }

        collector
    }

    fn status_files_list_factory(n: usize) -> Vec<String> {
        let mut list: Vec<String> = vec![];

        for _ in 0..n {
            list.push(format!(
                "{}/tests/playground/tmp/{}.log",
                env::current_dir().unwrap().display(),
                Uuid::new_v4()
            ));
        }

        list
    }

    fn remove_collector_files(collector: &OpenVPNStCollectorInner) -> Result<()> {
        for inx in 0..collector.len() {
            if Path::new(&collector.openvpn_status_files[inx].st_file).is_file() {
                fs::remove_file(&collector.openvpn_status_files[inx].st_file)?;
            }
            if Path::new(&collector.openvpn_status_files[inx].tmp_file).is_file() {
                fs::remove_file(&collector.openvpn_status_files[inx].tmp_file)?;
            }
            if Path::new(&collector.openvpn_status_files[inx].cache_file).is_file() {
                fs::remove_file(&collector.openvpn_status_files[inx].cache_file)?;
            }
        }

        Ok(())
    }

    #[test]
    #[serial]
    fn generates_right_default_openvpn_status_file_vector() {
        let collector = collector_factory(vec![], false);
        assert_eq!(collector.openvpn_status_files.len(), 1);
        assert_eq!(
            collector.openvpn_status_files[0].st_file,
            String::from("/etc/openvpn/openvpn-status.log")
        );
        assert_eq!(
            collector.openvpn_status_files[0].tmp_file,
            String::from("./tmp/_etc_openvpn_openvpn-status.log.tmp")
        );
        assert_eq!(
            collector.openvpn_status_files[0].cache_file,
            String::from("./data/_etc_openvpn_openvpn-status.log.data")
        );
        assert_eq!(collector.openvpn_status_files[0].last_update, 0);
    }

    #[test]
    #[serial]
    fn empty_openvpn_status_file_vector_if_config_option_is_empty() {
        let collector = collector_factory(vec![("OPENVPN_STATUS_FILES", String::from(""))], false);
        assert_eq!(collector.openvpn_status_files.len(), 0);
    }

    #[test]
    #[serial]
    fn customized_openvpn_status_files_config() {
        let n = rand::rng().random_range(0..5);
        let list = status_files_list_factory(n);
        let collector = collector_factory(vec![("OPENVPN_STATUS_FILES", list.join(","))], false);
        assert_eq!(collector.openvpn_status_files.len(), n);

        for inx in 0..n {
            assert_eq!(collector.openvpn_status_files[inx].st_file, list[inx]);
            assert_eq!(
                collector.openvpn_status_files[inx].tmp_file,
                format!("./tmp/{}.tmp", list[inx].replace('/', "_"))
            );
            assert_eq!(
                collector.openvpn_status_files[inx].cache_file,
                format!("./data/{}.data", list[inx].replace('/', "_"))
            );
            assert_eq!(collector.openvpn_status_files[inx].last_update, 0);
        }
    }

    #[test]
    #[serial]
    fn should_ignore_fist_sample_set() -> Result<()> {
        let list = status_files_list_factory(1);
        let mut collector = collector_factory(vec![("OPENVPN_STATUS_FILES", list.join(","))], true);

        fs::copy(
            "./tests/templates/openvpn-status.log_ts1",
            &collector.openvpn_status_files[0].st_file,
        )?;

        collector.collect_all_files_data();

        // This is the first data collection, and then the cache file should be created but with 0 bytes.
        let size = fs::metadata(&collector.openvpn_status_files[0].cache_file)?.len();
        assert_eq!(size, 0);
        // The last_updated timestamp must be updated with the one into the OpenVPN status file.
        assert_eq!(collector.openvpn_status_files[0].last_update, 1633366402);

        remove_collector_files(&collector)?;
        Ok(())
    }

    #[test]
    #[serial]
    fn should_append_to_cache_file_if_timestamp_changes() -> Result<()> {
        let list = status_files_list_factory(1);
        let mut collector = collector_factory(vec![("OPENVPN_STATUS_FILES", list.join(","))], true);

        fs::copy(
            "./tests/templates/openvpn-status.log_ts1",
            &collector.openvpn_status_files[0].st_file,
        )?;
        collector.collect_all_files_data();

        // This is the first data collection, and then the cache file should be created but with 0 bytes.
        let mut size = fs::metadata(&collector.openvpn_status_files[0].cache_file)?.len();
        assert_eq!(size, 0);
        // The last_updated timestamp must be updated with the one into the OpenVPN status file.
        assert_eq!(collector.openvpn_status_files[0].last_update, 1633366402);

        // Change the status file by a new one with different timestamp.
        fs::copy(
            "./tests/templates/openvpn-status.log_ts2",
            &collector.openvpn_status_files[0].st_file,
        )?;
        collector.collect_all_files_data();
        size = fs::metadata(&collector.openvpn_status_files[0].cache_file)?.len();
        assert_eq!(size, 262);
        assert_eq!(collector.openvpn_status_files[0].last_update, 1633366441);

        // Change the status file by a new one with different timestamp.
        fs::copy(
            "./tests/templates/openvpn-status.log_ts3",
            &collector.openvpn_status_files[0].st_file,
        )?;
        collector.collect_all_files_data();
        size = fs::metadata(&collector.openvpn_status_files[0].cache_file)?.len();
        assert_eq!(size, 524);
        assert_eq!(collector.openvpn_status_files[0].last_update, 1633366496);

        // Change the status file by a new one with lower timestamp.
        fs::copy(
            "./tests/templates/openvpn-status.log_ts1",
            &collector.openvpn_status_files[0].st_file,
        )?;
        collector.collect_all_files_data();
        size = fs::metadata(&collector.openvpn_status_files[0].cache_file)?.len();
        assert_eq!(size, 786);
        assert_eq!(collector.openvpn_status_files[0].last_update, 1633366402);

        remove_collector_files(&collector)?;
        Ok(())
    }

    #[test]
    #[serial]
    fn should_not_append_to_cache_file_if_timestamp_is_equal() -> Result<()> {
        let list = status_files_list_factory(1);
        let mut collector = collector_factory(vec![("OPENVPN_STATUS_FILES", list.join(","))], true);

        fs::copy(
            "./tests/templates/openvpn-status.log_ts1",
            &collector.openvpn_status_files[0].st_file,
        )?;
        collector.collect_all_files_data();

        // This is the first data collection, and then the cache file should be created but with 0 bytes.
        let mut size = fs::metadata(&collector.openvpn_status_files[0].cache_file)?.len();
        assert_eq!(size, 0);
        // The last_updated timestamp must be updated with the one into the OpenVPN status file.
        assert_eq!(collector.openvpn_status_files[0].last_update, 1633366402);

        // Change the status file by a new one with different timestamp.
        fs::copy(
            "./tests/templates/openvpn-status.log_ts2",
            &collector.openvpn_status_files[0].st_file,
        )?;
        collector.collect_all_files_data();
        size = fs::metadata(&collector.openvpn_status_files[0].cache_file)?.len();
        assert_eq!(size, 262);
        assert_eq!(collector.openvpn_status_files[0].last_update, 1633366441);

        // Don't change OpenVPN status log file, then timestamp is the same.
        collector.collect_all_files_data();
        size = fs::metadata(&collector.openvpn_status_files[0].cache_file)?.len();
        assert_eq!(size, 262);
        assert_eq!(collector.openvpn_status_files[0].last_update, 1633366441);

        remove_collector_files(&collector)?;
        Ok(())
    }

    #[test]
    #[serial]
    fn control_cache_file_size() -> Result<()> {
        let list = status_files_list_factory(1);
        let mut collector = collector_factory(
            vec![
                ("OPENVPN_STATUS_CACHE_MAX_SIZE", String::from("1")),
                ("OPENVPN_STATUS_FILES", list.join(",")),
            ],
            true,
        );

        fs::copy(
            "./tests/templates/openvpn-status.log_ts1",
            &collector.openvpn_status_files[0].st_file,
        )?;
        collector.collect_all_files_data();
        let mut size = fs::metadata(&collector.openvpn_status_files[0].cache_file)?.len();
        assert_eq!(size, 0);
        assert_eq!(collector.openvpn_status_files[0].last_update, 1633366402);

        fs::copy(
            "./tests/templates/openvpn-status.log_ts2",
            &collector.openvpn_status_files[0].st_file,
        )?;
        collector.collect_all_files_data();
        size = fs::metadata(&collector.openvpn_status_files[0].cache_file)?.len();
        assert_eq!(size, 262);
        assert_eq!(collector.openvpn_status_files[0].last_update, 1633366441);

        fs::copy(
            "./tests/templates/openvpn-status.log_ts3",
            &collector.openvpn_status_files[0].st_file,
        )?;
        collector.collect_all_files_data();
        size = fs::metadata(&collector.openvpn_status_files[0].cache_file)?.len();
        // The cache file size control takes effect and no more status data is collected.
        assert_eq!(size, 262);
        assert_eq!(collector.openvpn_status_files[0].last_update, 1633366441);

        remove_collector_files(&collector)?;
        Ok(())
    }

    #[test]
    fn should_convert_to_correct_timestamp_with_old_datetime_format() {
        assert_eq!(
            OpenVPNStCollectorInner::convert_to_seconds_since_unix_epoch(
                "Fri Jul 21 14:35:56 2023"
            ),
            Some(1689950156)
        );
    }

    #[test]
    fn should_convert_to_correct_timestamp_with_new_datetime_format() {
        assert_eq!(
            OpenVPNStCollectorInner::convert_to_seconds_since_unix_epoch("2023-07-21 15:02:00"),
            Some(1689951720)
        );
    }

    #[test]
    fn should_return_none_with_an_invalid_datetime_string() {
        assert_eq!(
            OpenVPNStCollectorInner::convert_to_seconds_since_unix_epoch("Invalid datetime string"),
            None
        );
    }
}
