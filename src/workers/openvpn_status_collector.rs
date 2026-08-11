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
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::sync::mpsc::{self, Sender};
use std::sync::Arc;
use std::{fs, fs::File, path::Path, sync::Mutex, thread, time};
use thread_id;

use crate::config::Config;

const FORMAT_STR_OLD: &str = "%a %b %e %H:%M:%S %Y";
const FORMAT_STR_NEW: &str = "%Y-%m-%d %H:%M:%S";
const API_CONFIG_FILE: &str = "openvpn_status_sampling.json";
pub const DEFAULT_SAMPLING_INTERVAL: u64 = 30;
pub const DEFAULT_REQUEST_MAX_LINES: usize = 1000;
pub const DEFAULT_CACHE_MAX_SIZE: usize = 10485760;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpenVPNStatusFileConfig {
    pub path: String,
    pub sampling_interval: u64,
    pub request_max_lines: usize,
    pub cache_max_size: usize,
}

impl OpenVPNStatusFileConfig {
    pub fn with_defaults(path: String) -> Self {
        OpenVPNStatusFileConfig {
            path,
            sampling_interval: DEFAULT_SAMPLING_INTERVAL,
            request_max_lines: DEFAULT_REQUEST_MAX_LINES,
            cache_max_size: DEFAULT_CACHE_MAX_SIZE,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpenVPNStatusSamplingConfig {
    pub status_files: Vec<OpenVPNStatusFileConfig>,
}

impl OpenVPNStatusSamplingConfig {
    pub fn empty() -> Self {
        OpenVPNStatusSamplingConfig {
            status_files: vec![],
        }
    }

    pub fn path(etc_dir: &str) -> String {
        format!("{etc_dir}/{API_CONFIG_FILE}")
    }

    pub fn load(etc_dir: &str) -> std::io::Result<Option<Self>> {
        let path = Self::path(etc_dir);

        if !Path::new(&path).is_file() {
            return Ok(None);
        }

        fs::read_to_string(path)
            .and_then(|data| Self::from_json(&data))
            .map(Some)
    }

    pub fn load_or_create(etc_dir: &str) -> std::io::Result<Self> {
        match Self::load(etc_dir)? {
            Some(config) => Ok(config),
            None => {
                let config = Self::empty();
                config.save(etc_dir)?;
                Ok(config)
            }
        }
    }

    pub fn save(&self, etc_dir: &str) -> std::io::Result<()> {
        fs::write(
            Self::path(etc_dir),
            serde_json::to_string_pretty(self)
                .map_err(|err| std::io::Error::other(err.to_string()))?,
        )
    }

    fn effective_status_files(&self) -> Vec<OpenVPNStatusFileConfig> {
        self.status_files.clone()
    }

    pub fn request_max_lines_for_path(&self, path: &str) -> usize {
        self.status_files
            .iter()
            .find(|status_file| status_file.path == path)
            .map(|status_file| status_file.request_max_lines)
            .unwrap_or(DEFAULT_REQUEST_MAX_LINES)
    }

    fn from_json(data: &str) -> std::io::Result<Self> {
        let value: Value =
            serde_json::from_str(data).map_err(|err| std::io::Error::other(err.to_string()))?;
        let enabled = value
            .get("enabled")
            .and_then(Value::as_bool)
            .unwrap_or(true);

        let mut status_files = vec![];

        if enabled {
            for item in value
                .get("status_files")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
            {
                if let Some(path) = item.as_str() {
                    status_files.push(OpenVPNStatusFileConfig::with_defaults(path.to_string()));
                } else {
                    status_files.push(
                        serde_json::from_value(item)
                            .map_err(|err| std::io::Error::other(err.to_string()))?,
                    );
                }
            }
        }

        Ok(OpenVPNStatusSamplingConfig { status_files })
    }
}

struct OpenVPNStFile {
    st_file: String,
    tmp_file: String,
    cache_file: String,
    last_update: u64,
    sampling_interval: u64,
    cache_max_size: usize,
    seconds_until_next_sample: u64,
}

impl OpenVPNStFile {
    fn new(config: &OpenVPNStatusFileConfig, tmp_dir: &str, data_dir: &str) -> Self {
        OpenVPNStFile {
            st_file: config.path.clone(),
            tmp_file: format!("{}/{}.tmp", tmp_dir, config.path.replace('/', "_")),
            cache_file: format!("{}/{}.data", data_dir, config.path.replace('/', "_")),
            last_update: 0,
            sampling_interval: config.sampling_interval,
            cache_max_size: config.cache_max_size,
            seconds_until_next_sample: 0,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct OpenVPNStatusSession {
    common_name: String,
    real_address: String,
    bytes_received: u64,
    bytes_sent: u64,
    connected_since: u64,
    sample_timestamp: u64,
}

impl OpenVPNStatusSession {
    fn to_cache_record(&self) -> String {
        format!(
            "{},{},{},{},{},{}",
            self.sample_timestamp,
            self.common_name,
            self.real_address,
            self.bytes_received,
            self.bytes_sent,
            self.connected_since
        )
    }
}

#[derive(Debug, PartialEq, Eq)]
enum OpenVPNStatusFormat {
    V1,
    V2,
    V3,
}

struct OpenVPNStatusClientListColumns {
    common_name: usize,
    real_address: usize,
    bytes_received: usize,
    bytes_sent: usize,
    connected_since: usize,
    connected_since_timestamp: Option<usize>,
}

struct OpenVPNStCollectorInner {
    openvpn_status_files: Vec<OpenVPNStFile>,
}

#[derive(Clone)]
pub struct OpenVPNStCollector {
    inner: Arc<Mutex<OpenVPNStCollectorInner>>,
}

impl OpenVPNStCollectorInner {
    pub fn new(cfg: &Config) -> Self {
        let mut data = OpenVPNStCollectorInner {
            openvpn_status_files: vec![],
        };

        let status_files = match OpenVPNStatusSamplingConfig::load_or_create(cfg.etc_dir) {
            Ok(config) => config.effective_status_files(),
            Err(err) => {
                error!("Loading OpenVPN status sampling API config ({err})");
                vec![]
            }
        };

        // Create the list of OpenVPN status files.
        for file in status_files.iter() {
            data.openvpn_status_files
                .push(OpenVPNStFile::new(file, cfg.tmp_dir, cfg.data_dir));
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

    fn detect_status_format(lines: &[String]) -> Option<OpenVPNStatusFormat> {
        let first_line = lines.iter().find(|line| !line.trim().is_empty())?;

        if first_line == "OpenVPN CLIENT LIST"
            && lines.iter().any(|line| line.starts_with("Updated,"))
            && lines.iter().any(|line| {
                line == "Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since"
            })
        {
            return Some(OpenVPNStatusFormat::V1);
        }

        if first_line.starts_with("TITLE,")
            && lines
                .iter()
                .any(|line| line.starts_with("HEADER,CLIENT_LIST,"))
        {
            return Some(OpenVPNStatusFormat::V2);
        }

        if first_line.starts_with("TITLE\t")
            && lines
                .iter()
                .any(|line| line.starts_with("HEADER\tCLIENT_LIST\t"))
        {
            return Some(OpenVPNStatusFormat::V3);
        }

        None
    }

    fn parse_v1_status_session(
        line: &str,
        sample_timestamp: u64,
    ) -> std::result::Result<OpenVPNStatusSession, String> {
        let mut fields = line.split(',');
        let common_name = fields
            .next()
            .ok_or_else(|| String::from("missing common name"))?;
        let real_address = fields
            .next()
            .ok_or_else(|| String::from("missing real address"))?;
        let bytes_received = fields
            .next()
            .ok_or_else(|| String::from("missing received byte counter"))?
            .parse()
            .map_err(|_| String::from("invalid received byte counter"))?;
        let bytes_sent = fields
            .next()
            .ok_or_else(|| String::from("missing sent byte counter"))?
            .parse()
            .map_err(|_| String::from("invalid sent byte counter"))?;
        let connected_since = fields
            .next()
            .and_then(OpenVPNStCollectorInner::convert_to_seconds_since_unix_epoch)
            .ok_or_else(|| String::from("invalid connected since datetime"))?;

        if fields.next().is_some() {
            return Err(String::from("unexpected client fields"));
        }

        Ok(OpenVPNStatusSession {
            common_name: common_name.to_string(),
            real_address: real_address.to_string(),
            bytes_received,
            bytes_sent,
            connected_since,
            sample_timestamp,
        })
    }

    fn parse_v1_status(
        lines: &[String],
    ) -> std::result::Result<(u64, Vec<OpenVPNStatusSession>), String> {
        let current_update = lines
            .iter()
            .find_map(|line| line.strip_prefix("Updated,"))
            .and_then(OpenVPNStCollectorInner::convert_to_seconds_since_unix_epoch)
            .ok_or_else(|| String::from("missing or invalid update timestamp"))?;
        let client_header = "Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since";
        let header_index = lines
            .iter()
            .position(|line| line == client_header)
            .ok_or_else(|| String::from("missing client list header"))?;
        let routing_table_index = lines
            .iter()
            .enumerate()
            .skip(header_index + 1)
            .find_map(|(index, line)| (line == "ROUTING TABLE").then_some(index))
            .ok_or_else(|| String::from("missing routing table header"))?;

        let sessions = lines[header_index + 1..routing_table_index]
            .iter()
            .enumerate()
            .map(|(index, line)| {
                OpenVPNStCollectorInner::parse_v1_status_session(line, current_update).map_err(
                    |err| {
                        format!(
                            "invalid client entry in line {}: {err}",
                            header_index + index + 2
                        )
                    },
                )
            })
            .collect::<std::result::Result<Vec<OpenVPNStatusSession>, String>>()?;

        Ok((current_update, sessions))
    }

    fn client_list_field<'a>(
        fields: &'a [&str],
        index: usize,
        field_name: &str,
    ) -> std::result::Result<&'a str, String> {
        fields
            .get(index + 1)
            .copied()
            .ok_or_else(|| format!("missing {field_name} field"))
    }

    fn parse_structured_status_session(
        line: &str,
        columns: &OpenVPNStatusClientListColumns,
        sample_timestamp: u64,
        delimiter: char,
    ) -> std::result::Result<OpenVPNStatusSession, String> {
        let fields = line.split(delimiter).collect::<Vec<&str>>();
        if fields.first() != Some(&"CLIENT_LIST") {
            return Err(String::from("invalid client list record"));
        }

        let common_name = OpenVPNStCollectorInner::client_list_field(
            &fields,
            columns.common_name,
            "common name",
        )?;
        let real_address = OpenVPNStCollectorInner::client_list_field(
            &fields,
            columns.real_address,
            "real address",
        )?;
        let bytes_received = OpenVPNStCollectorInner::client_list_field(
            &fields,
            columns.bytes_received,
            "received byte counter",
        )?
        .parse()
        .map_err(|_| String::from("invalid received byte counter"))?;
        let bytes_sent = OpenVPNStCollectorInner::client_list_field(
            &fields,
            columns.bytes_sent,
            "sent byte counter",
        )?
        .parse()
        .map_err(|_| String::from("invalid sent byte counter"))?;
        let connected_since_datetime = OpenVPNStCollectorInner::client_list_field(
            &fields,
            columns.connected_since,
            "connected since datetime",
        )?;
        let connected_since = columns
            .connected_since_timestamp
            .and_then(|index| {
                OpenVPNStCollectorInner::client_list_field(
                    &fields,
                    index,
                    "connected since timestamp",
                )
                .ok()
                .and_then(|value| value.parse().ok())
            })
            .or_else(|| {
                OpenVPNStCollectorInner::convert_to_seconds_since_unix_epoch(
                    connected_since_datetime,
                )
            })
            .ok_or_else(|| String::from("invalid connected since datetime"))?;

        Ok(OpenVPNStatusSession {
            common_name: common_name.to_string(),
            real_address: real_address.to_string(),
            bytes_received,
            bytes_sent,
            connected_since,
            sample_timestamp,
        })
    }

    fn parse_structured_status(
        lines: &[String],
        delimiter: char,
    ) -> std::result::Result<(u64, Vec<OpenVPNStatusSession>), String> {
        let time_prefix = format!("TIME{delimiter}");
        let client_list_header_prefix = format!("HEADER{delimiter}CLIENT_LIST{delimiter}");
        let client_list_prefix = format!("CLIENT_LIST{delimiter}");
        let current_update = lines
            .iter()
            .find_map(|line| line.strip_prefix(&time_prefix))
            .and_then(|line| {
                let fields = line.split(delimiter).collect::<Vec<&str>>();
                fields
                    .get(1)
                    .and_then(|timestamp| timestamp.parse().ok())
                    .or_else(|| {
                        fields.first().and_then(|datetime| {
                            OpenVPNStCollectorInner::convert_to_seconds_since_unix_epoch(datetime)
                        })
                    })
            })
            .ok_or_else(|| String::from("missing or invalid update timestamp"))?;
        let header_index = lines
            .iter()
            .position(|line| line.starts_with(&client_list_header_prefix))
            .ok_or_else(|| String::from("missing client list header"))?;
        let header = lines[header_index].split(delimiter).collect::<Vec<&str>>();
        let field_index = |field_name: &str| {
            header
                .iter()
                .skip(2)
                .position(|field| *field == field_name)
                .ok_or_else(|| format!("missing {field_name} column"))
        };
        let columns = OpenVPNStatusClientListColumns {
            common_name: field_index("Common Name")?,
            real_address: field_index("Real Address")?,
            bytes_received: field_index("Bytes Received")?,
            bytes_sent: field_index("Bytes Sent")?,
            connected_since: field_index("Connected Since")?,
            connected_since_timestamp: field_index("Connected Since (time_t)").ok(),
        };
        let mut sessions = vec![];

        for (index, line) in lines.iter().enumerate().skip(header_index + 1) {
            if !line.starts_with(&client_list_prefix) {
                break;
            }

            let session = OpenVPNStCollectorInner::parse_structured_status_session(
                line,
                &columns,
                current_update,
                delimiter,
            )
            .map_err(|err| format!("invalid client entry in line {}: {err}", index + 1))?;
            sessions.push(session);
        }

        Ok((current_update, sessions))
    }

    fn parse_v2_status(
        lines: &[String],
    ) -> std::result::Result<(u64, Vec<OpenVPNStatusSession>), String> {
        OpenVPNStCollectorInner::parse_structured_status(lines, ',')
    }

    fn parse_v3_status(
        lines: &[String],
    ) -> std::result::Result<(u64, Vec<OpenVPNStatusSession>), String> {
        OpenVPNStCollectorInner::parse_structured_status(lines, '\t')
    }

    fn collect_status_data(item: &mut OpenVPNStFile) -> std::io::Result<()> {
        if Path::new(&item.cache_file).is_file()
            && fs::metadata(&item.cache_file)?.len() > item.cache_max_size as u64
        {
            error!("OpenVPN status cache file for '{}' too big", item.st_file);
            return Ok(());
        }

        // Copy the current OpenVPN status data into a temporary file.
        fs::copy(&item.st_file, &item.tmp_file)?;

        // Open temporary file for reading and data file for writing.
        let f = File::open(&item.tmp_file)?;
        let reader = BufReader::new(&f);
        let lines = reader.lines().collect::<std::io::Result<Vec<String>>>()?;
        let status_format = match OpenVPNStCollectorInner::detect_status_format(&lines) {
            Some(status_format) => status_format,
            None => {
                fs::remove_file(&item.tmp_file)?;
                return Err(std::io::Error::other(
                    "Unrecognized OpenVPN status file format",
                ));
            }
        };
        let parsed_status = match status_format {
            OpenVPNStatusFormat::V1 => OpenVPNStCollectorInner::parse_v1_status(&lines),
            OpenVPNStatusFormat::V2 => OpenVPNStCollectorInner::parse_v2_status(&lines),
            OpenVPNStatusFormat::V3 => OpenVPNStCollectorInner::parse_v3_status(&lines),
        };
        let (current_update, sessions) = match parsed_status {
            Ok(parsed_status) => parsed_status,
            Err(err) => {
                fs::remove_file(&item.tmp_file)?;
                return Err(std::io::Error::other(err));
            }
        };

        // Skip the first sampling cycle, this way we avoid collect that of an OpenVPN status
        // file that doesn't change in time (for example, because the OpenVPN server is not running).
        if item.last_update == 0 {
            fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(&item.cache_file)?;
            item.last_update = current_update;
            fs::remove_file(&item.tmp_file)?;
            return Ok(());
        }

        if current_update == item.last_update {
            debug!("No new OpenVPN status data found in file: {}", item.st_file);
            fs::remove_file(&item.tmp_file)?;
            return Ok(());
        }

        let mut writer = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&item.cache_file)?;

        for session in sessions {
            writeln!(writer, "{}", session.to_cache_record())?;
        }

        // Update the last timestamp for the next iteration.
        item.last_update = current_update;

        // Remove the temporary file.
        fs::remove_file(&item.tmp_file)?;

        Ok(())
    }

    pub fn collect_all_files_data(&mut self, force: bool) {
        for item in self.openvpn_status_files.iter_mut() {
            if !force && item.seconds_until_next_sample > 0 {
                item.seconds_until_next_sample -= 1;
                if item.seconds_until_next_sample > 0 {
                    continue;
                }
            }

            debug!("Collecting OpenVPN status data from file: {}", item.st_file);
            match OpenVPNStCollectorInner::collect_status_data(item) {
                Ok(_) => {
                    item.seconds_until_next_sample = item.sampling_interval;
                }
                Err(e) => {
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

    pub fn replace_status_files(
        &mut self,
        status_files: &[OpenVPNStatusFileConfig],
        tmp_dir: &str,
        data_dir: &str,
    ) {
        self.openvpn_status_files = status_files
            .iter()
            .map(|file| OpenVPNStFile::new(file, tmp_dir, data_dir))
            .collect();
    }
}

impl OpenVPNStCollector {
    pub fn new(cfg: &Config) -> Self {
        OpenVPNStCollector {
            inner: Arc::new(Mutex::new(OpenVPNStCollectorInner::new(cfg))),
        }
    }

    pub fn replace_status_files(
        &self,
        status_files: &[OpenVPNStatusFileConfig],
        tmp_dir: &str,
        data_dir: &str,
    ) {
        self.inner
            .lock()
            .unwrap()
            .replace_status_files(status_files, tmp_dir, data_dir);
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
                    let mut force = false;
                    while rx.try_recv().unwrap_or(0) == 1 {
                        debug!("OpenVPN status data update requested");
                        force = true;
                    }

                    // Start of mutex scope.
                    {
                        debug!("Locking OpenVPN mutex (thread id: {})", thread_id::get());
                        let mutex = Arc::clone(&cfg.mutex.openvpn);
                        let _mutex_data = mutex.lock().await;
                        debug!("OpenVPN mutex locked (thread id: {})", thread_id::get());

                        // Only for debug purposes. It is useful for verify that the mutex makes its work.
                        //thread::sleep(time::Duration::from_millis(10_000));

                        let mut collector = local_self.lock().unwrap();
                        collector.collect_all_files_data(force);

                        debug!("Releasing OpenVPN mutex (thread id: {})", thread_id::get());
                    } // End of mutex scope.

                    thread::sleep(time::Duration::from_secs(1));
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
    use rand::RngExt;
    use serial_test::serial;
    use std::env;
    use uuid::Uuid;

    fn collector_factory(
        env_list: Vec<(&str, String)>,
        change_paths: bool,
    ) -> OpenVPNStCollectorInner {
        let api_config_file = OpenVPNStatusSamplingConfig::path("./etc");
        let _ = fs::remove_file(&api_config_file);

        for v in env_list.iter() {
            env::set_var(v.0, &v.1);
        }

        env::set_var("API_KEY", "d64c88318c8f213f427af857d0013f93");
        let cfg = Arc::new(Config::new().unwrap());

        for v in env_list.iter() {
            if v.0 == "OPENVPN_STATUS_FILES" {
                let status_files: Vec<String> =
                    v.1.split(',')
                        .filter(|file| !file.is_empty())
                        .map(|file| String::from(file.trim()))
                        .collect();
                let sampling_interval = env_list
                    .iter()
                    .find(|v| v.0 == "OPENVPN_STATUS_SAMPLING_INTERVAL")
                    .and_then(|v| v.1.parse::<u64>().ok())
                    .unwrap_or(DEFAULT_SAMPLING_INTERVAL);
                let request_max_lines = env_list
                    .iter()
                    .find(|v| v.0 == "OPENVPN_STATUS_REQUEST_MAX_LINES")
                    .and_then(|v| v.1.parse::<usize>().ok())
                    .unwrap_or(DEFAULT_REQUEST_MAX_LINES);
                let cache_max_size = env_list
                    .iter()
                    .find(|v| v.0 == "OPENVPN_STATUS_CACHE_MAX_SIZE")
                    .and_then(|v| v.1.parse::<usize>().ok())
                    .unwrap_or(DEFAULT_CACHE_MAX_SIZE);

                OpenVPNStatusSamplingConfig {
                    status_files: status_files
                        .into_iter()
                        .map(|path| OpenVPNStatusFileConfig {
                            path,
                            sampling_interval,
                            request_max_lines,
                            cache_max_size,
                        })
                        .collect(),
                }
                .save(cfg.etc_dir)
                .unwrap();
            }
        }

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

    fn structured_status_file(
        delimiter: char,
        update: &str,
        update_timestamp: u64,
        bytes: u64,
    ) -> String {
        let separator = delimiter.to_string();
        [
            format!("TITLE{separator}OpenVPN 2.6.0"),
            format!("TIME{separator}{update}{separator}{update_timestamp}"),
            format!("HEADER{separator}CLIENT_LIST{separator}Common Name{separator}Real Address{separator}Virtual Address{separator}Virtual IPv6 Address{separator}Bytes Received{separator}Bytes Sent{separator}Connected Since{separator}Connected Since (time_t)"),
            format!("CLIENT_LIST{separator}client{separator}1.1.1.1:1194{separator}10.0.0.2{separator}{separator}{bytes}{separator}20{separator}2023-07-21 15:01:00{separator}1689951660"),
            format!("HEADER{separator}ROUTING_TABLE{separator}Virtual Address{separator}Common Name{separator}Real Address{separator}Last Ref"),
        ]
        .join("\n")
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
    fn generates_empty_openvpn_status_file_vector_without_api_config() {
        let collector = collector_factory(vec![], false);
        assert_eq!(collector.openvpn_status_files.len(), 0);
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
            assert_eq!(
                collector.openvpn_status_files[inx].sampling_interval,
                DEFAULT_SAMPLING_INTERVAL
            );
            assert_eq!(
                collector.openvpn_status_files[inx].cache_max_size,
                DEFAULT_CACHE_MAX_SIZE
            );
        }
    }

    #[test]
    #[serial]
    fn should_apply_api_sampling_parameters_per_file() -> Result<()> {
        let api_config_file = OpenVPNStatusSamplingConfig::path("./etc");
        let _ = fs::remove_file(&api_config_file);
        env::set_var("API_KEY", "d64c88318c8f213f427af857d0013f93");
        let cfg = Arc::new(Config::new().unwrap());
        let list = status_files_list_factory(2);

        OpenVPNStatusSamplingConfig {
            status_files: vec![
                OpenVPNStatusFileConfig {
                    path: list[0].clone(),
                    sampling_interval: 10,
                    request_max_lines: 200,
                    cache_max_size: 1024,
                },
                OpenVPNStatusFileConfig {
                    path: list[1].clone(),
                    sampling_interval: 45,
                    request_max_lines: 500,
                    cache_max_size: 2097152,
                },
            ],
        }
        .save(cfg.etc_dir)?;

        let collector = OpenVPNStCollectorInner::new(&cfg);
        assert_eq!(collector.openvpn_status_files.len(), 2);
        assert_eq!(collector.openvpn_status_files[0].st_file, list[0]);
        assert_eq!(collector.openvpn_status_files[0].sampling_interval, 10);
        assert_eq!(collector.openvpn_status_files[0].cache_max_size, 1024);
        assert_eq!(collector.openvpn_status_files[1].st_file, list[1]);
        assert_eq!(collector.openvpn_status_files[1].sampling_interval, 45);
        assert_eq!(collector.openvpn_status_files[1].cache_max_size, 2097152);

        let config = OpenVPNStatusSamplingConfig::load(cfg.etc_dir)?.unwrap();
        assert_eq!(config.request_max_lines_for_path(&list[0]), 200);
        assert_eq!(config.request_max_lines_for_path(&list[1]), 500);
        assert_eq!(
            config.request_max_lines_for_path("/run/openvpn/missing.status"),
            DEFAULT_REQUEST_MAX_LINES
        );

        env::remove_var("API_KEY");
        fs::remove_file(api_config_file)?;
        Ok(())
    }

    #[test]
    #[serial]
    fn should_wait_for_file_sampling_interval() -> Result<()> {
        let list = status_files_list_factory(1);
        let mut collector = collector_factory(
            vec![
                ("OPENVPN_STATUS_SAMPLING_INTERVAL", String::from("2")),
                ("OPENVPN_STATUS_FILES", list.join(",")),
            ],
            true,
        );

        fs::copy(
            "./tests/templates/openvpn-status.log_ts1",
            &collector.openvpn_status_files[0].st_file,
        )?;
        collector.collect_all_files_data(false);
        assert_eq!(collector.openvpn_status_files[0].last_update, 1633366402);
        assert_eq!(
            collector.openvpn_status_files[0].seconds_until_next_sample,
            2
        );

        fs::copy(
            "./tests/templates/openvpn-status.log_ts2",
            &collector.openvpn_status_files[0].st_file,
        )?;
        collector.collect_all_files_data(false);
        assert_eq!(collector.openvpn_status_files[0].last_update, 1633366402);
        assert_eq!(
            collector.openvpn_status_files[0].seconds_until_next_sample,
            1
        );

        collector.collect_all_files_data(false);
        assert_eq!(collector.openvpn_status_files[0].last_update, 1633366441);
        assert_eq!(
            collector.openvpn_status_files[0].seconds_until_next_sample,
            2
        );

        remove_collector_files(&collector)?;
        Ok(())
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

        collector.collect_all_files_data(true);

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
        collector.collect_all_files_data(true);

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
        collector.collect_all_files_data(true);
        size = fs::metadata(&collector.openvpn_status_files[0].cache_file)?.len();
        assert_eq!(size, 262);
        assert_eq!(collector.openvpn_status_files[0].last_update, 1633366441);

        // Change the status file by a new one with different timestamp.
        fs::copy(
            "./tests/templates/openvpn-status.log_ts3",
            &collector.openvpn_status_files[0].st_file,
        )?;
        collector.collect_all_files_data(true);
        size = fs::metadata(&collector.openvpn_status_files[0].cache_file)?.len();
        assert_eq!(size, 524);
        assert_eq!(collector.openvpn_status_files[0].last_update, 1633366496);

        // Change the status file by a new one with lower timestamp.
        fs::copy(
            "./tests/templates/openvpn-status.log_ts1",
            &collector.openvpn_status_files[0].st_file,
        )?;
        collector.collect_all_files_data(true);
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
        collector.collect_all_files_data(true);

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
        collector.collect_all_files_data(true);
        size = fs::metadata(&collector.openvpn_status_files[0].cache_file)?.len();
        assert_eq!(size, 262);
        assert_eq!(collector.openvpn_status_files[0].last_update, 1633366441);

        // Don't change OpenVPN status log file, then timestamp is the same.
        collector.collect_all_files_data(true);
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
        collector.collect_all_files_data(true);
        let mut size = fs::metadata(&collector.openvpn_status_files[0].cache_file)?.len();
        assert_eq!(size, 0);
        assert_eq!(collector.openvpn_status_files[0].last_update, 1633366402);

        fs::copy(
            "./tests/templates/openvpn-status.log_ts2",
            &collector.openvpn_status_files[0].st_file,
        )?;
        collector.collect_all_files_data(true);
        size = fs::metadata(&collector.openvpn_status_files[0].cache_file)?.len();
        assert_eq!(size, 262);
        assert_eq!(collector.openvpn_status_files[0].last_update, 1633366441);

        fs::copy(
            "./tests/templates/openvpn-status.log_ts3",
            &collector.openvpn_status_files[0].st_file,
        )?;
        collector.collect_all_files_data(true);
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

    #[test]
    fn should_detect_openvpn_status_file_formats() {
        let v1 = vec![
            String::from("OpenVPN CLIENT LIST"),
            String::from("Updated,2026-08-10 10:00:00"),
            String::from("Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since"),
        ];
        let v2 = vec![
            String::from("TITLE,OpenVPN 2.6.0"),
            String::from("HEADER,CLIENT_LIST,Common Name,Real Address"),
        ];
        let v3 = vec![
            String::from("TITLE\tOpenVPN 2.6.0"),
            String::from("HEADER\tCLIENT_LIST\tCommon Name\tReal Address"),
        ];

        assert_eq!(
            OpenVPNStCollectorInner::detect_status_format(&v1),
            Some(OpenVPNStatusFormat::V1)
        );
        assert_eq!(
            OpenVPNStCollectorInner::detect_status_format(&v2),
            Some(OpenVPNStatusFormat::V2)
        );
        assert_eq!(
            OpenVPNStCollectorInner::detect_status_format(&v3),
            Some(OpenVPNStatusFormat::V3)
        );
    }

    #[test]
    fn should_reject_unrecognized_openvpn_status_file_format() {
        assert_eq!(
            OpenVPNStCollectorInner::detect_status_format(&[String::from("invalid")]),
            None
        );
    }

    #[test]
    fn should_parse_v1_status_file() -> Result<()> {
        let lines = fs::read_to_string("./tests/templates/openvpn-status.log_ts1")?
            .lines()
            .map(String::from)
            .collect::<Vec<String>>();

        let (sample_timestamp, sessions) =
            OpenVPNStCollectorInner::parse_v1_status(&lines).map_err(std::io::Error::other)?;

        assert_eq!(sample_timestamp, 1633366402);
        assert_eq!(sessions.len(), 4);
        assert_eq!(sessions[0].common_name, "FWCLOD-VPN-01");
        assert_eq!(sessions[0].real_address, "1.1.1.1:43501");
        assert_eq!(sessions[0].bytes_received, 22394454);
        assert_eq!(sessions[0].bytes_sent, 22553788);
        assert_eq!(sessions[0].connected_since, 1632487691);
        assert_eq!(sessions[0].sample_timestamp, sample_timestamp);

        Ok(())
    }

    #[test]
    fn should_parse_v1_status_file_with_new_datetime_format() {
        let lines = vec![
            String::from("OpenVPN CLIENT LIST"),
            String::from("Updated,2023-07-21 15:02:00"),
            String::from("Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since"),
            String::from("client,1.1.1.1:1194,10,20,2023-07-21 15:02:00"),
            String::from("ROUTING TABLE"),
        ];

        let (sample_timestamp, sessions) =
            OpenVPNStCollectorInner::parse_v1_status(&lines).unwrap();

        assert_eq!(sample_timestamp, 1689951720);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].connected_since, 1689951720);
    }

    #[test]
    fn should_parse_v2_status_file() {
        let lines = vec![
            String::from("TITLE,OpenVPN 2.6.0"),
            String::from("TIME,2023-07-21 15:02:00,1689951720"),
            String::from("HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,Client ID,Peer ID,Data Channel Cipher"),
            String::from("CLIENT_LIST,client,1.1.1.1:1194,10.0.0.2,,10,20,2023-07-21 15:01:00,1689951660,user,1,2,AES-256-GCM"),
            String::from("HEADER,ROUTING_TABLE,Virtual Address,Common Name,Real Address,Last Ref"),
        ];

        let (sample_timestamp, sessions) =
            OpenVPNStCollectorInner::parse_v2_status(&lines).unwrap();

        assert_eq!(sample_timestamp, 1689951720);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].common_name, "client");
        assert_eq!(sessions[0].real_address, "1.1.1.1:1194");
        assert_eq!(sessions[0].bytes_received, 10);
        assert_eq!(sessions[0].bytes_sent, 20);
        assert_eq!(sessions[0].connected_since, 1689951660);
    }

    #[test]
    fn should_parse_v3_status_file() {
        let lines = vec![
            String::from("TITLE\tOpenVPN 2.6.0"),
            String::from("TIME\t2023-07-21 15:02:00\t1689951720"),
            String::from("HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)\tUsername\tClient ID\tPeer ID\tData Channel Cipher"),
            String::from("CLIENT_LIST\tclient\t1.1.1.1:1194\t10.0.0.2\t\t10\t20\t2023-07-21 15:01:00\t1689951660\tuser\t1\t2\tAES-256-GCM"),
            String::from("HEADER\tROUTING_TABLE\tVirtual Address\tCommon Name\tReal Address\tLast Ref"),
        ];

        let (sample_timestamp, sessions) =
            OpenVPNStCollectorInner::parse_v3_status(&lines).unwrap();

        assert_eq!(sample_timestamp, 1689951720);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].common_name, "client");
        assert_eq!(sessions[0].real_address, "1.1.1.1:1194");
        assert_eq!(sessions[0].bytes_received, 10);
        assert_eq!(sessions[0].bytes_sent, 20);
        assert_eq!(sessions[0].connected_since, 1689951660);
    }

    #[test]
    fn should_normalize_all_status_formats_to_the_same_cache_record() {
        let v1 = vec![
            String::from("OpenVPN CLIENT LIST"),
            String::from("Updated,2023-07-21 15:02:00"),
            String::from("Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since"),
            String::from("client,1.1.1.1:1194,10,20,2023-07-21 15:01:00"),
            String::from("ROUTING TABLE"),
        ];
        let v2 = vec![
            String::from("TITLE,OpenVPN 2.6.0"),
            String::from("TIME,2023-07-21 15:02:00,1689951720"),
            String::from("HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t)"),
            String::from("CLIENT_LIST,client,1.1.1.1:1194,10.0.0.2,,10,20,2023-07-21 15:01:00,1689951660"),
            String::from("HEADER,ROUTING_TABLE,Virtual Address,Common Name,Real Address,Last Ref"),
        ];
        let v3 = vec![
            String::from("TITLE\tOpenVPN 2.6.0"),
            String::from("TIME\t2023-07-21 15:02:00\t1689951720"),
            String::from("HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)"),
            String::from("CLIENT_LIST\tclient\t1.1.1.1:1194\t10.0.0.2\t\t10\t20\t2023-07-21 15:01:00\t1689951660"),
            String::from("HEADER\tROUTING_TABLE\tVirtual Address\tCommon Name\tReal Address\tLast Ref"),
        ];

        let (_, v1_sessions) = OpenVPNStCollectorInner::parse_v1_status(&v1).unwrap();
        let (_, v2_sessions) = OpenVPNStCollectorInner::parse_v2_status(&v2).unwrap();
        let (_, v3_sessions) = OpenVPNStCollectorInner::parse_v3_status(&v3).unwrap();

        assert_eq!(v1_sessions, v2_sessions);
        assert_eq!(v2_sessions, v3_sessions);
        assert_eq!(
            v1_sessions[0].to_cache_record(),
            "1689951720,client,1.1.1.1:1194,10,20,1689951660"
        );
    }

    #[test]
    fn should_parse_structured_status_samples() {
        let v2 = structured_status_file(',', "2023-07-21 15:02:00", 1689951720, 22394454)
            .lines()
            .map(String::from)
            .collect::<Vec<String>>();
        let v3 = structured_status_file('\t', "2023-07-21 15:02:00", 1689951720, 22394454)
            .lines()
            .map(String::from)
            .collect::<Vec<String>>();

        let (_, v2_sessions) = OpenVPNStCollectorInner::parse_v2_status(&v2).unwrap();
        let (_, v3_sessions) = OpenVPNStCollectorInner::parse_v3_status(&v3).unwrap();

        assert_eq!(v2_sessions, v3_sessions);
        assert_eq!(
            v2_sessions[0].to_cache_record(),
            "1689951720,client,1.1.1.1:1194,22394454,20,1689951660"
        );
    }

    #[test]
    fn should_parse_structured_status_with_reordered_extended_columns() {
        for delimiter in [',', '\t'] {
            let separator = delimiter.to_string();
            let lines = vec![
                format!("TITLE{separator}OpenVPN 2.6.0"),
                format!("TIME{separator}2023-07-21 15:02:00{separator}1689951720"),
                format!("HEADER{separator}CLIENT_LIST{separator}Username{separator}Bytes Sent{separator}Common Name{separator}Connected Since (time_t){separator}Real Address{separator}Bytes Received{separator}Connected Since{separator}Peer ID{separator}Data Channel Cipher"),
                format!("CLIENT_LIST{separator}fwcloud{separator}20{separator}client{separator}1689951660{separator}1.1.1.1:1194{separator}10{separator}2023-07-21 15:01:00{separator}2{separator}AES-256-GCM"),
                format!("HEADER{separator}ROUTING_TABLE{separator}Virtual Address"),
            ];

            let (_, sessions) =
                OpenVPNStCollectorInner::parse_structured_status(&lines, delimiter).unwrap();

            assert_eq!(sessions.len(), 1);
            assert_eq!(sessions[0].common_name, "client");
            assert_eq!(sessions[0].real_address, "1.1.1.1:1194");
            assert_eq!(sessions[0].bytes_received, 10);
            assert_eq!(sessions[0].bytes_sent, 20);
            assert_eq!(sessions[0].connected_since, 1689951660);
        }
    }

    #[test]
    #[serial]
    fn should_preserve_sampling_semantics_for_structured_status_formats() -> Result<()> {
        for delimiter in [',', '\t'] {
            let list = status_files_list_factory(1);
            let mut collector = collector_factory(
                vec![
                    ("OPENVPN_STATUS_CACHE_MAX_SIZE", String::from("1")),
                    ("OPENVPN_STATUS_FILES", list.join(",")),
                ],
                true,
            );
            let status_file = collector.openvpn_status_files[0].st_file.clone();
            let cache_file = collector.openvpn_status_files[0].cache_file.clone();

            fs::write(
                &status_file,
                structured_status_file(delimiter, "2023-07-21 15:02:00", 1689951720, 10),
            )?;
            collector.collect_all_files_data(true);
            assert_eq!(fs::metadata(&cache_file)?.len(), 0);
            assert_eq!(collector.openvpn_status_files[0].last_update, 1689951720);

            fs::write(
                &status_file,
                structured_status_file(delimiter, "2023-07-21 15:03:00", 1689951780, 30),
            )?;
            collector.collect_all_files_data(true);
            let cached_status = fs::read_to_string(&cache_file)?;
            assert_eq!(
                cached_status,
                "1689951780,client,1.1.1.1:1194,30,20,1689951660\n"
            );
            assert_eq!(collector.openvpn_status_files[0].last_update, 1689951780);

            collector.collect_all_files_data(true);
            assert_eq!(fs::read_to_string(&cache_file)?, cached_status);

            fs::write(
                &status_file,
                structured_status_file(delimiter, "2023-07-21 15:04:00", 1689951840, 50),
            )?;
            collector.collect_all_files_data(true);
            assert_eq!(fs::read_to_string(&cache_file)?, cached_status);
            assert_eq!(collector.openvpn_status_files[0].last_update, 1689951780);

            remove_collector_files(&collector)?;
        }

        Ok(())
    }

    #[test]
    #[serial]
    fn should_not_write_partial_cache_for_malformed_structured_status_files() -> Result<()> {
        for delimiter in [',', '\t'] {
            let list = status_files_list_factory(1);
            let mut collector =
                collector_factory(vec![("OPENVPN_STATUS_FILES", list.join(","))], true);
            let status_file = collector.openvpn_status_files[0].st_file.clone();
            let tmp_file = collector.openvpn_status_files[0].tmp_file.clone();
            let cache_file = collector.openvpn_status_files[0].cache_file.clone();

            fs::write(
                &status_file,
                structured_status_file(delimiter, "2023-07-21 15:02:00", 1689951720, 22394454),
            )?;
            collector.collect_all_files_data(true);
            assert_eq!(collector.openvpn_status_files[0].last_update, 1689951720);

            let malformed_status =
                structured_status_file(delimiter, "2023-07-21 15:03:00", 1689951780, 22394454)
                    .replace("22394454", "invalid");
            fs::write(&status_file, malformed_status)?;
            collector.collect_all_files_data(true);

            assert_eq!(fs::metadata(&cache_file)?.len(), 0);
            assert_eq!(collector.openvpn_status_files[0].last_update, 1689951720);
            assert!(!Path::new(&tmp_file).is_file());

            remove_collector_files(&collector)?;
        }

        Ok(())
    }
}
