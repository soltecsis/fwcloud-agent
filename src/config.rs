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
extern crate num_cpus;

use rand::{distributions::Alphanumeric, Rng};
use std::env;
use std::fs;
use std::net::TcpListener;
use std::sync::Arc;

use crate::errors::Result;

use async_mutex::Mutex;

// A trait that the Validate derive will impl
use validator::Validate;

pub struct MyMutex {
    pub openvpn: Arc<Mutex<u8>>,
    pub fwcloud_script: Arc<Mutex<u8>>,
    pub plugins: Arc<Mutex<u8>>,
}

#[derive(Validate)]
pub struct Config {
    pub etc_dir: &'static str,
    pub tmp_dir: &'static str,
    pub data_dir: &'static str,
    pub plugins_dir: &'static str,

    pub enable_env_logger: bool,

    #[validate(regex(path = "crate::utils::myregex::IPV4", message = "Bad IPv4 address"))]
    pub bind_ip: String,

    #[validate(range(min = 1, max = 65535))]
    pub bind_port: u16,

    #[validate(range(min = 1, max = 65535))]
    pub workers: usize,

    pub enable_tls: bool,

    #[validate(regex(
        path = "crate::utils::myregex::IPV4_LIST",
        message = "Bad IPv4 address list"
    ))]
    pub allowed_ips_list: String,
    pub allowed_ips: Vec<String>,

    pub enable_api_key: bool,

    #[validate(regex = "crate::utils::myregex::ALPHA_NUM_2")]
    #[validate(length(min = 16, max = 128))]
    pub api_key: String,

    #[validate(regex(
        path = "crate::utils::myregex::ABSOLUTE_PATH_LIST",
        message = "Bad absolute path file names in FWCLOUD_SCRIPT_PATHS"
    ))]
    fwcloud_script_paths_list: String,
    pub fwcloud_script_paths: Vec<String>,

    #[validate(regex(
        path = "crate::utils::myregex::ABSOLUTE_PATH_LIST",
        message = "Bad absolute path file names in OPENVPN_STATUS_FILES"
    ))]
    openvpn_status_files_list: String,
    pub openvpn_status_files: Vec<String>,

    #[validate(range(min = 1))]
    pub openvpn_status_sampling_interval: u64,

    #[validate(range(min = 1, max = 10_000))]
    pub openvpn_status_request_max_lines: usize,

    #[validate(range(min = 1))]
    pub openvpn_status_cache_max_size: usize,

    pub mutex: MyMutex,
}

impl Config {
    pub fn new() -> Result<Self> {
        dotenv::dotenv().ok();

        // Amount of cores available.
        let cpus = num_cpus::get();

        let mut cfg = Config {
            etc_dir: "./etc",
            tmp_dir: "./tmp",
            data_dir: "./data",
            plugins_dir: "./plugins",

            enable_env_logger: true,

            bind_ip: env::var("BIND_IP").unwrap_or_else(|_| String::from("0.0.0.0")),
            bind_port: env::var("BIND_PORT")
                .unwrap_or_else(|_| String::from("33033"))
                .parse::<u16>()
                .unwrap_or(33033),
            workers: env::var("WORKERS")
                .unwrap_or_else(|_| cpus.to_string())
                .parse::<usize>()
                .unwrap_or(cpus),
            enable_tls: env::var("ENABLE_SSL")
                .unwrap_or_else(|_| String::from("true"))
                .parse::<bool>()
                .unwrap_or(true),

            allowed_ips_list: env::var("ALLOWED_IPS").unwrap_or_else(|_| String::from("")),
            allowed_ips: vec![],

            enable_api_key: env::var("ENABLE_API_KEY")
                .unwrap_or_else(|_| String::from("true"))
                .parse::<bool>()
                .unwrap_or(true),
            api_key: env::var("API_KEY").unwrap_or_else(|_| {
                rand::thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(64)
                    .map(char::from)
                    .collect()
            }),

            fwcloud_script_paths_list: env::var("FWCLOUD_SCRIPT_PATHS").unwrap_or_else(|_| {
                String::from("/etc/fwcloud/fwcloud.sh,/config/scripts/post-config.d/fwcloud.sh")
            }),
            fwcloud_script_paths: vec![],

            openvpn_status_files_list: env::var("OPENVPN_STATUS_FILES")
                .unwrap_or_else(|_| String::from("/etc/openvpn/openvpn-status.log")),
            openvpn_status_files: vec![],
            openvpn_status_sampling_interval: env::var("OPENVPN_STATUS_SAMPLING_INTERVAL")
                .unwrap_or_else(|_| String::from("30"))
                .parse::<u64>()
                .unwrap_or(30),
            openvpn_status_request_max_lines: env::var("OPENVPN_STATUS_REQUEST_MAX_LINES")
                .unwrap_or_else(|_| String::from("1000"))
                .parse::<usize>()
                .unwrap_or(1000),
            openvpn_status_cache_max_size: env::var("OPENVPN_STATUS_CACHE_MAX_SIZE")
                .unwrap_or_else(|_| String::from("10_485_760"))
                .parse::<usize>()
                .unwrap_or(10_485_760),

            mutex: MyMutex {
                openvpn: Arc::new(Mutex::new(0)),
                fwcloud_script: Arc::new(Mutex::new(0)),
                plugins: Arc::new(Mutex::new(0)),
            },
        };

        cfg.validate()?;

        // Create the list of allowed IPs.
        for ip in cfg.allowed_ips_list.split(' ').filter(|&x| !x.is_empty()) {
            cfg.allowed_ips.push(String::from(ip));
        }

        for file in cfg
            .fwcloud_script_paths_list
            .split(',')
            .filter(|&x| !x.is_empty())
        {
            cfg.fwcloud_script_paths.push(String::from(file.trim()));
        }

        for file in cfg
            .openvpn_status_files_list
            .split(',')
            .filter(|&x| !x.is_empty())
        {
            cfg.openvpn_status_files.push(String::from(file.trim()));
        }

        // Create config and temporary directories if don't exist.
        fs::create_dir_all(cfg.etc_dir)?;
        fs::create_dir_all(cfg.tmp_dir)?;
        fs::create_dir_all(cfg.data_dir)?;

        Ok(cfg)
    }

    pub fn bind_to(&mut self) -> TcpListener {
        let addr = format!("{}:{}", self.bind_ip, self.bind_port);
        let listener = TcpListener::bind(addr)
            .unwrap_or_else(|_| panic!("Error binding to {}:{}", self.bind_ip, self.bind_port));

        // If we want listen to a random TCP port, update the bind_port with the random one supplied by the operative system.
        if self.bind_port == 0 {
            self.bind_port = listener.local_addr().unwrap().port();
        }

        listener
    }
}
