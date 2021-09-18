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
extern crate num_cpus;

use std::env;
use std::fs;
use std::sync::Arc;

use crate::errors::Result;

use std::sync::Mutex;
// A trait that the Validate derive will impl
use validator::Validate;

pub struct MyMutex {
  pub openvpn: Arc<Mutex<u8>>,
  pub fwcloud_script: Arc<Mutex<u8>>
}

#[derive(Validate)]
pub struct Config {
  #[validate(regex(path = "crate::utils::myregex::IPV4", message = "Bad IPv4 address"))]
  bind_ip: String,

  #[validate(range(min = 1, max = 65535))]
  bind_port: u16,

  #[validate(range(min = 1, max = 65535))]
  pub workers: usize,

  pub enable_tls: bool,

  #[validate(regex(path = "crate::utils::myregex::IPV4_LIST", message = "Bad IPv4 address list"))]
  allowed_ips_list: String,
  
  pub allowed_ips: Vec<String>,

  #[validate(regex = "crate::utils::myregex::ALPHA_NUM_2")]
  #[validate(length(min = 16, max = 128))]
  pub api_key: String,

  pub etc_dir: String,
  pub tmp_dir: String,

  pub mutex: MyMutex
}

impl Config {
  pub fn new() -> Result<Self> {
    dotenv::dotenv().ok();
    
    // Amount of cores available.
    let cpus = num_cpus::get();

    let mut cfg = Config {
      bind_ip: env::var("BIND_IP").unwrap_or(String::from("0.0.0.0")),
      bind_port: env::var("BIND_PORT").unwrap_or(String::from("33033")).parse::<u16>().unwrap_or(33033),
      workers: env::var("WORKERS").unwrap_or(cpus.to_string()).parse::<usize>().unwrap_or(cpus),
      enable_tls: env::var("ENABLE_SSL").unwrap_or(String::from("true")).parse::<bool>().unwrap_or(true),
      
      allowed_ips_list: env::var("ALLOWED_IPS").unwrap_or(String::from("")),
      allowed_ips: vec![],
      
      api_key: env::var("API_KEY").unwrap_or(String::from("")),
      etc_dir: "./etc/".to_string(),
      tmp_dir: "./tmp/".to_string(),

      mutex: MyMutex {
        openvpn: Arc::new(Mutex::new(0)),
        fwcloud_script: Arc::new(Mutex::new(0))
      }
    };

    cfg.validate()?;
 
    // Create list of allowed IPs.
    if cfg.allowed_ips_list.len() > 1 {
      let ips: Vec<&str> = cfg.allowed_ips_list.split(" ").collect();
      for ip in ips.into_iter() {
        cfg.allowed_ips.push(String::from(ip));
      }  
    }
    
    // Create config and temporary directories if don't exist.
    fs::create_dir_all(&cfg.etc_dir)?;
    fs::create_dir_all(&cfg.tmp_dir)?;

    Ok(cfg)
  }

  pub fn bind_to(&self) -> String {
    format!("{}:{}",self.bind_ip,self.bind_port)
  }
}