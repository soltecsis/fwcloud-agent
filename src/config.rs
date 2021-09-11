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
use serde::Deserialize;
use regex::Regex;

use crate::errors::Result;

// A trait that the Validate derive will impl
use validator::Validate;

lazy_static! {
  static ref IPV4: Regex = Regex::new("^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})){3}$").unwrap();
  static ref IPV4_LIST: Regex = Regex::new("^(((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})){3})( ?))*$").unwrap();

  static ref IPV6: Regex = Regex::new("(^\\d{20}$)|(^((:[a-fA-F0-9]{1,4}){6}|::)ffff:(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})){3}$)|(^((:[a-fA-F0-9]{1,4}){6}|::)ffff(:[a-fA-F0-9]{1,4}){2}$)|(^([a-fA-F0-9]{1,4}) (:[a-fA-F0-9]{1,4}){7}$)|(^:(:[a-fA-F0-9]{1,4}(::)?){1,6}$)|(^((::)?[a-fA-F0-9]{1,4}:){1,6}:$)|(^::$)").unwrap();
  static ref IPV6_LIST: Regex = Regex::new("(((^\\d{20}$)|(^((:[a-fA-F0-9]{1,4}){6}|::)ffff:(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})){3}$)|(^((:[a-fA-F0-9]{1,4}){6}|::)ffff(:[a-fA-F0-9]{1,4}){2}$)|(^([a-fA-F0-9]{1,4}) (:[a-fA-F0-9]{1,4}){7}$)|(^:(:[a-fA-F0-9]{1,4}(::)?){1,6}$)|(^((::)?[a-fA-F0-9]{1,4}:){1,6}:$)|(^::$))(,\\n|,?)))*$").unwrap();
  
  static ref ALPHA_NUM: Regex = Regex::new("^[a-zA-Z0-9]*$").unwrap();
  static ref ALPHA_NUM_2: Regex = Regex::new("^[a-zA-Z0-9\\-_]*$").unwrap();
}

#[derive(Validate, Deserialize)]
pub struct Config {
  #[validate(regex(path = "IPV4", message = "Bad IPv4 address"))]
  bind_ip: String,
  #[validate(range(min = 1, max = 65535))]
  bind_port: u16,
  #[validate(range(min = 1, max = 65535))]
  pub workers: usize,
  #[validate(regex(path = "IPV4_LIST", message = "Bad IPv4 address list"))]
  allowed_ips_list: String,
  pub allowed_ips: Vec<String>,

  #[validate(regex = "ALPHA_NUM_2")]
  #[validate(length(min = 16, max = 128))]
  pub api_key: String,

  pub tmp_dir: String
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
      
      allowed_ips_list: env::var("ALLOWED_IPS").unwrap_or(String::from("")),
      allowed_ips: vec![],
      
      api_key: env::var("API_KEY").unwrap_or(String::from("")),
      tmp_dir: "./tmp/".to_string()
    };

    cfg.validate()?;
    
    // Create list of allowed IPs.
    if cfg.allowed_ips_list.len() > 1 {
      let ips: Vec<&str> = cfg.allowed_ips_list.split(" ").collect();
      for ip in ips.into_iter() {
        cfg.allowed_ips.push(String::from(ip));
      }  
    }
    
    // Create temporary directory if it doesn't exists.
    fs::create_dir_all(&cfg.tmp_dir)?;

    Ok(cfg)
  }

  pub fn bind_to(&self) -> String {
    format!("{}:{}",self.bind_ip,self.bind_port)
  }
}