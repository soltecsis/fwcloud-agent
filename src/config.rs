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

use crate::errors::FwcError;

// A trait that the Validate derive will impl
use validator::{Validate};

lazy_static! {
  static ref IPV4: Regex = Regex::new("^(?:[0-9]{1,3}.){3}[0-9]{1,3}$").unwrap();
}

#[derive(Validate, Deserialize)]
pub struct Config {
  #[validate(regex = "IPV4")]
  bind_ip: String,
  #[validate(range(min = 1, max = 65535))]
  bind_port: u16,
  #[validate(range(min = 1, max = 65535))]
  pub workers: usize,

  pub tmp_dir: String
}

impl Config {
  pub fn new() -> Result<Self, FwcError> {
    dotenv::dotenv().ok();
    
    // Amount of cores available.
    let cpus = num_cpus::get();

    let cfg = Config {
      bind_ip: env::var("BIND_IP").unwrap_or("127.0.0.1".to_string()),
      bind_port: env::var("BIND_PORT").unwrap_or("33033".to_string()).parse::<u16>().unwrap_or(33033),
      workers: env::var("WORKERS").unwrap_or(cpus.to_string()).parse::<usize>().unwrap_or(cpus),
      tmp_dir: "./tmp/".to_string()
    };

    cfg.validate()?;
    
    // Create temporary directory if it doesn't exists.
    fs::create_dir_all(&cfg.tmp_dir)?;

    Ok(cfg)
  }

  pub fn bind_to(&self) -> String {
    format!("{}:{}",self.bind_ip,self.bind_port)
  }
}