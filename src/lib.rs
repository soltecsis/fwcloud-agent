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

#[macro_use]
extern crate lazy_static;

mod errors;
mod config;
mod auth;
mod routes;
mod utils;
mod workers;

use log::{info, warn};
use std::sync::Arc;
use actix_web::{App, HttpServer, middleware, web, dev::Server};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use env_logger::Env;

use config::Config;
use crate::workers::{ WorkersChannels, openvpn_status_collector::OpenVPNStCollector};

pub fn run() -> Result<Server, std::io::Error> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    info!("Starting fwcloud-agent application");

    let cfg = Arc::new(Config::new().unwrap());
    let cfg_main_thread = cfg.clone();

    // Start workers threads.
    let workers_channels = WorkersChannels {
        openvpn_st_collector: OpenVPNStCollector::new(&cfg).start(cfg.clone())
    };

    let server = HttpServer::new( move || {
        App::new()
            .app_data(web::Data::new(cfg.clone()))
            .app_data(web::Data::new(workers_channels.clone()))
            .wrap(middleware::Logger::default())
            .wrap(auth::Authorize)
            .configure(routes::routes_setup)
    })
    .workers(cfg_main_thread.workers);
    
    if cfg_main_thread.enable_tls { 
        info!("Using secure communications (https)");
        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        builder.set_private_key_file(format!("{}/key.pem",cfg_main_thread.etc_dir), SslFiletype::PEM).unwrap();
        builder.set_certificate_chain_file(format!("{}/cert.pem",cfg_main_thread.etc_dir)).unwrap();
        
        Ok(server.bind_openssl(cfg_main_thread.bind_to(), builder)?.run())
    }
    else { 
        warn!("Insecure communications (http) not recommended in production");
        Ok(server.bind(cfg_main_thread.bind_to())?.run())
    }
}
