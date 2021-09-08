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

#[macro_use]
extern crate lazy_static;

mod errors;
mod config;
mod auth;
mod routes;
mod utils;

use std::sync::Arc;

use config::Config;
use actix_web::{App, HttpServer, middleware};
use actix_web_requestid::{RequestIDService};
use env_logger::Env;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let cfg = Arc::new(Config::new().unwrap());
    let workers = cfg.workers;
    let bind_to = cfg.bind_to();
    
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    HttpServer::new(move || {
        App::new()
            .data(cfg.clone())
            .wrap(RequestIDService::default())
            .wrap(middleware::Logger::default())
            .wrap(auth::Auth)
            .configure(routes::routes_setup)
    })
    .workers(workers)
    .bind(bind_to)?
    .run()
    .await
}
