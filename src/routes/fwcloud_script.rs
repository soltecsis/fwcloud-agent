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

use std::sync::Arc;
use actix_web::{get, post, HttpResponse, Responder, web, Error};
use actix_multipart::Multipart;
use rand::Rng;

use crate::config::Config;
use crate::utils::http_files::HttpFiles;

#[get("/cpu_stress")]
pub async fn cpu_stress() -> impl Responder {
    // Creates an array of 10000000 random integers in the range 0 - 1000000000
    //let mut array: [i32; 10000000] = [0; 10000000];
    let n = 10_000_000;
    let mut array = Vec::new();

    // Fill the array
    let mut rng = rand::thread_rng();
    for _ in 0..n {
        //array[i] = rng.gen::<i32>();
        array.push(rng.gen::<i32>());
    }

    // Sort
    array.sort();
    
    HttpResponse::Ok().body("Done!")
}

#[post("/upload")]
pub async fn upload_and_run(payload: Multipart, cfg: web::Data<Arc<Config>>) -> Result<HttpResponse, Error> {
  HttpFiles::new(cfg.tmp_dir.clone()).process(payload).await?;
  Ok(HttpResponse::Ok().finish())
}

