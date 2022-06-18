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

use std::sync::Arc;

use actix_web::{post, HttpResponse, web};
use log::debug;
use validator::Validate;
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::utils::cmd::run_cmd;

use crate::errors::Result;

#[derive(Deserialize,Serialize)]
#[derive(Validate)]
struct Plugin {
    #[validate(regex(path = "crate::utils::myregex::PLUGINS_NAMES", message = "Invalid plugin name"))]
    name: String,
    #[validate(regex(path = "crate::utils::myregex::PLUGINS_ACTIONS", message = "Invalid plugin action"))]
    action: String
}

/* 
  curl -k -i -X POST -H 'X-API-Key: **************************' \
    -H "Content-Type: application/json" \
    -d '{"name":"openvpn", "action":"enable"}' \
    https://localhost:33033/api/v1/plugin
*/
#[post("/plugin")]
async fn plugin(plugin: web::Json<Plugin>, cfg: web::Data<Arc<Config>>) -> Result<HttpResponse> {
  // Validate input.
  plugin.validate()?;

  debug!("Locking FWCloud plugins mutex (thread id: {}) ...", thread_id::get());
  let mutex = Arc::clone(&cfg.mutex.plugins);
  let mutex_data = mutex.lock().unwrap();
  debug!("FWCloud plugins mutex locked (thread id: {})!", thread_id::get());

  let res = run_cmd("sh", &[format!("{}/{}/{}.sh",cfg.plugins_dir,plugin.name,plugin.name).as_str(), plugin.action.as_str()])?;

  debug!("Unlocking FWCloud plugins mutex (thread id: {}) ...", thread_id::get());
  drop(mutex_data);
  debug!("FWCloud plugins mutex unlocked (thread id: {})!", thread_id::get());

  Ok(res)
}


#[cfg(test)]
mod tests {
  use actix_web::{test, App, dev::ServiceResponse, test::TestRequest};

  use super::*;

  async fn send_request(req: TestRequest) -> ServiceResponse {
    let cfg = Arc::new(Config::new().unwrap());

    let app = test::init_service(
      App::new()
          .app_data(web::Data::new(cfg.clone()))
          .service(plugin)
    ).await;

    test::call_service(&app, req.to_request()).await
  }


  #[actix_web::test]
  async fn post_plugin_without_data() {
    let req = test::TestRequest::post()
        .uri("/plugin");

    let res = send_request(req).await;
    assert_eq!(res.status().as_u16(), 400);
  }
  

  #[actix_web::test]
  async fn post_plugin_with_valid_data() {
    let req = test::TestRequest::post()
      .uri("/plugin")
      .set_json(Plugin { name : String::from("openvpn"), action: String::from("enable") });

    let res = send_request(req).await;
    assert_eq!(res.status().as_u16(), 200);
  }


  #[actix_web::test]
  async fn post_plugin_with_invalid_action() {
    let req = test::TestRequest::post()
      .uri("/plugin")
      .set_json(Plugin { name : String::from("openvpn"), action: String::from("invalid_action") });

    let res = send_request(req).await;
    assert_eq!(res.status().as_u16(), 400);
    
    // Verify the text in the body answer.
    let body = res.into_body();
    assert_eq!("test", "test");
  }


  #[actix_web::test]
  async fn post_plugin_with_bad_data() {
    #[derive(Serialize)]
    struct BadData {
      field1: String
    }

    let req = test::TestRequest::post()
      .uri("/plugin")
      .set_json(BadData { field1 : String::from("test")});

    let res = send_request(req).await;
    assert_eq!(res.status().as_u16(), 400);
  }
}