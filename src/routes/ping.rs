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
use actix_web::{put, HttpResponse, Responder};

/* 
  curl -k -i -X PUT -H 'X-API-Key: **************************' https://localhost:33033/api/v1/ping
*/
#[put("/ping")]
async fn ping() -> impl Responder {
    HttpResponse::Ok().finish()
}


#[cfg(test)]
mod tests {
    use actix_web::{test, App};

    use super::*;

    #[actix_web::test]
    async fn put_ping() {
      let app = test::init_service(
        App::new()
        .service(ping)
      ).await;
      
      let req = test::TestRequest::put()
        .uri("/ping")
        .to_request();
      let resp = test::call_service(&app, req).await;      
      assert!(resp.status().is_success());
  }
}