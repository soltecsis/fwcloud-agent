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

mod common;

#[tokio::test]
async fn auth_error_no_api_key() {
  let cfg_opt = common::TestCfgOpt {
    enable_api_key: true,
    api_key: common::random_api_key(64),
    allowed_ips: vec![]
  };

  let url = format!("{}/api/v1/ping", common::spawn_app(Some(cfg_opt)));

  let res = reqwest::Client::new()
    .put(url)
    .send()
    .await
    .unwrap();

  assert_eq!(res.status().as_u16(), 403);
  let body = res.text().await.unwrap();
  assert_eq!(body, "{\"message\":\"API key not found\"}");
}


#[tokio::test]
async fn auth_invalid_api_key() {
  let cfg_opt = common::TestCfgOpt {
    enable_api_key: true,
    api_key: common::random_api_key(64),
    allowed_ips: vec![]
  };

  let url = format!("{}/api/v1/ping", common::spawn_app(Some(cfg_opt)));

  let res = reqwest::Client::new()
    .put(url)
    .header("X-API-Key", "1234567812345678")
    .send()
    .await
    .unwrap();

  assert_eq!(res.status().as_u16(), 403);
  let body = res.text().await.unwrap();
  assert_eq!(body, "{\"message\":\"Invalid API key\"}");
}


#[tokio::test]
async fn auth_valid_api_key() {
  let api_key: String = common::random_api_key(64);

  let cfg_opt = common::TestCfgOpt {
    enable_api_key: true,
    api_key: api_key.clone(),
    allowed_ips: vec![]
  };

  let url = format!("{}/api/v1/ping", common::spawn_app(Some(cfg_opt)));

  let res = reqwest::Client::new()
    .put(url)
    .header("X-API-Key", api_key)
    .send()
    .await
    .unwrap();

  assert_eq!(res.status().as_u16(), 200);
  assert_eq!(res.content_length(), Some(0));
}


#[tokio::test]
async fn auth_myip_in_allowed_ips() {
  let api_key: String = common::random_api_key(64);
  
  let cfg_opt = common::TestCfgOpt {
    enable_api_key: true,
    api_key: api_key.clone(),
    allowed_ips: vec!["127.0.0.1".to_string()]
  };

  let url = format!("{}/api/v1/ping", common::spawn_app(Some(cfg_opt)));

  let res = reqwest::Client::new()
    .put(url)
    .header("X-API-Key", api_key)
    .send()
    .await
    .unwrap();

  assert_eq!(res.status().as_u16(), 200);
  assert_eq!(res.content_length(), Some(0));
}


#[tokio::test]
async fn auth_myip_not_in_allowed_ips() {
  let api_key: String = common::random_api_key(64);
  
  let cfg_opt = common::TestCfgOpt {
    enable_api_key: true,
    api_key: api_key.clone(),
    allowed_ips: vec!["10.20.30.40".to_string()]
  };

  let url = format!("{}/api/v1/ping", common::spawn_app(Some(cfg_opt)));

  let res = reqwest::Client::new()
    .put(url)
    .header("X-API-Key", api_key)
    .send()
    .await
    .unwrap();

  assert_eq!(res.status().as_u16(), 403);
  let body = res.text().await.unwrap();
  assert_eq!(body, "{\"message\":\"Authorization error, access from your IP is not allowed\"}");
}

