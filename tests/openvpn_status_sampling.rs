/*
    Copyright 2026 SOLTECSIS SOLUCIONES TECNOLOGICAS, SLU
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

use serial_test::serial;
use std::fs;

const API_CONFIG_FILE: &str = "./etc/openvpn_status_sampling.json";

fn remove_api_config_file() {
    let _ = fs::remove_file(API_CONFIG_FILE);
}

#[tokio::test]
#[serial]
async fn openvpn_status_sampling_accepts_valid_config() {
    remove_api_config_file();
    let url = format!("{}/api/v1/openvpn/status/sampling", common::spawn_app(None));

    let res = reqwest::Client::new()
        .put(url)
        .header("Content-Type", "application/json")
        .body(
            serde_json::json!({
                "enabled": true,
                "status_files": ["/run/openvpn/server.status"]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();

    assert_eq!(res.status().as_u16(), 200);

    let body: serde_json::Value = serde_json::from_str(&res.text().await.unwrap()).unwrap();
    assert_eq!(body["accepted"], true);
    assert_eq!(body["enabled"], true);
    assert_eq!(body["status_files"][0], "/run/openvpn/server.status");

    let persisted: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(API_CONFIG_FILE).unwrap()).unwrap();
    assert_eq!(persisted["enabled"], true);
    assert_eq!(persisted["status_files"][0], "/run/openvpn/server.status");
    remove_api_config_file();
}

#[tokio::test]
#[serial]
async fn openvpn_status_sampling_rejects_relative_paths() {
    remove_api_config_file();
    let url = format!("{}/api/v1/openvpn/status/sampling", common::spawn_app(None));

    let res = reqwest::Client::new()
        .put(url)
        .header("Content-Type", "application/json")
        .body(
            serde_json::json!({
                "enabled": true,
                "status_files": ["openvpn/server.status"]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();

    assert_eq!(res.status().as_u16(), 400);
    remove_api_config_file();
}

#[tokio::test]
#[serial]
async fn openvpn_status_sampling_deduplicates_valid_paths() {
    remove_api_config_file();
    let url = format!("{}/api/v1/openvpn/status/sampling", common::spawn_app(None));

    let res = reqwest::Client::new()
        .put(url)
        .header("Content-Type", "application/json")
        .body(
            serde_json::json!({
                "enabled": true,
                "status_files": [
                    "/run/openvpn/server.status",
                    "/run/openvpn/server.status"
                ]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();

    assert_eq!(res.status().as_u16(), 200);

    let body: serde_json::Value = serde_json::from_str(&res.text().await.unwrap()).unwrap();
    assert_eq!(body["status_files"].as_array().unwrap().len(), 1);
    assert_eq!(body["status_files"][0], "/run/openvpn/server.status");
    remove_api_config_file();
}

#[tokio::test]
#[serial]
async fn openvpn_status_sampling_disable_clears_paths() {
    remove_api_config_file();
    let url = format!("{}/api/v1/openvpn/status/sampling", common::spawn_app(None));

    let res = reqwest::Client::new()
        .put(url)
        .header("Content-Type", "application/json")
        .body(
            serde_json::json!({
                "enabled": false,
                "status_files": ["/run/openvpn/server.status"]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();

    assert_eq!(res.status().as_u16(), 200);

    let body: serde_json::Value = serde_json::from_str(&res.text().await.unwrap()).unwrap();
    assert_eq!(body["enabled"], false);
    assert_eq!(body["status_files"].as_array().unwrap().len(), 0);
    remove_api_config_file();
}
