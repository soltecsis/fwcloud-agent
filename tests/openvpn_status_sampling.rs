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

use std::fs;

#[tokio::test]
async fn openvpn_status_sampling_accepts_valid_config() {
    let app = common::spawn_app(None);
    let url = format!("{}/api/v1/openvpn/status/sampling", app);

    let res = app
        .client()
        .put(url)
        .header("Content-Type", "application/json")
        .body(
            serde_json::json!({
                "status_files": [{
                    "path": app.path("server.status").to_str().unwrap(),
                    "sampling_interval": 30,
                    "request_max_lines": 1000,
                    "cache_max_size": 10485760
                }]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();

    assert_eq!(res.status().as_u16(), 200);

    let body: serde_json::Value = serde_json::from_str(&res.text().await.unwrap()).unwrap();
    assert_eq!(body["accepted"], true);
    assert_eq!(
        body["status_files"][0]["path"],
        app.path("server.status").to_str().unwrap()
    );
    assert_eq!(body["status_files"][0]["sampling_interval"], 30);
    assert_eq!(body["status_files"][0]["request_max_lines"], 1000);
    assert_eq!(body["status_files"][0]["cache_max_size"], 10485760);

    let persisted: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(app.path("etc/openvpn_status_sampling.json")).unwrap(),
    )
    .unwrap();
    assert!(persisted.get("enabled").is_none());
    assert_eq!(
        persisted["status_files"][0]["path"],
        app.path("server.status").to_str().unwrap()
    );
}

#[tokio::test]
async fn openvpn_status_sampling_creates_initial_config() {
    let app = common::spawn_app(None);
    let url = format!("{}/api/v1/openvpn/status/sampling", app);

    let res = app.client().get(url).send().await.unwrap();
    assert_eq!(res.status().as_u16(), 200);

    let body: serde_json::Value = serde_json::from_str(&res.text().await.unwrap()).unwrap();
    assert_eq!(body["accepted"], true);
    assert_eq!(body["status_files"].as_array().unwrap().len(), 0);

    let persisted: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(app.path("etc/openvpn_status_sampling.json")).unwrap(),
    )
    .unwrap();
    assert!(persisted.get("enabled").is_none());
    assert_eq!(persisted["status_files"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn openvpn_status_sampling_rejects_relative_paths() {
    let app = common::spawn_app(None);
    let url = format!("{}/api/v1/openvpn/status/sampling", app);

    let res = app
        .client()
        .put(url)
        .header("Content-Type", "application/json")
        .body(
            serde_json::json!({
                "status_files": [{
                    "path": "openvpn/server.status",
                    "sampling_interval": 30,
                    "request_max_lines": 1000,
                    "cache_max_size": 10485760
                }]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();

    assert_eq!(res.status().as_u16(), 400);
}

#[tokio::test]
async fn openvpn_status_sampling_rejects_empty_paths() {
    let app = common::spawn_app(None);
    let url = format!("{}/api/v1/openvpn/status/sampling", app);

    let res = app
        .client()
        .put(url)
        .header("Content-Type", "application/json")
        .body(
            serde_json::json!({
                "status_files": [{
                    "path": "",
                    "sampling_interval": 30,
                    "request_max_lines": 1000,
                    "cache_max_size": 10485760
                }]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();

    assert_eq!(res.status().as_u16(), 400);
}

#[tokio::test]
async fn openvpn_status_sampling_rejects_zero_sampling_parameters() {
    let app = common::spawn_app(None);
    let url = format!("{}/api/v1/openvpn/status/sampling", app);

    let res = app
        .client()
        .put(url)
        .header("Content-Type", "application/json")
        .body(
            serde_json::json!({
                "status_files": [{
                    "path": app.path("server.status").to_str().unwrap(),
                    "sampling_interval": 0,
                    "request_max_lines": 1000,
                    "cache_max_size": 10485760
                }]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();

    assert_eq!(res.status().as_u16(), 400);
}

#[tokio::test]
async fn openvpn_status_sampling_rejects_missing_sampling_parameters() {
    let app = common::spawn_app(None);
    let url = format!("{}/api/v1/openvpn/status/sampling", app);

    let res = app
        .client()
        .put(url)
        .header("Content-Type", "application/json")
        .body(
            serde_json::json!({
                "status_files": [{
                    "path": app.path("server.status").to_str().unwrap(),
                    "request_max_lines": 1000,
                    "cache_max_size": 10485760
                }]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();

    assert_eq!(res.status().as_u16(), 400);
}

#[tokio::test]
async fn openvpn_status_sampling_rejects_unknown_fields() {
    let app = common::spawn_app(None);
    let url = format!("{}/api/v1/openvpn/status/sampling", app);

    let res = app
        .client()
        .put(url)
        .header("Content-Type", "application/json")
        .body(
            serde_json::json!({
                "status_files": [{
                    "path": app.path("server.status").to_str().unwrap(),
                    "sampling_interval": 30,
                    "request_max_lines": 1000,
                    "cache_max_size": 10485760,
                    "unexpected": true
                }]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();

    assert_eq!(res.status().as_u16(), 400);
}

#[tokio::test]
async fn openvpn_status_sampling_deduplicates_valid_paths() {
    let app = common::spawn_app(None);
    let url = format!("{}/api/v1/openvpn/status/sampling", app);

    let res = app
        .client()
        .put(url)
        .header("Content-Type", "application/json")
        .body(
            serde_json::json!({
                "status_files": [
                    {
                        "path": app.path("server.status").to_str().unwrap(),
                        "sampling_interval": 30,
                        "request_max_lines": 1000,
                        "cache_max_size": 10485760
                    },
                    {
                        "path": app.path("server.status").to_str().unwrap(),
                        "sampling_interval": 30,
                        "request_max_lines": 1000,
                        "cache_max_size": 10485760
                    }
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
    assert_eq!(
        body["status_files"][0]["path"],
        app.path("server.status").to_str().unwrap()
    );
}

#[tokio::test]
async fn openvpn_status_sampling_disable_clears_paths() {
    let app = common::spawn_app(None);
    let url = format!("{}/api/v1/openvpn/status/sampling", app);

    let res = app
        .client()
        .put(url)
        .header("Content-Type", "application/json")
        .body(
            serde_json::json!({
                "status_files": []
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();

    assert_eq!(res.status().as_u16(), 200);

    let body: serde_json::Value = serde_json::from_str(&res.text().await.unwrap()).unwrap();
    assert_eq!(body["status_files"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn openvpn_status_sampling_show_returns_applied_config() {
    let app = common::spawn_app(None);
    let base_url = &app;
    let url = format!("{}/api/v1/openvpn/status/sampling", base_url);

    let res = app
        .client()
        .put(&url)
        .header("Content-Type", "application/json")
        .body(
            serde_json::json!({
                "status_files": [{
                    "path": app.path("server.status").to_str().unwrap(),
                    "sampling_interval": 30,
                    "request_max_lines": 1000,
                    "cache_max_size": 10485760
                }]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 200);

    let res = app.client().get(url).send().await.unwrap();
    assert_eq!(res.status().as_u16(), 200);

    let body: serde_json::Value = serde_json::from_str(&res.text().await.unwrap()).unwrap();
    assert_eq!(body["accepted"], true);
    assert_eq!(
        body["status_files"][0]["path"],
        app.path("server.status").to_str().unwrap()
    );
}
