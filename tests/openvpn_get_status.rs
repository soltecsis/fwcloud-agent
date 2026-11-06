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

use reqwest::header::CONTENT_TYPE;

#[tokio::test]
async fn openvpn_get_status_without_header_neither_data() {
    let app = common::spawn_app(None);
    let url = format!("{}/api/v1/openvpn/get/status", app);

    let res = app.client().put(url).send().await.unwrap();

    assert_eq!(res.status().as_u16(), 400);
    let body = res.text().await.unwrap();
    assert_eq!(body, "Content type error");
}

#[tokio::test]
async fn openvpn_get_status_without_data() {
    let app = common::spawn_app(None);
    let url = format!("{}/api/v1/openvpn/get/status", app);

    let res = app
        .client()
        .put(url)
        .header(CONTENT_TYPE, "application/json")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status().as_u16(), 400);
    let body = res.text().await.unwrap();
    assert_eq!(
        body,
        "Json deserialize error: EOF while parsing a value at line 1 column 0"
    );
}

const CSV_HEADER: &str =
    "Timestamp,Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since";

#[tokio::test]
async fn cached_status_is_returned_as_csv_and_consumed() {
    let app = common::spawn_app(Some(common::protected_options(true)));
    let source = app.path("status.log");
    let cache_name = format!("{}.data", source.display()).replace('/', "_");
    let cache = app.path("data").join(cache_name);
    std::fs::write(
        &cache,
        "1689951720,client,192.0.2.1:1194,10,20,1689951660\nremaining\n",
    )
    .unwrap();
    let sampling = serde_json::json!({"status_files":[{"path":source,"sampling_interval":30,"request_max_lines":1,"cache_max_size":1024}]});
    let response = common::files::json_request(
        &app,
        reqwest::Method::PUT,
        "openvpn/status/sampling",
        sampling,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    // The configured source does not exist: the collector cannot touch a real installation.
    let response = common::files::json_request(
        &app,
        reqwest::Method::PUT,
        "openvpn/get/status",
        serde_json::json!({"dir":app.root.path(),"files":["status.log"]}),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.headers()["Content-Type"], "text/csv");
    assert_eq!(
        response.text().await.unwrap(),
        format!("{CSV_HEADER}\n1689951720,client,192.0.2.1:1194,10,20,1689951660")
    );
    assert_eq!(std::fs::read_to_string(&cache).unwrap(), "remaining\n");
    assert!(!std::path::Path::new(&format!("{}.tmp", cache.display())).exists());
}

#[tokio::test]
async fn missing_and_empty_cached_status_return_only_the_header() {
    let app = common::spawn_app(Some(common::protected_options(true)));
    for create_empty in [false, true] {
        if create_empty {
            let source = app.path("status.log");
            std::fs::write(
                app.path("data")
                    .join(format!("{}.data", source.display()).replace('/', "_")),
                "",
            )
            .unwrap();
        }
        let response = common::files::json_request(
            &app,
            reqwest::Method::PUT,
            "openvpn/get/status",
            serde_json::json!({"dir":app.root.path(),"files":["status.log"]}),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(response.text().await.unwrap(), CSV_HEADER);
    }
}

#[tokio::test]
async fn file_contents_and_realtime_status_use_only_fixture_files() {
    let app = common::spawn_app(Some(common::protected_options(true)));
    for data in ["line one\nline two\n", "", "malformed status\n"] {
        std::fs::write(app.path("status.log"), data).unwrap();
        for endpoint in ["openvpn/files/read", "openvpn/get/status/rt"] {
            let response = common::files::json_request(
                &app,
                reqwest::Method::PUT,
                endpoint,
                serde_json::json!({"dir":app.root.path(),"files":["status.log"]}),
            )
            .send()
            .await
            .unwrap();
            assert_eq!(response.status().as_u16(), 200);
            assert_eq!(response.headers()["Content-Type"], "text/plain");
            // These endpoints return raw lines rather than parsing OpenVPN status records.
            assert_eq!(response.text().await.unwrap(), data.trim_end_matches('\n'));
            assert_eq!(
                std::fs::read_to_string(app.path("status.log")).unwrap(),
                data
            );
        }
    }
    let response = common::files::json_request(
        &app,
        reqwest::Method::PUT,
        "openvpn/files/read",
        serde_json::json!({"dir":app.path("missing"),"files":["status.log"]}),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(response.status().as_u16(), 400);
    for endpoint in ["openvpn/files/read", "openvpn/get/status/rt"] {
        let response = common::files::json_request(
            &app,
            reqwest::Method::PUT,
            endpoint,
            serde_json::json!({"dir":app.root.path(),"files":["missing.log"]}),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status().as_u16(), 500); // Existing I/O-error contract.
    }
}

#[tokio::test]
async fn invalid_status_and_read_paths_leave_files_unchanged() {
    let app = common::spawn_app(Some(common::protected_options(true)));
    std::fs::create_dir(app.path("destination")).unwrap();
    std::fs::write(app.path("sentinel"), "preserved").unwrap();
    std::os::unix::fs::symlink(app.path("sentinel"), app.path("destination/link")).unwrap();
    let before = common::files::snapshot(app.root.path());
    for endpoint in [
        "openvpn/files/read",
        "openvpn/get/status/rt",
        "openvpn/get/status",
    ] {
        for body in [
            serde_json::json!({"dir":app.root.path(),"files":[]}),
            serde_json::json!({"dir":app.root.path(),"files":["one","two"]}),
            serde_json::json!({"dir":app.path("destination"),"files":["../sentinel"]}),
            serde_json::json!({"dir":app.root.path(),"files":["/sentinel"]}),
            serde_json::json!({"dir":app.path("destination/.."),"files":["sentinel"]}),
            serde_json::json!({"dir":"","files":["status.log"]}),
            serde_json::json!({"dir":app.path("destination"),"files":["link"]}),
        ] {
            let response = common::files::json_request(&app, reqwest::Method::PUT, endpoint, body)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), 400);
            assert_eq!(common::files::snapshot(app.root.path()), before);
        }
    }
}

#[tokio::test]
async fn unauthorized_status_requests_cannot_consume_cache_or_change_sampling() {
    for (allowed, key) in [
        (true, None),
        (true, Some("invalid")),
        (false, Some(common::API_KEY)),
    ] {
        let app = common::spawn_app(Some(common::protected_options(allowed)));
        std::fs::write(app.path("status.log"), "preserved").unwrap();
        let before = common::files::snapshot(app.root.path());
        for endpoint in [
            "openvpn/files/read",
            "openvpn/get/status/rt",
            "openvpn/get/status",
            "openvpn/status/sampling",
            "openvpn/update/status",
        ] {
            let mut request = app
                .client()
                .put(format!("{app}/api/v1/{endpoint}"))
                .header("Content-Type", "application/json")
                .body(
                    serde_json::json!({"dir":app.root.path(),"files":["status.log"]}).to_string(),
                );
            if let Some(key) = key {
                request = request.header("X-API-Key", key);
            }
            let response = request.send().await.unwrap();
            assert_eq!(response.status().as_u16(), 403);
            assert_eq!(common::files::snapshot(app.root.path()), before);
            assert!(app.commands.calls.lock().unwrap().is_empty());
        }
    }
}
