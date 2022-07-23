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

use fwcloud_agent::routes::plugin::Plugin;

#[tokio::test]
async fn plugin_without_header_neither_data() {
    let url = format!("{}/api/v1/plugin", common::spawn_app(None));

    let res = reqwest::Client::new().post(url).send().await.unwrap();

    assert_eq!(res.status().as_u16(), 400);
    let body = res.text().await.unwrap();
    assert_eq!(body, "Content type error");
}

#[tokio::test]
async fn plugin_without_data() {
    let url = format!("{}/api/v1/plugin", common::spawn_app(None));

    let res = reqwest::Client::new()
        .post(url)
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

#[tokio::test]
async fn plugin_with_invalid_data() {
    let url = format!("{}/api/v1/plugin", common::spawn_app(None));
    let test_cases = vec![
        (
            Plugin {
                name: String::from("openvpn"),
                action: String::from("INVALID"),
            },
            "{\"message\":\"action: Invalid plugin action\"}",
        ),
        (
            Plugin {
                name: String::from("INVALID"),
                action: String::from("enable"),
            },
            "{\"message\":\"name: Invalid plugin name\"}",
        ),
    ];

    for (invalid_data, error_message) in test_cases {
        let res = reqwest::Client::new()
            .post(&url)
            .header(CONTENT_TYPE, "application/json")
            .body(serde_json::to_string(&invalid_data).unwrap())
            .send()
            .await
            .unwrap();

        assert_eq!(res.status().as_u16(), 400);
        let body = res.text().await.unwrap();
        assert_eq!(body, error_message);
    }
}

#[tokio::test]
async fn test_plugin_enable_and_disable() {
    let url = format!("{}/api/v1/plugin", common::spawn_app(None));
    let test_cases = vec![
        (
            Plugin {
                name: String::from("test"),
                action: String::from("enable"),
            },
            "ENABLED\n",
        ),
        (
            Plugin {
                name: String::from("test"),
                action: String::from("disable"),
            },
            "DISABLED\n",
        ),
    ];

    for (data, answer) in test_cases {
        let res = reqwest::Client::new()
            .post(&url)
            .header(CONTENT_TYPE, "application/json")
            .body(serde_json::to_string(&data).unwrap())
            .send()
            .await
            .unwrap();

        assert_eq!(res.status().as_u16(), 200);
        let body = res.text().await.unwrap();
        assert_eq!(body, answer);
    }
}
