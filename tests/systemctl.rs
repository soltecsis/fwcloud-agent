/*
    Copyright 2023 SOLTECSIS SOLUCIONES TECNOLOGICAS, SLU
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

use fwcloud_agent::routes::systemctl::Systemctl;

// `tokio::test` is the testing equivalent of `tokio::main`.
// It also spares you from having to specify the `#[test]` attribute.
//
// You can inspect what code gets generated using
// `cargo expand --test health_check` (<- name of the test file)
#[tokio::test]
async fn systemctl_without_header_neither_data() {
    let url = format!("{}/api/v1/systemctl", common::spawn_app(None));

    let res = reqwest::Client::new().post(url).send().await.unwrap();

    assert_eq!(res.status().as_u16(), 400);
    let body = res.text().await.unwrap();
    assert_eq!(body, "Content type error");
}

#[tokio::test]
async fn systemctl_without_data() {
    let url = format!("{}/api/v1/systemctl", common::spawn_app(None));

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
async fn systemctl_with_invalid_data() {
    let url = format!("{}/api/v1/systemctl", common::spawn_app(None));
    let test_cases = vec![
        (
            Systemctl {
                command: String::from("INVALID"),
                service: String::from("openvpn"),
            },
            "{\"message\":\"command: Invalid systemctl command\"}",
        ),
        (
            Systemctl {
                command: String::from("status"),
                service: String::from("INVALID"),
            },
            "{\"message\":\"service: Invalid systemctl service\"}",
        ),
        (
            Systemctl {
                command: String::from("INVALID"),
                service: String::from("INVALID"),
            },
            "{\"message\":\"service: Invalid systemctl service\ncommand: Invalid systemctl command\"}",
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

