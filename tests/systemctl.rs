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
use validator::Validate;

// `tokio::test` is the testing equivalent of `tokio::main`.
// It also spares you from having to specify the `#[test]` attribute.
//
// You can inspect what code gets generated using
// `cargo expand --test health_check` (<- name of the test file)
#[tokio::test]
async fn systemctl_without_header_neither_data() {
    let app = common::spawn_app(None);
    let url = format!("{}/api/v1/systemctl", app);

    let res = app.client().post(url).send().await.unwrap();

    assert_eq!(res.status().as_u16(), 400);
    let body = res.text().await.unwrap();
    assert_eq!(body, "Content type error");
}

#[tokio::test]
async fn systemctl_without_data() {
    let app = common::spawn_app(None);
    let url = format!("{}/api/v1/systemctl", app);

    let res = app
        .client()
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
    let app = common::spawn_app(None);
    let url = format!("{}/api/v1/systemctl", app);
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
    ];

    for (invalid_data, error_message) in test_cases {
        let res = app
            .client()
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

#[test]
fn systemctl_openvpn_service_validation() {
    let valid_services = vec!["openvpn@firewall1", "openvpn-server@firewall1"];

    for service in valid_services {
        let data = Systemctl {
            command: String::from("status"),
            service: String::from(service),
        };

        assert!(data.validate().is_ok());
    }

    let invalid_data = Systemctl {
        command: String::from("status"),
        service: String::from("openvpn-server"),
    };

    assert!(invalid_data.validate().is_err());
}

#[tokio::test]
async fn valid_commands_are_recorded_and_authorization_prevents_execution() {
    for (allowed, key, expected) in [
        (true, Some(common::API_KEY), 200),
        (true, None, 403),
        (true, Some("invalid"), 403),
        (false, Some(common::API_KEY), 403),
    ] {
        let app = common::spawn_app(Some(common::protected_options(allowed)));
        let mut request = app
            .client()
            .post(format!("{app}/api/v1/systemctl"))
            .header("Content-Type", "application/json")
            .body(r#"{"command":"restart","service":"openvpn-server@test"}"#);
        if let Some(key) = key {
            request = request.header("X-API-Key", key);
        }
        let response = request.send().await.unwrap();
        assert_eq!(response.status().as_u16(), expected);
        let calls = app.commands.calls.lock().unwrap();
        if expected == 200 {
            assert_eq!(
                *calls,
                vec![(
                    "systemctl".into(),
                    vec!["restart".into(), "openvpn-server@test".into()]
                )]
            );
        } else {
            assert!(calls.is_empty());
        }
    }
}
