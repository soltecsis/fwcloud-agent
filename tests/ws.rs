mod common;

use actix_codec::Framed;
use actix_http::ws::{Codec, Frame, Message};
use common::{protected_options, spawn_app, TestApp, API_KEY};
use futures::{SinkExt, StreamExt};
use reqwest::{RequestBuilder, StatusCode};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};
use uuid::Uuid;

fn upgrade(app: &TestApp) -> RequestBuilder {
    app.client()
        .get(format!("{app}/api/v1/ws"))
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
}

async fn connect(app: &TestApp) -> Framed<reqwest::Upgraded, Codec> {
    let response = upgrade(app)
        .header("X-API-Key", API_KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    assert_eq!(
        response.headers()["Sec-WebSocket-Accept"],
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    );
    let stream = response.upgrade().await.unwrap();
    Framed::new(stream, Codec::new().client_mode())
}

async fn next(socket: &mut Framed<reqwest::Upgraded, Codec>) -> Frame {
    tokio::time::timeout(Duration::from_secs(3), socket.next())
        .await
        .expect("websocket read timed out")
        .expect("websocket ended unexpectedly")
        .expect("invalid websocket frame")
}

async fn id(socket: &mut Framed<reqwest::Upgraded, Codec>) -> Uuid {
    match next(socket).await {
        Frame::Text(bytes) => Uuid::parse_str(std::str::from_utf8(&bytes).unwrap()).unwrap(),
        frame => panic!("expected UUID text, got {:?}", frame),
    }
}

async fn wait_removed(app: &TestApp, id: Uuid) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while app.ws_map.lock().unwrap().contains_key(&id) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("closed websocket still registered");
}

#[tokio::test]
async fn handshake_ping_and_client_close_clean_up_state() {
    let app = spawn_app(Some(protected_options(true)));
    let mut socket = connect(&app).await;
    let id = id(&mut socket).await;
    assert!(app.ws_map.lock().unwrap().contains_key(&id));
    socket
        .send(Message::Ping("client ping".into()))
        .await
        .unwrap();
    assert!(matches!(next(&mut socket).await, Frame::Pong(bytes) if bytes == "client ping"));
    socket.send(Message::Close(None)).await.unwrap();
    assert!(matches!(next(&mut socket).await, Frame::Close(_)));
    wait_removed(&app, id).await;
    assert!(app.commands.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_endpoint_streams_output_and_finishes_the_connection() {
    let app = spawn_app(Some(protected_options(true)));
    let mut socket = connect(&app).await;
    let id = id(&mut socket).await;
    let request = app
        .client()
        .get(format!("{app}/api/v1/ws/test/{id}/1"))
        .header("X-API-Key", API_KEY);
    let response = tokio::spawn(async move { request.send().await.unwrap() });
    assert!(matches!(next(&mut socket).await, Frame::Text(bytes) if bytes == "1 seconds left"));
    assert_eq!(response.await.unwrap().status(), StatusCode::OK);
    assert!(matches!(next(&mut socket).await, Frame::Close(_)));
    wait_removed(&app, id).await;
    assert_eq!(
        app.client()
            .get(format!("{app}/api/v1/ws/test/{id}/0"))
            .header("X-API-Key", API_KEY)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn zero_second_lifecycle_finishes_without_waiting() {
    let app = spawn_app(Some(protected_options(true)));
    let mut socket = connect(&app).await;
    let id = id(&mut socket).await;
    let response = app
        .client()
        .get(format!("{app}/api/v1/ws/test/{id}/0"))
        .header("X-API-Key", API_KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(matches!(next(&mut socket).await, Frame::Close(_)));
    wait_removed(&app, id).await;
}

#[tokio::test]
async fn invalid_upgrades_do_not_allocate_connection_state() {
    let app = spawn_app(Some(protected_options(true)));
    for request in [
        app.client().get(format!("{app}/api/v1/ws")),
        app.client()
            .get(format!("{app}/api/v1/ws"))
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "12")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
        app.client()
            .get(format!("{app}/api/v1/ws"))
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13"),
    ] {
        let response = request.header("X-API-Key", API_KEY).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(app.ws_map.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn invalid_parameters_and_unknown_identifiers() {
    let app = spawn_app(Some(protected_options(true)));
    for path in [
        "not-a-uuid/0".to_owned(),
        format!("{}/not-a-number", Uuid::nil()),
        format!("{}/65536", Uuid::nil()),
        format!("{}/0", Uuid::nil()),
    ] {
        let response = app
            .client()
            .get(format!("{app}/api/v1/ws/test/{path}"))
            .header("X-API-Key", API_KEY)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(app.ws_map.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn authorization_applies_to_upgrades_and_test_requests() {
    for (allowed, key) in [
        (true, None),
        (true, Some("invalid")),
        (false, Some(API_KEY)),
    ] {
        let app = spawn_app(Some(protected_options(allowed)));
        let before = common::files::snapshot(app.root.path());
        // An existing isolated entry proves unauthorized test requests cannot set finished.
        let id = Uuid::new_v4();
        let data = Arc::new(Mutex::new(fwcloud_agent::WsData {
            created_at: SystemTime::now(),
            lines: vec![],
            finished: false,
        }));
        app.ws_map.lock().unwrap().insert(id, data.clone());
        for mut request in [
            upgrade(&app),
            app.client().get(format!("{app}/api/v1/ws/test/{id}/0")),
        ] {
            if let Some(key) = key {
                request = request.header("X-API-Key", key);
            }
            let response = request.send().await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert!(!data.lock().unwrap().finished);
            assert_eq!(app.ws_map.lock().unwrap().len(), 1);
            assert_eq!(common::files::snapshot(app.root.path()), before);
            assert!(app.commands.calls.lock().unwrap().is_empty());
        }
    }
}

#[tokio::test]
async fn expired_entries_are_removed_without_waiting_two_hours() {
    let app = spawn_app(Some(protected_options(true)));
    let expired = Uuid::new_v4();
    let data = Arc::new(Mutex::new(fwcloud_agent::WsData {
        created_at: SystemTime::now() - Duration::from_secs(7201),
        lines: vec![],
        finished: false,
    }));
    app.ws_map.lock().unwrap().insert(expired, data.clone());
    let mut socket = connect(&app).await;
    let id = id(&mut socket).await;
    assert!(!app.ws_map.lock().unwrap().contains_key(&expired));
    assert!(data.lock().unwrap().finished);
    socket.send(Message::Close(None)).await.unwrap();
    wait_removed(&app, id).await;
}

#[tokio::test]
async fn connection_limit_uses_isolated_records_without_live_sockets() {
    let app = spawn_app(Some(protected_options(true)));
    for _ in 0..256 {
        app.ws_map.lock().unwrap().insert(
            Uuid::new_v4(),
            Arc::new(Mutex::new(fwcloud_agent::WsData {
                created_at: SystemTime::now(),
                lines: vec![],
                finished: false,
            })),
        );
    }
    let response = upgrade(&app)
        .header("X-API-Key", API_KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(app.ws_map.lock().unwrap().len(), 256);
}

#[tokio::test]
async fn dropped_transport_is_removed_from_connection_map() {
    let app = spawn_app(Some(protected_options(true)));
    let mut socket = connect(&app).await;
    let id = id(&mut socket).await;
    drop(socket);
    wait_removed(&app, id).await;
}
