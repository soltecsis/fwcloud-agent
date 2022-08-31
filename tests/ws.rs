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

use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};

// `tokio::test` is the testing equivalent of `tokio::main`.
// It also spares you from having to specify the `#[test]` attribute.
//
// You can inspect what code gets generated using
// `cargo expand --test health_check` (<- name of the test file)
#[tokio::test]
async fn ws_first_read_message_must_be_valid_uuid() {
    let url = format!("{}/api/v1/ws", common::spawn_app(None)).replace("http://", "ws://");

    let (mut ws_stream, res) = connect_async(url).await.expect("Failed to connect");

    //let (_write, read) = ws_stream.split();

    //let ws_id = .read_message().expect("Error reading message");
    ws_stream.close(None).await.expect("Error closing websocket");

    assert_eq!(res.status().as_u16(), 200);
}
