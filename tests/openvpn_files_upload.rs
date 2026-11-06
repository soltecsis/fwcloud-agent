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
async fn openvpn_files_upload_without_data() {
    let app = common::spawn_app(None);
    let url = format!("{}/api/v1/openvpn/files/upload", app);

    let res = app.client().post(url).send().await.unwrap();

    assert_eq!(res.status().as_u16(), 400);
    let body = res.text().await.unwrap();
    assert_eq!(body, "{\"message\":\"Could not find Content-Type header\"}");
}

#[tokio::test]
async fn upload_success() {
    common::files::upload_success("openvpn/files/upload").await;
}

#[tokio::test]
async fn upload_validation() {
    common::files::upload_validation("openvpn/files/upload").await;
}

#[tokio::test]
async fn authorization_prevents_side_effects() {
    common::files::authorization("openvpn/files/upload", Some("openvpn/files/remove")).await;
}
