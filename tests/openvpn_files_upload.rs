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
    let url = format!("{}/api/v1/openvpn/files/upload", common::spawn_app(None));

    let res = reqwest::Client::new().post(url).send().await.unwrap();

    assert_eq!(res.status().as_u16(), 500);
    let body = res.text().await.unwrap();
    assert_eq!(
        body,
        "{\"message\":\"Destination directory parameter not found in multipart/form-data stream\"}"
    );
}
