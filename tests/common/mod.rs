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

use fwcloud_agent::config::Config;

// Launch our application in the background ~somehow~
pub fn spawn_app() -> String {
  let mut config = Config::new().unwrap();

  config.enable_env_logger = false;
  config.bind_ip = String::from("127.0.0.1");
  config.bind_port = 0;
  let listener = config.bind_to();
  config.enable_tls = false;
  config.enable_api_key = false;
  config.workers = 1;

  let protocol = "http";
  let ip = config.bind_ip.clone();
  let port = config.bind_port;

  let server = fwcloud_agent::run(config,listener).expect("Failed to run FWCloud-Agent server");
  // Launch the server as a background task
  // tokio::spawn returns a handle to the spawned future,
  // but we have no use for it here, hence the non-binding let
  let _ = tokio::spawn(server);

  format!("{}://{}:{}", protocol, ip, port)
}
