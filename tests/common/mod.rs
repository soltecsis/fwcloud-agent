/*
    Copyright 2025 SOLTECSIS SOLUCIONES TECNOLOGICAS, SLU
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

#![allow(dead_code)]

use actix_web::{dev::ServerHandle, HttpResponse};
use fwcloud_agent::{config::Config, CommandExecutor, FwcError, WsData};
use rand::RngExt;
use rand_distr::Alphanumeric;
use std::{
    fmt, fs,
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
};

pub struct TestCfgOpt {
    pub enable_api_key: bool,
    pub api_key: String,
    pub allowed_ips: Vec<String>,
}

pub const API_KEY: &str = "integration-test-api-key-12345678";

pub fn protected_options(allowed: bool) -> TestCfgOpt {
    TestCfgOpt {
        enable_api_key: true,
        api_key: API_KEY.into(),
        allowed_ips: vec![if allowed { "127.0.0.1" } else { "192.0.2.1" }.into()],
    }
}

#[derive(Default)]
pub struct RecordingCommands {
    pub calls: Mutex<Vec<(String, Vec<String>)>>,
}
impl CommandExecutor for RecordingCommands {
    fn run(&self, cmd: &str, args: &[&str]) -> Result<HttpResponse, FwcError> {
        self.calls
            .lock()
            .unwrap()
            .push((cmd.into(), args.iter().map(|s| (*s).into()).collect()));
        let body = if args.first().is_some_and(|path| path.ends_with("test.sh"))
            && args.contains(&"enable")
        {
            "ENABLED\n"
        } else if args.first().is_some_and(|path| path.ends_with("test.sh"))
            && args.contains(&"disable")
        {
            "DISABLED\n"
        } else {
            "recorded\n"
        };
        Ok(HttpResponse::Ok().content_type("text/plain").body(body))
    }
    fn run_ws(
        &self,
        cmd: &str,
        args: &[&str],
        data: &Arc<Mutex<WsData>>,
        finish: bool,
    ) -> Result<HttpResponse, FwcError> {
        data.lock().unwrap().finished = finish;
        self.run(cmd, args)
    }
}

// A dedicated server runtime allows Drop to stop and join it even after a test panic.
// Joining also waits for the collector guard before removing its filesystem resources.
pub struct TestApp {
    pub address: String,
    pub root: tempfile::TempDir,
    pub commands: Arc<RecordingCommands>,
    pub ws_map: Arc<Mutex<std::collections::HashMap<uuid::Uuid, Arc<Mutex<WsData>>>>>,
    server: ServerHandle,
    thread: Option<thread::JoinHandle<()>>,
}
impl fmt::Display for TestApp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.address.fmt(f)
    }
}
impl TestApp {
    pub fn path(&self, path: &str) -> PathBuf {
        self.root.path().join(path)
    }
    pub fn client(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap()
    }
}
impl Drop for TestApp {
    fn drop(&mut self) {
        futures::executor::block_on(self.server.stop(false));
        if let Some(thread) = self.thread.take() {
            thread.join().expect("test server panicked");
        }
    }
}

pub fn spawn_app(custom: Option<TestCfgOpt>) -> TestApp {
    let options = custom.unwrap_or(TestCfgOpt {
        enable_api_key: false,
        api_key: API_KEY.into(),
        allowed_ips: vec![],
    });
    let playground = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/playground/tmp");
    fs::create_dir_all(&playground).unwrap();
    let root = tempfile::Builder::new()
        .prefix("app-")
        .tempdir_in(playground)
        .unwrap();
    let dir = |name| root.path().join(name).to_str().unwrap().to_owned();
    let mut config =
        Config::with_runtime_dirs(dir("etc"), dir("tmp"), dir("data"), dir("plugins")).unwrap();
    fs::create_dir_all(&config.plugins_dir).unwrap();
    config.enable_env_logger = false;
    config.bind_ip = "127.0.0.1".into();
    config.bind_port = 0;
    let listener = config.bind_to();
    config.enable_tls = false;
    config.enable_api_key = options.enable_api_key;
    config.api_key = options.api_key;
    config.allowed_ips = options.allowed_ips;
    config.workers = 1;
    config.fwcloud_script_paths = vec![dir("policy/fwcloud.sh")];
    let address = format!("http://127.0.0.1:{}", config.bind_port);
    let commands = Arc::new(RecordingCommands::default());
    config.command_executor = commands.clone();
    let ws_map = config.ws_map.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    let thread = thread::spawn(move || {
        actix_web::rt::System::new().block_on(async move {
            let server = fwcloud_agent::run(config, listener).expect("start test server");
            sender.send(server.handle()).unwrap();
            server.await.expect("test server failed");
        });
    });
    let server = receiver.recv().expect("receive test server handle");
    TestApp {
        address,
        root,
        commands,
        ws_map,
        server,
        thread: Some(thread),
    }
}

pub fn random_api_key(size: usize) -> String {
    rand::rng()
        .sample_iter(Alphanumeric)
        .take(size)
        .map(char::from)
        .collect()
}

pub mod files;
