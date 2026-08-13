/*
    Copyright 2026 SOLTECSIS SOLUCIONES TECNOLOGICAS, SLU
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

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use log::debug;
use uuid::Uuid;

use crate::{
    config::Config,
    crowdsec::secrets::redact_sensitive_text,
    errors::{FwcError, Result},
    utils::ws::WsData,
};

type WsMap = Arc<Mutex<HashMap<Uuid, Arc<Mutex<WsData>>>>>;

pub struct CrowdSecProgress {
    ws_id: Option<Uuid>,
    ws_data: Option<Arc<Mutex<WsData>>>,
    ws_map: Option<WsMap>,
}

impl CrowdSecProgress {
    pub fn from_request(cfg: &Config, ws_id: Option<Uuid>) -> Result<Self> {
        Self::from_ws_map(Arc::clone(&cfg.ws_map), ws_id)
    }

    pub(crate) fn from_ws_map(ws_map: WsMap, ws_id: Option<Uuid>) -> Result<Self> {
        let Some(ws_id) = ws_id else {
            return Ok(Self {
                ws_id: None,
                ws_data: None,
                ws_map: None,
            });
        };

        debug!("Locking ws map mutex (thread id: {})", thread_id::get());
        let ws_data = ws_map
            .lock()
            .unwrap()
            .get(&ws_id)
            .ok_or(FwcError::WebSocketIdNotFound)?
            .clone();
        debug!("Releasing ws map mutex (thread id: {})", thread_id::get());

        Ok(Self {
            ws_id: Some(ws_id),
            ws_data: Some(ws_data),
            ws_map: Some(ws_map),
        })
    }

    pub fn message(&self, message: &str) {
        let Some(ws_data) = &self.ws_data else {
            return;
        };

        let message = redact_sensitive_text(message);
        debug!("Locking ws data mutex (thread id: {})", thread_id::get());
        let mut ws_data = ws_data.lock().unwrap();
        ws_data.lines.extend(message.lines().map(String::from));
        debug!("Releasing ws data mutex (thread id: {})", thread_id::get());
    }

    pub fn finish(&mut self) {
        let Some(ws_id) = self.ws_id.take() else {
            return;
        };

        if let Some(ws_data) = &self.ws_data {
            debug!("Locking ws data mutex (thread id: {})", thread_id::get());
            ws_data.lock().unwrap().finished = true;
            debug!("Releasing ws data mutex (thread id: {})", thread_id::get());
        }

        if let Some(ws_map) = &self.ws_map {
            debug!("Locking ws map mutex (thread id: {})", thread_id::get());
            ws_map.lock().unwrap().remove(&ws_id);
            debug!("Removed CrowdSec websocket(id: {})", ws_id);
            debug!("Releasing ws map mutex (thread id: {})", thread_id::get());
        }
    }
}

impl Drop for CrowdSecProgress {
    fn drop(&mut self) {
        self.finish();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
        time::SystemTime,
    };

    use uuid::Uuid;

    use super::CrowdSecProgress;
    use crate::errors::FwcError;
    use crate::utils::ws::WsData;

    fn ws_map() -> Arc<Mutex<HashMap<Uuid, Arc<Mutex<WsData>>>>> {
        Arc::new(Mutex::new(HashMap::new()))
    }

    fn ws_data() -> Arc<Mutex<WsData>> {
        Arc::new(Mutex::new(WsData {
            created_at: SystemTime::now(),
            lines: Vec::new(),
            finished: false,
        }))
    }

    #[test]
    fn does_nothing_without_a_websocket_identifier() {
        let mut progress = CrowdSecProgress::from_ws_map(ws_map(), None).unwrap();

        progress.message("CrowdSec installation started");
        progress.finish();
    }

    #[test]
    fn rejects_an_unknown_websocket_identifier() {
        let error = match CrowdSecProgress::from_ws_map(ws_map(), Some(Uuid::new_v4())) {
            Ok(_) => panic!("Expected an unknown WebSocket identifier to be rejected"),
            Err(error) => error,
        };

        assert!(matches!(error, FwcError::WebSocketIdNotFound));
    }

    #[test]
    fn redacts_messages_and_finishes_the_websocket() {
        let map = ws_map();
        let id = Uuid::new_v4();
        let data = ws_data();
        map.lock().unwrap().insert(id, Arc::clone(&data));
        let mut progress = CrowdSecProgress::from_ws_map(Arc::clone(&map), Some(id)).unwrap();

        progress.message("api_key: secret-api-key\nEnrollment-Key=secret-enrollment-key");
        progress.finish();

        let data = data.lock().unwrap();
        assert_eq!(
            data.lines,
            vec!["api_key: [REDACTED]", "Enrollment-Key= [REDACTED]"]
        );
        assert!(data.finished);
        assert!(!map.lock().unwrap().contains_key(&id));
    }

    #[test]
    fn finishes_the_websocket_when_an_operation_exits_with_an_error() {
        let map = ws_map();
        let id = Uuid::new_v4();
        let data = ws_data();
        map.lock().unwrap().insert(id, Arc::clone(&data));

        {
            let progress = CrowdSecProgress::from_ws_map(Arc::clone(&map), Some(id)).unwrap();
            progress.message("CrowdSec uninstall started");
        }

        assert!(data.lock().unwrap().finished);
        assert!(!map.lock().unwrap().contains_key(&id));
    }
}
