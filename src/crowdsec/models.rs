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

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrowdSecOperation {
    Status,
    Install,
    Uninstall,
    Collections,
    Console,
    Decisions,
    Alerts,
    Bouncers,
    Machines,
}

#[derive(Debug, Deserialize)]
pub struct CrowdSecOperationRequest {
    pub operation: CrowdSecOperation,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrowdSecApiStatus {
    NotImplemented,
}

#[derive(Serialize)]
pub struct CrowdSecCapabilitiesResponse {
    pub api_version: &'static str,
    pub status: CrowdSecApiStatus,
    pub message: &'static str,
    pub operations: Vec<CrowdSecOperation>,
}

impl CrowdSecCapabilitiesResponse {
    pub fn not_implemented() -> Self {
        Self {
            api_version: "v1",
            status: CrowdSecApiStatus::NotImplemented,
            message: "CrowdSec operations are not implemented yet",
            operations: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CrowdSecCapabilitiesResponse, CrowdSecOperationRequest};

    #[test]
    fn rejects_unknown_crowdsec_operations() {
        let request = serde_json::from_str::<CrowdSecOperationRequest>(r#"{"operation":"shell"}"#);
        assert!(request.is_err());
    }

    #[test]
    fn capability_response_does_not_include_sensitive_fields() {
        let response =
            serde_json::to_string(&CrowdSecCapabilitiesResponse::not_implemented()).unwrap();

        assert!(!response.contains("api_key"));
        assert!(!response.contains("enrollment_key"));
    }
}
