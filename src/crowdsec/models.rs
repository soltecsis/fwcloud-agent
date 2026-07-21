/*
    Copyright 2026 SOLTECSIS SOLUCIONES TECNOLOGICAS, SLU
    https://soltecsis.com
    info@soltecsis.com

    This file is part of FWCloud (https://fwcloud.net).
    FWCloud is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
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
