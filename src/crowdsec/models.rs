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

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrowdSecInstallRequest {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrowdSecUninstallRequest {
    pub confirm: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrowdSecBouncerInstallRequest {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrowdSecBouncerUninstallRequest {
    pub confirm: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrowdSecInstallStep {
    Repository,
    Packages,
    CrowdSecService,
    HubUpdate,
    DefaultCollections,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrowdSecUninstallStep {
    CrowdSecService,
    FirewallBouncerService,
    Packages,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrowdSecBouncerInstallStep {
    BlacklistIpSets,
    IpSetSetupService,
    Configuration,
    Package,
    Service,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrowdSecBouncerUninstallStep {
    Service,
    Registration,
    Configuration,
    IpSetSetupService,
    BlacklistIpSets,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrowdSecStepStatus {
    Pending,
    Completed,
    Skipped,
    Failed,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecStepResult<T> {
    pub step: T,
    pub status: CrowdSecStepStatus,
    pub message: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrowdSecDataRetention {
    Preserve,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecInstallResponse {
    pub data_retention: CrowdSecDataRetention,
    pub steps: Vec<CrowdSecStepResult<CrowdSecInstallStep>>,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecUninstallResponse {
    pub data_retention: CrowdSecDataRetention,
    pub steps: Vec<CrowdSecStepResult<CrowdSecUninstallStep>>,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecBouncerInstallResponse {
    pub steps: Vec<CrowdSecStepResult<CrowdSecBouncerInstallStep>>,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecBouncerUninstallResponse {
    pub steps: Vec<CrowdSecStepResult<CrowdSecBouncerUninstallStep>>,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecBouncer {
    pub name: String,
    #[serde(rename = "type")]
    pub bouncer_type: Option<String>,
    pub revoked: bool,
    pub last_pull: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecBouncersResponse {
    pub bouncers: Vec<CrowdSecBouncer>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrowdSecBouncerRegisterRequest {
    pub name: String,
}

#[derive(Serialize)]
pub struct CrowdSecBouncerRegisterResponse {
    pub name: String,
    pub api_key: String,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecBouncerRemoveResponse {
    pub name: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecPackageStatus {
    pub crowdsec_installed: bool,
    pub ipset_installed: bool,
    pub firewall_bouncer_installed: bool,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecServiceStatus {
    pub installed: bool,
    pub running: bool,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecFirewallBouncerStatus {
    pub installed: bool,
    pub integration: crate::crowdsec::bouncers::CrowdSecBouncerIntegrationStatus,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecStatusResponse {
    pub crowdsec: CrowdSecServiceStatus,
    pub ipset_installed: bool,
    pub firewall_bouncer: CrowdSecFirewallBouncerStatus,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrowdSecCollectionState {
    Available,
    Installed,
    Tainted,
    Disabled,
    Unknown,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecCollection {
    pub name: String,
    pub version: Option<String>,
    pub state: CrowdSecCollectionState,
    pub available: bool,
    pub path: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecCollectionsResponse {
    pub collections: Vec<CrowdSecCollection>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrowdSecCollectionsQuery {
    pub installed: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrowdSecCollectionInstallRequest {
    pub name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrowdSecCollectionRemoveRequest {
    pub name: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrowdSecCollectionUpdateRequest {}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrowdSecCollectionOperation {
    Install,
    Remove,
    Update,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecCollectionOperationResponse {
    pub operation: CrowdSecCollectionOperation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection: Option<String>,
    pub processed_collections: Vec<String>,
    pub skipped_collections: Vec<String>,
    pub message: String,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrowdSecConsoleState {
    NotConfigured,
    PendingApproval,
    Connected,
    Error,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecConsoleStatusResponse {
    pub state: CrowdSecConsoleState,
    pub message: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrowdSecConsoleEnrollRequest {
    pub enrollment_key: String,
    pub name: Option<String>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecConsoleEnrollResponse {
    pub status: CrowdSecConsoleStatusResponse,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecDecision {
    pub id: String,
    pub scope: String,
    pub value: String,
    pub decision_type: String,
    pub origin: Option<String>,
    pub scenario: Option<String>,
    pub expires_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecDecisionsResponse {
    pub decisions: Vec<CrowdSecDecision>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrowdSecDecisionsQuery {
    pub limit: Option<u32>,
    pub scope: Option<String>,
    pub value: Option<String>,
    pub decision_type: Option<String>,
    pub origin: Option<String>,
    pub scenario: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrowdSecDecisionsFlushRequest {
    pub confirm: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrowdSecDecisionOperation {
    Delete,
    Flush,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecDecisionOperationResponse {
    pub operation: CrowdSecDecisionOperation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_id: Option<String>,
    pub deleted_count: u64,
    pub message: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrowdSecAlertsQuery {
    pub limit: Option<u32>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub scenario: Option<String>,
    #[serde(rename = "type")]
    pub decision_type: Option<String>,
    pub scope: Option<String>,
    pub value: Option<String>,
    pub ip: Option<String>,
    pub range: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecAlert {
    pub id: String,
    pub created_at: Option<String>,
    pub source_ip: Option<String>,
    pub scenario: Option<String>,
    pub decision_type: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecAlertsResponse {
    pub alerts: Vec<CrowdSecAlert>,
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
    use super::{
        CrowdSecCapabilitiesResponse, CrowdSecDataRetention, CrowdSecOperationRequest,
        CrowdSecStepResult, CrowdSecStepStatus, CrowdSecUninstallResponse, CrowdSecUninstallStep,
    };

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

    #[test]
    fn uninstall_response_preserves_data_and_reports_steps() {
        let response = CrowdSecUninstallResponse {
            data_retention: CrowdSecDataRetention::Preserve,
            steps: vec![CrowdSecStepResult {
                step: CrowdSecUninstallStep::Packages,
                status: CrowdSecStepStatus::Completed,
                message: "Removed CrowdSec packages: crowdsec".to_string(),
            }],
        };

        let response = serde_json::to_value(response).unwrap();
        assert_eq!(response["data_retention"], "preserve");
        assert_eq!(response["steps"][0]["step"], "packages");
        assert_eq!(response["steps"][0]["status"], "completed");
    }
}
