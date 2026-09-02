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
use uuid::Uuid;

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

#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CrowdSecInstallMode {
    #[default]
    Standalone,
    Machine,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrowdSecInstallRequest {
    #[serde(default)]
    pub mode: CrowdSecInstallMode,
    #[serde(default)]
    pub backend: CrowdSecFirewallBackend,
    pub machine_name: Option<String>,
    pub lapi_url: Option<String>,
    pub central_agent_url: Option<String>,
    pub central_agent_tls_fingerprint: Option<String>,
    pub preflight_token: Option<String>,
    pub ws_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrowdSecUninstallRequest {
    pub confirm: bool,
    pub ws_id: Option<Uuid>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrowdSecBouncerInstallRequest {
    #[serde(default)]
    pub backend: CrowdSecFirewallBackend,
    pub ws_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrowdSecBouncerUninstallRequest {
    pub confirm: bool,
    pub ws_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrowdSecInstallStep {
    Repository,
    Packages,
    CrowdSecService,
    HubUpdate,
    DefaultCollections,
    FirewallBouncer,
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
    NftablesRuntime,
    NftablesBlacklistSets,
    IpSetSetupService,
    Configuration,
    LegacyResources,
    Package,
    Service,
    Integration,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrowdSecBouncerUninstallStep {
    Service,
    Registration,
    Configuration,
    NftablesStartupOrder,
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
    pub integration: crate::crowdsec::bouncers::CrowdSecBouncerIntegrationStatus,
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrowdSecCentralLapiConfigureRequest {
    pub listen_uri: String,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecCentralLapiConfigureResponse {
    pub listen_uri: String,
    pub message: String,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrowdSecMachineState {
    Pending,
    Validated,
    Unknown,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecMachine {
    pub name: String,
    pub state: CrowdSecMachineState,
    pub last_heartbeat: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecMachinesResponse {
    pub machines: Vec<CrowdSecMachine>,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecMachineValidationResponse {
    pub name: String,
    pub state: CrowdSecMachineState,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecMachineRemoveResponse {
    pub name: String,
    pub message: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrowdSecLapiPreflightTokenRequest {
    pub machine_name: String,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecLapiPreflightTokenResponse {
    pub token: String,
    pub expires_in_seconds: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrowdSecLapiPreflightRequest {
    pub central_agent_url: String,
    pub central_agent_tls_fingerprint: String,
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecRemoteMachineInstallResponse {
    pub machine_name: String,
    pub lapi_url: String,
    pub state: CrowdSecMachineState,
    pub message: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrowdSecRemoteMachineActivationRequest {
    pub machine_name: String,
    #[serde(default)]
    pub local_remediation: bool,
    #[serde(default)]
    pub backend: CrowdSecFirewallBackend,
    pub bouncer_api_key: Option<String>,
    pub ws_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecRemoteMachineActivationResponse {
    pub machine_name: String,
    pub state: CrowdSecMachineState,
    pub local_remediation: bool,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecPackageStatus {
    pub crowdsec_installed: bool,
    pub ipset_installed: bool,
    pub iptables_firewall_bouncer_installed: bool,
    pub nftables_firewall_bouncer_installed: bool,
}

impl CrowdSecPackageStatus {
    pub const fn firewall_bouncer_installed(&self, backend: CrowdSecFirewallBackend) -> bool {
        match backend {
            CrowdSecFirewallBackend::Iptables => self.iptables_firewall_bouncer_installed,
            CrowdSecFirewallBackend::Nftables => self.nftables_firewall_bouncer_installed,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct CrowdSecServiceStatus {
    pub installed: bool,
    pub running: bool,
    pub version: Option<String>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrowdSecHealthState {
    Unknown,
    Ready,
    NotConfigured,
    ReauthenticationRequired,
    Unavailable,
    RateLimited,
    Error,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CrowdSecCapiState {
    Connected,
    NotConfigured,
    TemporarilyBlocked,
    Error,
}

#[derive(Debug, PartialEq, Eq)]
pub struct CrowdSecCapiStatus {
    pub state: CrowdSecCapiState,
    pub retry_after_minutes: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecHealthStatus {
    pub state: CrowdSecHealthState,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecStatusCount {
    pub count: Option<u64>,
    pub limit: Option<u64>,
    pub truncated: bool,
    pub state: CrowdSecHealthState,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrowdSecFirewallBackend {
    #[default]
    Iptables,
    Nftables,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecFirewallBouncerStatus {
    pub installed: bool,
    pub backend: CrowdSecFirewallBackend,
    pub integration: crate::crowdsec::bouncers::CrowdSecBouncerIntegrationStatus,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecStatusWarning {
    pub component: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecStatusResponse {
    pub crowdsec: CrowdSecServiceStatus,
    pub ipset_installed: bool,
    pub lapi: CrowdSecHealthStatus,
    pub community_blocklist: CrowdSecHealthStatus,
    pub firewall_bouncer: CrowdSecFirewallBouncerStatus,
    pub active_decisions: CrowdSecStatusCount,
    pub installed_collections: CrowdSecStatusCount,
    pub warnings: Vec<CrowdSecStatusWarning>,
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
    RateLimited,
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
        CrowdSecBouncerInstallRequest, CrowdSecBouncerInstallStep, CrowdSecBouncerUninstallStep,
        CrowdSecCapabilitiesResponse, CrowdSecDataRetention, CrowdSecFirewallBackend,
        CrowdSecInstallMode, CrowdSecInstallRequest, CrowdSecInstallStep, CrowdSecOperationRequest,
        CrowdSecPackageStatus, CrowdSecRemoteMachineActivationRequest, CrowdSecStepResult,
        CrowdSecStepStatus, CrowdSecUninstallResponse, CrowdSecUninstallStep,
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

    #[test]
    fn bouncer_install_request_defaults_to_iptables_backend() {
        let request = serde_json::from_str::<CrowdSecBouncerInstallRequest>(r#"{}"#).unwrap();

        assert_eq!(request.backend, CrowdSecFirewallBackend::Iptables);
    }

    #[test]
    fn bouncer_install_request_accepts_the_nftables_backend() {
        let request =
            serde_json::from_str::<CrowdSecBouncerInstallRequest>(r#"{"backend":"nftables"}"#)
                .unwrap();

        assert_eq!(request.backend, CrowdSecFirewallBackend::Nftables);
    }

    #[test]
    fn crowdsec_install_request_accepts_the_nftables_backend() {
        let request =
            serde_json::from_str::<CrowdSecInstallRequest>(r#"{"backend":"nftables"}"#).unwrap();

        assert_eq!(request.backend, CrowdSecFirewallBackend::Nftables);
    }

    #[test]
    fn crowdsec_install_request_defaults_to_iptables_backend() {
        let request = serde_json::from_str::<CrowdSecInstallRequest>(r#"{}"#).unwrap();

        assert_eq!(request.backend, CrowdSecFirewallBackend::Iptables);
        assert_eq!(request.mode, CrowdSecInstallMode::Standalone);
    }

    #[test]
    fn crowdsec_install_request_accepts_machine_mode() {
        let request = serde_json::from_str::<CrowdSecInstallRequest>(
            r#"{"mode":"machine","machine_name":"fwcloud-web-01"}"#,
        )
        .unwrap();

        assert_eq!(request.mode, CrowdSecInstallMode::Machine);
        assert_eq!(request.machine_name.as_deref(), Some("fwcloud-web-01"));
    }

    #[test]
    fn remote_machine_activation_request_requires_a_machine_name() {
        assert!(serde_json::from_str::<CrowdSecRemoteMachineActivationRequest>(r#"{}"#).is_err());
        assert!(
            serde_json::from_str::<CrowdSecRemoteMachineActivationRequest>(
                r#"{"machine_name":"fwcloud-web-01"}"#,
            )
            .is_ok()
        );
    }

    #[test]
    fn remote_machine_activation_request_accepts_local_remediation() {
        let request = serde_json::from_str::<CrowdSecRemoteMachineActivationRequest>(
            r#"{"machine_name":"fwcloud-web-01","local_remediation":true,"backend":"nftables","bouncer_api_key":"machine-bouncer-key"}"#,
        )
        .unwrap();

        assert!(request.local_remediation);
        assert_eq!(request.backend, CrowdSecFirewallBackend::Nftables);
        assert_eq!(
            request.bouncer_api_key.as_deref(),
            Some("machine-bouncer-key")
        );
    }

    #[test]
    fn reports_the_selected_firewall_bouncer_package_status() {
        let packages = CrowdSecPackageStatus {
            crowdsec_installed: true,
            ipset_installed: true,
            iptables_firewall_bouncer_installed: false,
            nftables_firewall_bouncer_installed: true,
        };

        assert!(!packages.firewall_bouncer_installed(CrowdSecFirewallBackend::Iptables));
        assert!(packages.firewall_bouncer_installed(CrowdSecFirewallBackend::Nftables));
    }

    #[test]
    fn serializes_nftables_bouncer_install_steps() {
        assert_eq!(
            serde_json::to_value(CrowdSecBouncerInstallStep::NftablesRuntime).unwrap(),
            "nftables_runtime"
        );
        assert_eq!(
            serde_json::to_value(CrowdSecBouncerInstallStep::NftablesBlacklistSets).unwrap(),
            "nftables_blacklist_sets"
        );
        assert_eq!(
            serde_json::to_value(CrowdSecBouncerInstallStep::LegacyResources).unwrap(),
            "legacy_resources"
        );
        assert_eq!(
            serde_json::to_value(CrowdSecBouncerInstallStep::Integration).unwrap(),
            "integration"
        );
        assert_eq!(
            serde_json::to_value(CrowdSecInstallStep::FirewallBouncer).unwrap(),
            "firewall_bouncer"
        );
        assert_eq!(
            serde_json::to_value(CrowdSecBouncerUninstallStep::NftablesStartupOrder).unwrap(),
            "nftables_startup_order"
        );
    }
}
