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

use serde::Serialize;

pub const FIREWALL_BOUNCER_PACKAGE: &str = "crowdsec-firewall-bouncer-iptables";
pub const FIREWALL_BOUNCER_SERVICE: &str = "crowdsec-firewall-bouncer.service";
pub const FWCLOUD_BOUNCER_NAME: &str = "fwcloud";
pub const BOUNCER_CONFIG_DIRECTORY: &str = "/etc/crowdsec/bouncers";
pub const BOUNCER_CONFIG_OVERRIDE_PATH: &str =
    "/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local";
pub const IPSET_SETUP_SERVICE: &str = "fwcloud-crowdsec-ipsets.service";
pub const IPSET_SETUP_SERVICE_PATH: &str = "/etc/systemd/system/fwcloud-crowdsec-ipsets.service";
pub const IPSET_V4_BLACKLIST: &str = "crowdsec-blacklists";
pub const IPSET_V6_BLACKLIST: &str = "crowdsec6-blacklists";

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrowdSecBouncerIntegrationState {
    NotConfigured,
    Ready,
    MissingBlacklistSets,
    ManagedConfiguration,
    ServiceInactive,
    Error,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecIpSetStatus {
    pub name: &'static str,
    pub exists: bool,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecBouncerIntegrationStatus {
    pub state: CrowdSecBouncerIntegrationState,
    pub ipv4_blacklist: CrowdSecIpSetStatus,
    pub ipv6_blacklist: CrowdSecIpSetStatus,
    pub service_running: bool,
    pub message: String,
}

#[derive(Debug)]
pub struct CrowdSecBouncerSetOnlyConfig {
    pub mode: &'static str,
    pub blacklists_ipv4: &'static str,
    pub blacklists_ipv6: &'static str,
}

impl Default for CrowdSecBouncerSetOnlyConfig {
    fn default() -> Self {
        Self {
            mode: "ipset",
            blacklists_ipv4: IPSET_V4_BLACKLIST,
            blacklists_ipv6: IPSET_V6_BLACKLIST,
        }
    }
}
