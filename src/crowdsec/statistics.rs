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

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CrowdSecFirewallBouncerStatisticsConfig {
    pub enabled: bool,
    pub sampling_interval: u64,
    pub cache_max_size: usize,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct CrowdSecFirewallBouncerCounter {
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CrowdSecFirewallBouncerAddressCounter {
    pub address: String,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CrowdSecFirewallBouncerStatisticsSample {
    pub collected_at: String,
    pub policy_generation: u64,
    pub ipv4: CrowdSecFirewallBouncerCounter,
    pub ipv6: CrowdSecFirewallBouncerCounter,
    pub addresses: Vec<CrowdSecFirewallBouncerAddressCounter>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrowdSecFirewallBouncerStatisticsState {
    Available,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CrowdSecFirewallBouncerStatisticsSamplesResponse {
    pub state: CrowdSecFirewallBouncerStatisticsState,
    pub samples: Vec<CrowdSecFirewallBouncerStatisticsSample>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn serializes_statistics_sample_with_aggregate_and_address_counters() {
        let sample = CrowdSecFirewallBouncerStatisticsSample {
            collected_at: "2026-10-19T10:00:00.000Z".to_string(),
            policy_generation: 4,
            ipv4: CrowdSecFirewallBouncerCounter {
                packets: 12,
                bytes: 3456,
            },
            ipv6: CrowdSecFirewallBouncerCounter::default(),
            addresses: vec![CrowdSecFirewallBouncerAddressCounter {
                address: "192.0.2.15".to_string(),
                packets: 3,
                bytes: 420,
            }],
        };

        assert_eq!(
            serde_json::to_value(sample).unwrap(),
            json!({
                "collected_at": "2026-10-19T10:00:00.000Z",
                "policy_generation": 4,
                "ipv4": { "packets": 12, "bytes": 3456 },
                "ipv6": { "packets": 0, "bytes": 0 },
                "addresses": [{
                    "address": "192.0.2.15",
                    "packets": 3,
                    "bytes": 420
                }]
            })
        );
    }

    #[test]
    fn deserializes_sampling_configuration() {
        let config: CrowdSecFirewallBouncerStatisticsConfig = serde_json::from_value(json!({
            "enabled": true,
            "sampling_interval": 30,
            "cache_max_size": 1000
        }))
        .unwrap();

        assert_eq!(config.enabled, true);
        assert_eq!(config.sampling_interval, 30);
        assert_eq!(config.cache_max_size, 1000);
    }
}
