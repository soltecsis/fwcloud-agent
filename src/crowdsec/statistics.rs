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
use std::{
    fs, io,
    path::Path,
    sync::{Arc, Mutex},
};

const API_CONFIG_FILE: &str = "crowdsec_firewall_bouncer_statistics.json";
pub const DEFAULT_CROWDSEC_FIREWALL_BOUNCER_STATISTICS_SAMPLING_INTERVAL: u64 = 30;
pub const DEFAULT_CROWDSEC_FIREWALL_BOUNCER_STATISTICS_CACHE_MAX_SIZE: usize = 10485760;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CrowdSecFirewallBouncerStatisticsConfig {
    pub enabled: bool,
    pub sampling_interval: u64,
    pub cache_max_size: usize,
}

impl Default for CrowdSecFirewallBouncerStatisticsConfig {
    fn default() -> Self {
        CrowdSecFirewallBouncerStatisticsConfig {
            enabled: false,
            sampling_interval: DEFAULT_CROWDSEC_FIREWALL_BOUNCER_STATISTICS_SAMPLING_INTERVAL,
            cache_max_size: DEFAULT_CROWDSEC_FIREWALL_BOUNCER_STATISTICS_CACHE_MAX_SIZE,
        }
    }
}

impl CrowdSecFirewallBouncerStatisticsConfig {
    pub fn path(etc_dir: &str) -> String {
        format!("{etc_dir}/{API_CONFIG_FILE}")
    }

    pub fn load(etc_dir: &str) -> io::Result<Option<Self>> {
        let path = Self::path(etc_dir);

        if !Path::new(&path).is_file() {
            return Ok(None);
        }

        let config: Self = serde_json::from_str(&fs::read_to_string(path)?)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        config.validate()?;

        Ok(Some(config))
    }

    pub fn load_or_create(etc_dir: &str) -> io::Result<Self> {
        match Self::load(etc_dir)? {
            Some(config) => Ok(config),
            None => {
                let config = Self::default();
                config.save(etc_dir)?;
                Ok(config)
            }
        }
    }

    pub fn save(&self, etc_dir: &str) -> io::Result<()> {
        self.validate()?;
        fs::write(
            Self::path(etc_dir),
            serde_json::to_string_pretty(self)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?,
        )
    }

    pub fn validate(&self) -> io::Result<()> {
        if self.sampling_interval == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "CrowdSec Firewall Bouncer statistics sampling interval must be a positive integer",
            ));
        }

        if self.cache_max_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "CrowdSec Firewall Bouncer statistics cache max size must be a positive integer",
            ));
        }

        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct CrowdSecFirewallBouncerStatisticsConfigStore {
    configuration: Arc<Mutex<Option<CrowdSecFirewallBouncerStatisticsConfig>>>,
}

impl CrowdSecFirewallBouncerStatisticsConfigStore {
    pub fn configuration(&self) -> io::Result<Option<CrowdSecFirewallBouncerStatisticsConfig>> {
        self.configuration
            .lock()
            .map(|configuration| configuration.clone())
            .map_err(|_| io::Error::other("CrowdSec Firewall Bouncer statistics configuration is unavailable"))
    }

    pub fn replace(
        &self,
        configuration: CrowdSecFirewallBouncerStatisticsConfig,
    ) -> io::Result<()> {
        self.configuration
            .lock()
            .map(|mut current| *current = Some(configuration))
            .map_err(|_| io::Error::other("CrowdSec Firewall Bouncer statistics configuration is unavailable"))
    }
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

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct CrowdSecFirewallBouncerBlockingCounters {
    pub ipv4_input: CrowdSecFirewallBouncerCounter,
    pub ipv4_forward: CrowdSecFirewallBouncerCounter,
    pub ipv6_input: CrowdSecFirewallBouncerCounter,
    pub ipv6_forward: CrowdSecFirewallBouncerCounter,
    pub addresses: Vec<CrowdSecFirewallBouncerAddressCounter>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CrowdSecFirewallBouncerStatisticsSample {
    pub collected_at: String,
    pub policy_generation: u64,
    pub ipv4_input: CrowdSecFirewallBouncerCounter,
    pub ipv4_forward: CrowdSecFirewallBouncerCounter,
    pub ipv6_input: CrowdSecFirewallBouncerCounter,
    pub ipv6_forward: CrowdSecFirewallBouncerCounter,
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
    use uuid::Uuid;

    #[test]
    fn serializes_statistics_sample_with_aggregate_and_address_counters() {
        let sample = CrowdSecFirewallBouncerStatisticsSample {
            collected_at: "2026-10-19T10:00:00.000Z".to_string(),
            policy_generation: 4,
            ipv4_input: CrowdSecFirewallBouncerCounter {
                packets: 12,
                bytes: 3456,
            },
            ipv4_forward: CrowdSecFirewallBouncerCounter::default(),
            ipv6_input: CrowdSecFirewallBouncerCounter::default(),
            ipv6_forward: CrowdSecFirewallBouncerCounter::default(),
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
                "ipv4_input": { "packets": 12, "bytes": 3456 },
                "ipv4_forward": { "packets": 0, "bytes": 0 },
                "ipv6_input": { "packets": 0, "bytes": 0 },
                "ipv6_forward": { "packets": 0, "bytes": 0 },
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

    #[test]
    fn loads_and_persists_sampling_configuration() {
        let root = std::env::temp_dir().join(format!(
            "fwcloud-crowdsec-statistics-config-{}",
            Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let etc_dir = root.to_str().unwrap();

        let config = CrowdSecFirewallBouncerStatisticsConfig {
            enabled: false,
            sampling_interval: 15,
            cache_max_size: 1024,
        };
        config.save(etc_dir).unwrap();

        assert_eq!(
            CrowdSecFirewallBouncerStatisticsConfig::load(etc_dir).unwrap(),
            Some(config)
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_non_positive_sampling_configuration_values() {
        assert!(
            CrowdSecFirewallBouncerStatisticsConfig {
                enabled: true,
                sampling_interval: 0,
                cache_max_size: 1024,
            }
            .validate()
            .is_err()
        );
        assert!(
            CrowdSecFirewallBouncerStatisticsConfig {
                enabled: true,
                sampling_interval: 30,
                cache_max_size: 0,
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn replaces_configuration_in_the_shared_store() {
        let store = CrowdSecFirewallBouncerStatisticsConfigStore::default();
        let config = CrowdSecFirewallBouncerStatisticsConfig {
            enabled: true,
            sampling_interval: 15,
            cache_max_size: 1024,
        };

        store.replace(config.clone()).unwrap();

        assert_eq!(store.configuration().unwrap(), Some(config));
    }
}
