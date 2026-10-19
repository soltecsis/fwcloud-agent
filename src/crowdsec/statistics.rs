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
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

const API_CONFIG_FILE: &str = "crowdsec_firewall_bouncer_statistics.json";
const CACHE_DIRECTORY: &str = "crowdsec";
const CACHE_FILE: &str = "firewall_bouncer_statistics.jsonl";
pub const DEFAULT_CROWDSEC_FIREWALL_BOUNCER_STATISTICS_SAMPLING_INTERVAL: u64 = 30;
pub const DEFAULT_CROWDSEC_FIREWALL_BOUNCER_STATISTICS_REQUEST_MAX_SAMPLES: usize = 1000;
pub const DEFAULT_CROWDSEC_FIREWALL_BOUNCER_STATISTICS_CACHE_MAX_SIZE: usize = 10485760;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CrowdSecFirewallBouncerStatisticsConfig {
    pub enabled: bool,
    pub sampling_interval: u64,
    #[serde(default = "default_request_max_samples")]
    pub request_max_samples: usize,
    pub cache_max_size: usize,
}

const fn default_request_max_samples() -> usize {
    DEFAULT_CROWDSEC_FIREWALL_BOUNCER_STATISTICS_REQUEST_MAX_SAMPLES
}

impl Default for CrowdSecFirewallBouncerStatisticsConfig {
    fn default() -> Self {
        CrowdSecFirewallBouncerStatisticsConfig {
            enabled: false,
            sampling_interval: DEFAULT_CROWDSEC_FIREWALL_BOUNCER_STATISTICS_SAMPLING_INTERVAL,
            request_max_samples: DEFAULT_CROWDSEC_FIREWALL_BOUNCER_STATISTICS_REQUEST_MAX_SAMPLES,
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

    pub fn remove(etc_dir: &str) -> io::Result<()> {
        match fs::remove_file(Self::path(etc_dir)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
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

        if self.request_max_samples == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "CrowdSec Firewall Bouncer statistics request max samples must be a positive integer",
            ));
        }

        Ok(())
    }
}

pub fn cache_path(data_dir: &str) -> PathBuf {
    Path::new(data_dir).join(CACHE_DIRECTORY).join(CACHE_FILE)
}

pub fn cached_samples(data_dir: &str) -> io::Result<Vec<CrowdSecFirewallBouncerStatisticsSample>> {
    let path = cache_path(data_dir);

    if !path.is_file() {
        return Ok(vec![]);
    }

    fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
        })
        .collect()
}

pub fn append_cached_sample(
    data_dir: &str,
    sample: CrowdSecFirewallBouncerStatisticsSample,
    cache_max_size: usize,
) -> io::Result<()> {
    let mut samples = cached_samples(data_dir)?;
    samples.push(sample);

    let mut lines = samples
        .into_iter()
        .map(|sample| {
            serde_json::to_string(&sample)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
        })
        .collect::<io::Result<Vec<_>>>()?;
    let mut cache_size = lines.iter().map(|line| line.len() + 1).sum::<usize>();

    while cache_size > cache_max_size && !lines.is_empty() {
        cache_size = cache_size.saturating_sub(lines.remove(0).len() + 1);
    }

    write_cached_lines(data_dir, &lines)
}

pub fn take_cached_samples(
    data_dir: &str,
    request_max_samples: usize,
) -> io::Result<Vec<CrowdSecFirewallBouncerStatisticsSample>> {
    let mut samples = cached_samples(data_dir)?;
    let remaining = samples.split_off(samples.len().min(request_max_samples));

    if remaining.is_empty() {
        clear_cached_samples(data_dir)?;
    } else {
        let lines = remaining
            .iter()
            .map(|sample| {
                serde_json::to_string(sample)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
            })
            .collect::<io::Result<Vec<_>>>()?;
        write_cached_lines(data_dir, &lines)?;
    }

    Ok(samples)
}

pub fn clear_cached_samples(data_dir: &str) -> io::Result<()> {
    match fs::remove_file(cache_path(data_dir)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn write_cached_lines(data_dir: &str, lines: &[String]) -> io::Result<()> {
    let path = cache_path(data_dir);
    let directory = path
        .parent()
        .ok_or_else(|| io::Error::other("CrowdSec statistics cache directory is unavailable"))?;
    fs::create_dir_all(directory)?;

    let temporary = path.with_extension("tmp");
    let mut file = fs::File::create(&temporary)?;
    for line in lines {
        writeln!(file, "{line}")?;
    }
    file.sync_all()?;
    fs::rename(temporary, path)
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
            .map_err(|_| {
                io::Error::other(
                    "CrowdSec Firewall Bouncer statistics configuration is unavailable",
                )
            })
    }

    pub fn replace(
        &self,
        configuration: CrowdSecFirewallBouncerStatisticsConfig,
    ) -> io::Result<()> {
        self.configuration
            .lock()
            .map(|mut current| *current = Some(configuration))
            .map_err(|_| {
                io::Error::other(
                    "CrowdSec Firewall Bouncer statistics configuration is unavailable",
                )
            })
    }

    pub fn clear(&self) -> io::Result<()> {
        self.configuration
            .lock()
            .map(|mut current| *current = None)
            .map_err(|_| {
                io::Error::other(
                    "CrowdSec Firewall Bouncer statistics configuration is unavailable",
                )
            })
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
            "request_max_samples": 1000,
            "cache_max_size": 1000
        }))
        .unwrap();

        assert_eq!(config.enabled, true);
        assert_eq!(config.sampling_interval, 30);
        assert_eq!(config.request_max_samples, 1000);
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
            request_max_samples: 500,
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
    fn removes_sampling_configuration() {
        let root = std::env::temp_dir().join(format!(
            "fwcloud-crowdsec-statistics-config-{}",
            Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let etc_dir = root.to_str().unwrap();

        CrowdSecFirewallBouncerStatisticsConfig::default()
            .save(etc_dir)
            .unwrap();
        CrowdSecFirewallBouncerStatisticsConfig::remove(etc_dir).unwrap();

        assert_eq!(
            CrowdSecFirewallBouncerStatisticsConfig::load(etc_dir).unwrap(),
            None
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_non_positive_sampling_configuration_values() {
        assert!(CrowdSecFirewallBouncerStatisticsConfig {
            enabled: true,
            sampling_interval: 0,
            request_max_samples: 1000,
            cache_max_size: 1024,
        }
        .validate()
        .is_err());
        assert!(CrowdSecFirewallBouncerStatisticsConfig {
            enabled: true,
            sampling_interval: 30,
            request_max_samples: 1000,
            cache_max_size: 0,
        }
        .validate()
        .is_err());
    }

    #[test]
    fn replaces_configuration_in_the_shared_store() {
        let store = CrowdSecFirewallBouncerStatisticsConfigStore::default();
        let config = CrowdSecFirewallBouncerStatisticsConfig {
            enabled: true,
            sampling_interval: 15,
            request_max_samples: 500,
            cache_max_size: 1024,
        };

        store.replace(config.clone()).unwrap();

        assert_eq!(store.configuration().unwrap(), Some(config));
    }

    #[test]
    fn clears_configuration_from_the_shared_store() {
        let store = CrowdSecFirewallBouncerStatisticsConfigStore::default();
        store
            .replace(CrowdSecFirewallBouncerStatisticsConfig::default())
            .unwrap();

        store.clear().unwrap();

        assert_eq!(store.configuration().unwrap(), None);
    }

    #[test]
    fn retains_a_bounded_cache_and_consumes_it() {
        let root = std::env::temp_dir().join(format!(
            "fwcloud-crowdsec-statistics-cache-{}",
            Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let data_dir = root.to_str().unwrap();
        let first = CrowdSecFirewallBouncerStatisticsSample {
            collected_at: "2026-10-19T10:00:00.000Z".to_string(),
            policy_generation: 0,
            ipv4_input: CrowdSecFirewallBouncerCounter::default(),
            ipv4_forward: CrowdSecFirewallBouncerCounter::default(),
            ipv6_input: CrowdSecFirewallBouncerCounter::default(),
            ipv6_forward: CrowdSecFirewallBouncerCounter::default(),
            addresses: vec![],
        };
        let second = CrowdSecFirewallBouncerStatisticsSample {
            collected_at: "2026-10-19T10:00:01.000Z".to_string(),
            ..first.clone()
        };
        let cache_max_size = serde_json::to_string(&first).unwrap().len() + 1;

        append_cached_sample(data_dir, first, cache_max_size).unwrap();
        append_cached_sample(data_dir, second.clone(), cache_max_size).unwrap();

        assert_eq!(cached_samples(data_dir).unwrap(), vec![second.clone()]);
        assert_eq!(take_cached_samples(data_dir, 1).unwrap(), vec![second]);
        assert!(cached_samples(data_dir).unwrap().is_empty());

        fs::remove_dir_all(root).unwrap();
    }
}
