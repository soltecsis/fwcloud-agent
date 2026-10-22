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
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with FWCloud.  If not, see <https://www.gnu.org/licenses/>.
*/

use chrono::{DateTime, SecondsFormat, Utc};
use log::{debug, error, info};
use std::{
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime},
};
use tokio::runtime::Runtime;

use crate::{
    config::Config,
    crowdsec::{
        bouncers,
        statistics::{
            append_cached_sample, cached_samples, take_cached_samples,
            CrowdSecFirewallBouncerStatisticsConfig, CrowdSecFirewallBouncerStatisticsConfigStore,
            CrowdSecFirewallBouncerStatisticsSample,
            CrowdSecFirewallBouncerStatisticsSamplesResponse,
            CrowdSecFirewallBouncerStatisticsState,
        },
    },
};

struct CrowdSecFirewallBouncerStatisticsCollectorInner {
    state: CrowdSecFirewallBouncerStatisticsState,
    policy_generation: u64,
    next_sample_at: Option<Instant>,
    last_sample: Option<CrowdSecFirewallBouncerStatisticsSample>,
}

#[derive(Clone)]
pub struct CrowdSecFirewallBouncerStatisticsCollector {
    inner: Arc<Mutex<CrowdSecFirewallBouncerStatisticsCollectorInner>>,
    configuration: CrowdSecFirewallBouncerStatisticsConfigStore,
    data_dir: String,
}

impl CrowdSecFirewallBouncerStatisticsCollector {
    pub fn new(
        data_dir: &str,
        configuration: CrowdSecFirewallBouncerStatisticsConfigStore,
    ) -> Self {
        CrowdSecFirewallBouncerStatisticsCollector {
            inner: Arc::new(Mutex::new(
                CrowdSecFirewallBouncerStatisticsCollectorInner {
                    state: CrowdSecFirewallBouncerStatisticsState::Unavailable,
                    policy_generation: 0,
                    next_sample_at: None,
                    last_sample: None,
                },
            )),
            configuration,
            data_dir: data_dir.to_string(),
        }
    }

    pub fn samples(&self) -> CrowdSecFirewallBouncerStatisticsSamplesResponse {
        if self.configuration.configuration().ok().flatten().is_none() {
            return CrowdSecFirewallBouncerStatisticsSamplesResponse {
                state: CrowdSecFirewallBouncerStatisticsState::Unavailable,
                samples: vec![],
            };
        }

        let samples = match cached_samples(&self.data_dir) {
            Ok(samples) => samples,
            Err(error) => {
                error!("Reading CrowdSec Firewall Bouncer statistics cache ({error})");
                return CrowdSecFirewallBouncerStatisticsSamplesResponse {
                    state: CrowdSecFirewallBouncerStatisticsState::Unavailable,
                    samples: vec![],
                };
            }
        };
        let collector = self.inner.lock().unwrap();

        CrowdSecFirewallBouncerStatisticsSamplesResponse {
            state: collector.state.clone(),
            samples,
        }
    }

    pub fn take_samples(
        &self,
    ) -> std::io::Result<CrowdSecFirewallBouncerStatisticsSamplesResponse> {
        let Some(configuration) = self.configuration.configuration()? else {
            return Ok(CrowdSecFirewallBouncerStatisticsSamplesResponse {
                state: CrowdSecFirewallBouncerStatisticsState::Unavailable,
                samples: vec![],
            });
        };

        Ok(CrowdSecFirewallBouncerStatisticsSamplesResponse {
            state: self.inner.lock().unwrap().state.clone(),
            samples: take_cached_samples(&self.data_dir, configuration.request_max_samples)?,
        })
    }

    pub fn reset_after_policy_load(&self) -> std::io::Result<()> {
        if self.configuration.configuration()?.is_none() {
            return Ok(());
        }

        self.start_new_policy_generation()?;
        let mut collector = self.inner.lock().unwrap();
        collector.next_sample_at = None;
        collector.state = CrowdSecFirewallBouncerStatisticsState::Unavailable;
        collector.last_sample = None;

        Ok(())
    }

    pub fn start(&self, cfg: Arc<Config>) {
        let collector = self.clone();

        thread::spawn(move || {
            let runtime = match Runtime::new() {
                Ok(runtime) => runtime,
                Err(error) => {
                    error!("Starting CrowdSec Firewall Bouncer statistics runtime ({error})");
                    return;
                }
            };

            runtime.block_on(async move {
                info!(
                    "Starting CrowdSec Firewall Bouncer statistics collector thread (id: {})",
                    thread_id::get()
                );

                collector.initialize(&cfg).await;

                loop {
                    collector.collect(&cfg).await;
                    thread::sleep(Duration::from_secs(1));
                }
            })
        });
    }

    async fn initialize(&self, cfg: &Config) {
        let configuration = match self.load_persisted_configuration(cfg.etc_dir) {
            Ok(Some(configuration)) => configuration,
            Ok(None) => return,
            Err(error) => {
                error!("Loading CrowdSec Firewall Bouncer statistics configuration ({error})");
                self.set_unavailable();
                return;
            }
        };

        let previous_sample = match cached_samples(&self.data_dir) {
            Ok(samples) => samples.last().cloned(),
            Err(error) => {
                error!("Reading CrowdSec Firewall Bouncer statistics cache ({error})");
                self.set_unavailable();
                return;
            }
        };
        let Some(previous_sample) = previous_sample else {
            if configuration.enabled {
                if let Err(error) = self.start_new_policy_generation() {
                    error!(
                        "Starting a new CrowdSec Firewall Bouncer statistics generation ({error})"
                    );
                    self.set_unavailable();
                }
            }
            return;
        };

        self.set_policy_generation(previous_sample.policy_generation);
        self.set_last_sample(Some(previous_sample.clone()));

        if !configuration.enabled {
            return;
        }

        let counters = match self.read_counters(cfg).await {
            Ok(counters) => counters,
            Err(error) => {
                debug!("CrowdSec Firewall Bouncer statistics are unavailable ({error})");
                self.set_unavailable();
                return;
            }
        };

        if blocking_rule_counters_decreased(&previous_sample, &counters) {
            if let Err(error) = self.start_new_policy_generation() {
                error!("Starting a new CrowdSec Firewall Bouncer statistics generation ({error})");
                self.set_unavailable();
            }
        }
    }

    async fn collect(&self, cfg: &Config) {
        let configuration = match self.configuration.configuration() {
            Ok(Some(configuration)) => configuration,
            Ok(None) => match self.load_persisted_configuration(cfg.etc_dir) {
                Ok(Some(configuration)) => configuration,
                Ok(None) => {
                    self.set_unavailable();
                    return;
                }
                Err(error) => {
                    error!("Loading CrowdSec Firewall Bouncer statistics configuration ({error})");
                    self.set_unavailable();
                    return;
                }
            },
            Err(error) => {
                error!("Loading CrowdSec Firewall Bouncer statistics configuration ({error})");
                self.set_unavailable();
                return;
            }
        };

        if !configuration.enabled || !self.sampling_is_due(configuration.sampling_interval) {
            return;
        }

        let counters = self.read_counters(cfg).await;

        match counters {
            Ok(counters) => {
                let _guard = cfg.mutex.crowdsec.lock().await;
                let sample = CrowdSecFirewallBouncerStatisticsSample {
                    collected_at: DateTime::<Utc>::from(SystemTime::now())
                        .to_rfc3339_opts(SecondsFormat::Millis, true),
                    policy_generation: self.policy_generation(),
                    ipv4_input: counters.ipv4_input,
                    ipv4_forward: counters.ipv4_forward,
                    ipv6_input: counters.ipv6_input,
                    ipv6_forward: counters.ipv6_forward,
                    addresses: counters.addresses,
                };

                if self.should_store_sample(&sample) {
                    self.store_sample(sample, configuration.cache_max_size);
                }
            }
            Err(error) => {
                debug!("CrowdSec Firewall Bouncer statistics are unavailable ({error})");
                self.set_unavailable();
            }
        }
    }

    fn load_persisted_configuration(
        &self,
        etc_dir: &str,
    ) -> std::io::Result<Option<CrowdSecFirewallBouncerStatisticsConfig>> {
        let configuration = CrowdSecFirewallBouncerStatisticsConfig::load(etc_dir)?;
        if let Some(configuration) = &configuration {
            self.configuration.replace(configuration.clone())?;
        }

        Ok(configuration)
    }

    async fn read_counters(
        &self,
        cfg: &Config,
    ) -> crate::errors::Result<crate::crowdsec::statistics::CrowdSecFirewallBouncerBlockingCounters>
    {
        {
            debug!(
                "Locking CrowdSec mutex for Firewall Bouncer statistics (thread id: {})",
                thread_id::get()
            );
            let _guard = cfg.mutex.crowdsec.lock().await;
            let result = async {
                let backend = bouncers::active_backend().await?;
                bouncers::collect_blocking_statistics(backend).await
            }
            .await;
            debug!(
                "Releasing CrowdSec mutex for Firewall Bouncer statistics (thread id: {})",
                thread_id::get()
            );
            result
        }
    }

    fn sampling_is_due(&self, sampling_interval: u64) -> bool {
        let mut collector = self.inner.lock().unwrap();
        let now = Instant::now();

        if collector
            .next_sample_at
            .is_some_and(|next_sample_at| next_sample_at > now)
        {
            return false;
        }

        collector.next_sample_at = Some(now + Duration::from_secs(sampling_interval));
        true
    }

    fn policy_generation(&self) -> u64 {
        self.inner.lock().unwrap().policy_generation
    }

    fn set_policy_generation(&self, policy_generation: u64) {
        self.inner.lock().unwrap().policy_generation = policy_generation;
    }

    fn set_last_sample(&self, sample: Option<CrowdSecFirewallBouncerStatisticsSample>) {
        self.inner.lock().unwrap().last_sample = sample;
    }

    fn should_store_sample(&self, sample: &CrowdSecFirewallBouncerStatisticsSample) -> bool {
        self.inner
            .lock()
            .unwrap()
            .last_sample
            .as_ref()
            .is_none_or(|previous| !samples_have_same_counters(previous, sample))
    }

    fn start_new_policy_generation(&self) -> std::io::Result<()> {
        let current_generation = self.policy_generation();
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(std::io::Error::other)?
            .as_millis() as u64;
        self.set_policy_generation(timestamp.max(current_generation.saturating_add(1)));

        Ok(())
    }

    fn set_unavailable(&self) {
        self.inner.lock().unwrap().state = CrowdSecFirewallBouncerStatisticsState::Unavailable;
    }

    fn store_sample(&self, sample: CrowdSecFirewallBouncerStatisticsSample, cache_max_size: usize) {
        match append_cached_sample(&self.data_dir, sample.clone(), cache_max_size) {
            Ok(()) => {
                let mut collector = self.inner.lock().unwrap();
                collector.state = CrowdSecFirewallBouncerStatisticsState::Available;
                collector.last_sample = Some(sample);
            }
            Err(error) => {
                error!("Writing CrowdSec Firewall Bouncer statistics cache ({error})");
                self.set_unavailable();
            }
        }
    }
}

fn samples_have_same_counters(
    previous: &CrowdSecFirewallBouncerStatisticsSample,
    current: &CrowdSecFirewallBouncerStatisticsSample,
) -> bool {
    previous.policy_generation == current.policy_generation
        && previous.ipv4_input == current.ipv4_input
        && previous.ipv4_forward == current.ipv4_forward
        && previous.ipv6_input == current.ipv6_input
        && previous.ipv6_forward == current.ipv6_forward
        && previous.addresses == current.addresses
}

fn blocking_rule_counters_decreased(
    previous: &CrowdSecFirewallBouncerStatisticsSample,
    current: &crate::crowdsec::statistics::CrowdSecFirewallBouncerBlockingCounters,
) -> bool {
    previous.ipv4_input.packets > current.ipv4_input.packets
        || previous.ipv4_input.bytes > current.ipv4_input.bytes
        || previous.ipv4_forward.packets > current.ipv4_forward.packets
        || previous.ipv4_forward.bytes > current.ipv4_forward.bytes
        || previous.ipv6_input.packets > current.ipv6_input.packets
        || previous.ipv6_input.bytes > current.ipv6_input.bytes
        || previous.ipv6_forward.packets > current.ipv6_forward.packets
        || previous.ipv6_forward.bytes > current.ipv6_forward.bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crowdsec::statistics::{
        CrowdSecFirewallBouncerAddressCounter, CrowdSecFirewallBouncerBlockingCounters,
        CrowdSecFirewallBouncerCounter,
    };

    fn sample(address: &str) -> CrowdSecFirewallBouncerStatisticsSample {
        CrowdSecFirewallBouncerStatisticsSample {
            collected_at: "2026-10-19T10:00:00.000Z".to_string(),
            policy_generation: 0,
            ipv4_input: CrowdSecFirewallBouncerCounter::default(),
            ipv4_forward: CrowdSecFirewallBouncerCounter::default(),
            ipv6_input: CrowdSecFirewallBouncerCounter::default(),
            ipv6_forward: CrowdSecFirewallBouncerCounter::default(),
            addresses: vec![CrowdSecFirewallBouncerAddressCounter {
                address: address.to_string(),
                packets: 1,
                bytes: 100,
            }],
        }
    }

    #[test]
    fn retains_only_samples_that_fit_the_cache() {
        let root = std::env::temp_dir().join(format!(
            "fwcloud-crowdsec-statistics-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let configuration = CrowdSecFirewallBouncerStatisticsConfigStore::default();
        configuration.replace(Default::default()).unwrap();
        let collector =
            CrowdSecFirewallBouncerStatisticsCollector::new(root.to_str().unwrap(), configuration);
        let first = sample("192.0.2.1");
        let second = sample("192.0.2.2");
        let cache_max_size = serde_json::to_vec(&first).unwrap().len() + 1;

        collector.store_sample(first, cache_max_size);
        collector.store_sample(second, cache_max_size);

        let samples = collector.samples();
        assert_eq!(
            samples.state,
            CrowdSecFirewallBouncerStatisticsState::Available
        );
        assert_eq!(samples.samples.len(), 1);
        assert_eq!(samples.samples[0].addresses[0].address, "192.0.2.2");

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn preserves_cached_samples_and_starts_a_new_policy_generation() {
        let root = std::env::temp_dir().join(format!(
            "fwcloud-crowdsec-statistics-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let configuration = CrowdSecFirewallBouncerStatisticsConfigStore::default();
        configuration.replace(Default::default()).unwrap();
        let collector =
            CrowdSecFirewallBouncerStatisticsCollector::new(root.to_str().unwrap(), configuration);

        collector.store_sample(sample("192.0.2.1"), 1024 * 1024);
        collector.reset_after_policy_load().unwrap();

        assert_eq!(collector.samples().samples.len(), 1);
        assert_eq!(collector.samples().samples[0].policy_generation, 0);
        assert!(collector.policy_generation() > 0);

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn detects_decreased_blocking_rule_counters() {
        let mut previous = sample("192.0.2.1");
        previous.ipv4_input = CrowdSecFirewallBouncerCounter {
            packets: 10,
            bytes: 1000,
        };
        let current = CrowdSecFirewallBouncerBlockingCounters {
            ipv4_input: CrowdSecFirewallBouncerCounter {
                packets: 9,
                bytes: 1000,
            },
            ..Default::default()
        };

        assert!(blocking_rule_counters_decreased(&previous, &current));
    }

    #[test]
    fn accepts_increasing_blocking_rule_counters() {
        let mut previous = sample("192.0.2.1");
        previous.ipv6_forward = CrowdSecFirewallBouncerCounter {
            packets: 10,
            bytes: 1000,
        };
        let current = CrowdSecFirewallBouncerBlockingCounters {
            ipv6_forward: CrowdSecFirewallBouncerCounter {
                packets: 10,
                bytes: 1001,
            },
            ..Default::default()
        };

        assert!(!blocking_rule_counters_decreased(&previous, &current));
    }

    #[test]
    fn ignores_samples_with_unchanged_counters() {
        let mut previous = sample("192.0.2.1");
        previous.ipv4_input = CrowdSecFirewallBouncerCounter {
            packets: 12,
            bytes: 3456,
        };
        let mut current = previous.clone();
        current.collected_at = "2026-10-19T10:00:05.000Z".to_string();

        assert!(samples_have_same_counters(&previous, &current));

        current.ipv4_input.packets += 1;
        assert!(!samples_have_same_counters(&previous, &current));
    }

    #[test]
    fn stores_the_first_sample_and_skips_unchanged_ones() {
        let root = std::env::temp_dir().join(format!(
            "fwcloud-crowdsec-statistics-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let configuration = CrowdSecFirewallBouncerStatisticsConfigStore::default();
        configuration.replace(Default::default()).unwrap();
        let collector =
            CrowdSecFirewallBouncerStatisticsCollector::new(root.to_str().unwrap(), configuration);
        let first = sample("192.0.2.1");

        assert!(collector.should_store_sample(&first));
        collector.store_sample(first.clone(), 1024 * 1024);
        assert!(!collector.should_store_sample(&first));

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn disabled_sampling_preserves_the_configuration_without_collecting_samples() {
        let root = std::env::temp_dir().join(format!(
            "fwcloud-crowdsec-statistics-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let configuration = CrowdSecFirewallBouncerStatisticsConfigStore::default();
        let disabled = CrowdSecFirewallBouncerStatisticsConfig {
            enabled: false,
            sampling_interval: 15,
            request_max_samples: 500,
            cache_max_size: 1024,
        };
        configuration.replace(disabled.clone()).unwrap();
        let collector = CrowdSecFirewallBouncerStatisticsCollector::new(
            root.to_str().unwrap(),
            configuration.clone(),
        );

        futures::executor::block_on(collector.collect(&crate::config::Config::new().unwrap()));

        assert_eq!(configuration.configuration().unwrap(), Some(disabled));
        assert!(collector.samples().samples.is_empty());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reloads_the_persisted_configuration_when_the_store_is_empty() {
        let root = std::env::temp_dir().join(format!(
            "fwcloud-crowdsec-statistics-{}",
            uuid::Uuid::new_v4()
        ));
        let etc_dir = root.join("etc");
        let data_dir = root.join("data");
        std::fs::create_dir_all(&etc_dir).unwrap();
        std::fs::create_dir_all(&data_dir).unwrap();

        let expected = CrowdSecFirewallBouncerStatisticsConfig {
            enabled: true,
            sampling_interval: 2,
            request_max_samples: 1000,
            cache_max_size: 1024,
        };
        expected.save(etc_dir.to_str().unwrap()).unwrap();

        let configuration = CrowdSecFirewallBouncerStatisticsConfigStore::default();
        let collector = CrowdSecFirewallBouncerStatisticsCollector::new(
            data_dir.to_str().unwrap(),
            configuration.clone(),
        );

        assert_eq!(
            collector
                .load_persisted_configuration(etc_dir.to_str().unwrap())
                .unwrap(),
            Some(expected.clone())
        );
        assert_eq!(configuration.configuration().unwrap(), Some(expected));

        std::fs::remove_dir_all(root).unwrap();
    }
}
