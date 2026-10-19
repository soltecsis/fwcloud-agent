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
use futures::executor::block_on;
use log::{debug, error, info};
use std::{
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime},
};

use crate::{
    config::Config,
    crowdsec::{
        bouncers,
        statistics::{
            append_cached_sample, cached_samples, take_cached_samples,
            CrowdSecFirewallBouncerStatisticsConfigStore, CrowdSecFirewallBouncerStatisticsSample,
            CrowdSecFirewallBouncerStatisticsSamplesResponse,
            CrowdSecFirewallBouncerStatisticsState,
        },
    },
};

struct CrowdSecFirewallBouncerStatisticsCollectorInner {
    state: CrowdSecFirewallBouncerStatisticsState,
    policy_generation: u64,
    next_sample_at: Option<Instant>,
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

    pub fn start(&self, cfg: Arc<Config>) {
        let collector = self.clone();

        thread::spawn(move || {
            block_on(async move {
                info!(
                    "Starting CrowdSec Firewall Bouncer statistics collector thread (id: {})",
                    thread_id::get()
                );

                loop {
                    collector.collect(&cfg).await;
                    thread::sleep(Duration::from_secs(1));
                }
            })
        });
    }

    async fn collect(&self, cfg: &Config) {
        let configuration = match self.configuration.configuration() {
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
        };

        if !configuration.enabled || !self.sampling_is_due(configuration.sampling_interval) {
            return;
        }

        let counters = {
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
        };

        match counters {
            Ok(counters) => {
                let _guard = cfg.mutex.crowdsec.lock().await;
                self.store_sample(
                    CrowdSecFirewallBouncerStatisticsSample {
                        collected_at: DateTime::<Utc>::from(SystemTime::now())
                            .to_rfc3339_opts(SecondsFormat::Millis, true),
                        policy_generation: self.policy_generation(),
                        ipv4_input: counters.ipv4_input,
                        ipv4_forward: counters.ipv4_forward,
                        ipv6_input: counters.ipv6_input,
                        ipv6_forward: counters.ipv6_forward,
                        addresses: counters.addresses,
                    },
                    configuration.cache_max_size,
                );
            }
            Err(error) => {
                debug!("CrowdSec Firewall Bouncer statistics are unavailable ({error})");
                self.set_unavailable();
            }
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

    fn set_unavailable(&self) {
        self.inner.lock().unwrap().state = CrowdSecFirewallBouncerStatisticsState::Unavailable;
    }

    fn store_sample(&self, sample: CrowdSecFirewallBouncerStatisticsSample, cache_max_size: usize) {
        match append_cached_sample(&self.data_dir, sample, cache_max_size) {
            Ok(()) => {
                self.inner.lock().unwrap().state =
                    CrowdSecFirewallBouncerStatisticsState::Available;
            }
            Err(error) => {
                error!("Writing CrowdSec Firewall Bouncer statistics cache ({error})");
                self.set_unavailable();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crowdsec::statistics::{
        CrowdSecFirewallBouncerAddressCounter, CrowdSecFirewallBouncerCounter,
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
}
