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
    collections::VecDeque,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime},
};

use crate::{
    config::Config,
    crowdsec::{
        bouncers,
        statistics::{
            CrowdSecFirewallBouncerStatisticsConfigStore, CrowdSecFirewallBouncerStatisticsSample,
            CrowdSecFirewallBouncerStatisticsSamplesResponse,
            CrowdSecFirewallBouncerStatisticsState,
        },
    },
};

struct CrowdSecFirewallBouncerStatisticsCollectorInner {
    samples: VecDeque<CrowdSecFirewallBouncerStatisticsSample>,
    state: CrowdSecFirewallBouncerStatisticsState,
    policy_generation: u64,
    next_sample_at: Option<Instant>,
}

#[derive(Clone)]
pub struct CrowdSecFirewallBouncerStatisticsCollector {
    inner: Arc<Mutex<CrowdSecFirewallBouncerStatisticsCollectorInner>>,
    configuration: CrowdSecFirewallBouncerStatisticsConfigStore,
}

impl CrowdSecFirewallBouncerStatisticsCollector {
    pub fn new(configuration: CrowdSecFirewallBouncerStatisticsConfigStore) -> Self {
        CrowdSecFirewallBouncerStatisticsCollector {
            inner: Arc::new(Mutex::new(
                CrowdSecFirewallBouncerStatisticsCollectorInner {
                    samples: VecDeque::new(),
                    state: CrowdSecFirewallBouncerStatisticsState::Unavailable,
                    policy_generation: 0,
                    next_sample_at: None,
                },
            )),
            configuration,
        }
    }

    pub fn samples(&self) -> CrowdSecFirewallBouncerStatisticsSamplesResponse {
        if self.configuration.configuration().ok().flatten().is_none() {
            return CrowdSecFirewallBouncerStatisticsSamplesResponse {
                state: CrowdSecFirewallBouncerStatisticsState::Unavailable,
                samples: vec![],
            };
        }

        let collector = self.inner.lock().unwrap();

        CrowdSecFirewallBouncerStatisticsSamplesResponse {
            state: collector.state.clone(),
            samples: collector.samples.iter().cloned().collect(),
        }
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
            Ok(counters) => self.store_sample(
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
            ),
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
        let sample_size = match serde_json::to_vec(&sample) {
            Ok(sample) => sample.len(),
            Err(error) => {
                error!("Serializing CrowdSec Firewall Bouncer statistics sample ({error})");
                return;
            }
        };
        let mut collector = self.inner.lock().unwrap();

        if sample_size > cache_max_size {
            collector.samples.clear();
            collector.state = CrowdSecFirewallBouncerStatisticsState::Available;
            return;
        }

        let mut cache_size = collector
            .samples
            .iter()
            .filter_map(|sample| serde_json::to_vec(sample).ok())
            .map(|sample| sample.len())
            .sum::<usize>();

        while cache_size + sample_size > cache_max_size {
            let Some(removed) = collector.samples.pop_front() else {
                break;
            };
            cache_size = cache_size.saturating_sub(
                serde_json::to_vec(&removed)
                    .map(|sample| sample.len())
                    .unwrap_or_default(),
            );
        }

        collector.samples.push_back(sample);
        collector.state = CrowdSecFirewallBouncerStatisticsState::Available;
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
        let collector = CrowdSecFirewallBouncerStatisticsCollector::new(
            CrowdSecFirewallBouncerStatisticsConfigStore::default(),
        );
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
    }
}
