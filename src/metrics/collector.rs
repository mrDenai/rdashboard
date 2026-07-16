use std::{fs, path::PathBuf};

use crate::domain::{HostTelemetry, ObservationStatus, PsiMeasurement};

use super::{
    CpuTimes, NetworkTotals, parse_loadavg, parse_meminfo, parse_net_dev, parse_proc_stat,
    parse_psi_avg10,
};

#[derive(Clone, Copy, Debug)]
struct PreviousSample {
    observed_at_ms: i64,
    cpu: Option<CpuTimes>,
    network: Option<NetworkTotals>,
}

#[derive(Debug)]
pub struct HostCollector {
    proc_root: PathBuf,
    disk_path: PathBuf,
    previous: Option<PreviousSample>,
}

impl HostCollector {
    pub fn linux(disk_path: impl Into<PathBuf>) -> Self {
        Self::new("/proc", disk_path)
    }

    pub fn new(proc_root: impl Into<PathBuf>, disk_path: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
            disk_path: disk_path.into(),
            previous: None,
        }
    }

    pub fn collect(&mut self, observed_at_ms: i64) -> HostTelemetry {
        let mut partial_reasons = Vec::new();

        let cpu = self.read_and_parse("stat", parse_proc_stat, &mut partial_reasons);
        let cpu_percent = self.previous.and_then(|previous| {
            let current = cpu?;
            let previous = previous.cpu?;
            current.usage_since(previous)
        });

        let load = self.read_and_parse("loadavg", parse_loadavg, &mut partial_reasons);
        let memory = self.read_and_parse("meminfo", parse_meminfo, &mut partial_reasons);
        let network = self.read_and_parse("net/dev", parse_net_dev, &mut partial_reasons);

        let elapsed_ms = self.previous.and_then(|previous| {
            let elapsed_ms = observed_at_ms.checked_sub(previous.observed_at_ms)?;
            (elapsed_ms > 0)
                .then(|| u64::try_from(elapsed_ms).ok())
                .flatten()
        });
        let (rx_rate, tx_rate) = network_rates(network, self.previous, elapsed_ms);

        let disk = match (
            fs2::total_space(&self.disk_path),
            fs2::available_space(&self.disk_path),
        ) {
            (Ok(total), Ok(available)) if available <= total => Some((total, available)),
            (Ok(_), Ok(_)) => {
                partial_reasons.push("disk: inconsistent values".to_owned());
                None
            }
            (total, available) => {
                let total = total
                    .err()
                    .map_or_else(|| "ok".to_owned(), |error| format!("total error: {error}"));
                let available = available.err().map_or_else(
                    || "ok".to_owned(),
                    |error| format!("available error: {error}"),
                );
                partial_reasons.push(format!("disk: {total}; {available}"));
                None
            }
        };

        let psi = PsiMeasurement {
            cpu_some_avg10: self.read_and_parse(
                "pressure/cpu",
                parse_psi_avg10,
                &mut partial_reasons,
            ),
            memory_some_avg10: self.read_and_parse(
                "pressure/memory",
                parse_psi_avg10,
                &mut partial_reasons,
            ),
            io_some_avg10: self.read_and_parse(
                "pressure/io",
                parse_psi_avg10,
                &mut partial_reasons,
            ),
        };

        self.previous = Some(PreviousSample {
            observed_at_ms,
            cpu,
            network,
        });

        HostTelemetry {
            observed_at_ms,
            status: if partial_reasons.is_empty() {
                ObservationStatus::Fresh
            } else {
                ObservationStatus::Partial
            },
            cpu_percent,
            load_1: load.map(|value| value.one),
            load_5: load.map(|value| value.five),
            load_15: load.map(|value| value.fifteen),
            memory_total_bytes: memory.map(|value| value.total_bytes),
            memory_available_bytes: memory.map(|value| value.available_bytes),
            swap_total_bytes: memory.map(|value| value.swap_total_bytes),
            swap_free_bytes: memory.map(|value| value.swap_free_bytes),
            disk_total_bytes: disk.map(|value| value.0),
            disk_available_bytes: disk.map(|value| value.1),
            network_rx_bytes: network.map(|value| value.rx_bytes),
            network_tx_bytes: network.map(|value| value.tx_bytes),
            network_rx_bytes_per_second: rx_rate,
            network_tx_bytes_per_second: tx_rate,
            psi,
            partial_reasons,
        }
    }

    fn read_and_parse<T, E>(
        &self,
        relative_path: &str,
        parser: impl FnOnce(&str) -> Result<T, E>,
        partial_reasons: &mut Vec<String>,
    ) -> Option<T>
    where
        E: std::fmt::Display,
    {
        let path = self.proc_root.join(relative_path);
        match fs::read_to_string(&path) {
            Ok(input) => match parser(&input) {
                Ok(value) => Some(value),
                Err(error) => {
                    partial_reasons.push(format!("{relative_path}: {error}"));
                    None
                }
            },
            Err(error) => {
                partial_reasons.push(format!("{relative_path}: {error}"));
                None
            }
        }
    }
}

fn network_rates(
    current: Option<NetworkTotals>,
    previous: Option<PreviousSample>,
    elapsed_ms: Option<u64>,
) -> (Option<u64>, Option<u64>) {
    let Some((current, previous, elapsed)) = current
        .zip(previous.and_then(|sample| sample.network))
        .zip(elapsed_ms)
        .map(|((current, previous), elapsed)| (current, previous, elapsed))
    else {
        return (None, None);
    };
    if elapsed == 0 {
        return (None, None);
    }
    let rx = current
        .rx_bytes
        .checked_sub(previous.rx_bytes)
        .and_then(|delta| bytes_per_second(delta, elapsed));
    let tx = current
        .tx_bytes
        .checked_sub(previous.tx_bytes)
        .and_then(|delta| bytes_per_second(delta, elapsed));
    (rx, tx)
}

fn bytes_per_second(delta: u64, elapsed_ms: u64) -> Option<u64> {
    let scaled = u128::from(delta).checked_mul(1000)? / u128::from(elapsed_ms);
    u64::try_from(scaled).ok()
}
