use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CpuTimes {
    pub idle: u64,
    pub total: u64,
}

impl CpuTimes {
    pub fn usage_since(self, previous: Self) -> Option<f64> {
        let total_delta = self.total.checked_sub(previous.total)?;
        let idle_delta = self.idle.checked_sub(previous.idle)?;
        if total_delta == 0 || idle_delta > total_delta {
            return None;
        }
        let active_delta = u32::try_from(total_delta - idle_delta).ok()?;
        let total_delta = u32::try_from(total_delta).ok()?;
        Some(100.0 * f64::from(active_delta) / f64::from(total_delta))
    }
}

pub fn parse_proc_stat(input: &str) -> Result<CpuTimes, ParseMetricError> {
    let line = input
        .lines()
        .find(|line| line.starts_with("cpu "))
        .ok_or(ParseMetricError::MissingCpuLine)?;
    let values = line
        .split_ascii_whitespace()
        .skip(1)
        .take(8)
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ParseMetricError::InvalidNumber)?;
    if values.len() < 5 {
        return Err(ParseMetricError::MissingCpuFields);
    }
    let total = values.iter().try_fold(0_u64, |sum, value| {
        sum.checked_add(*value)
            .ok_or(ParseMetricError::ArithmeticOverflow)
    })?;
    let idle = values[3]
        .checked_add(values[4])
        .ok_or(ParseMetricError::ArithmeticOverflow)?;
    Ok(CpuTimes { idle, total })
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LoadAverages {
    pub one: f64,
    pub five: f64,
    pub fifteen: f64,
}

pub fn parse_loadavg(input: &str) -> Result<LoadAverages, ParseMetricError> {
    let mut fields = input.split_ascii_whitespace();
    let parse = |value: Option<&str>| -> Result<f64, ParseMetricError> {
        let parsed = value
            .ok_or(ParseMetricError::MissingLoadFields)?
            .parse::<f64>()
            .map_err(|_| ParseMetricError::InvalidNumber)?;
        if parsed.is_finite() {
            Ok(parsed)
        } else {
            Err(ParseMetricError::InvalidNumber)
        }
    };
    Ok(LoadAverages {
        one: parse(fields.next())?,
        five: parse(fields.next())?,
        fifteen: parse(fields.next())?,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryInfo {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_free_bytes: u64,
}

pub fn parse_meminfo(input: &str) -> Result<MemoryInfo, ParseMetricError> {
    let mut fields = HashMap::new();
    for line in input.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let Some(kibibytes) = value.split_ascii_whitespace().next() else {
            continue;
        };
        if let Ok(kibibytes) = kibibytes.parse::<u64>() {
            fields.insert(name, kibibytes);
        }
    }
    let bytes = |name| {
        fields
            .get(name)
            .ok_or(ParseMetricError::MissingMemoryField(name))?
            .checked_mul(1024)
            .ok_or(ParseMetricError::ArithmeticOverflow)
    };
    let result = MemoryInfo {
        total_bytes: bytes("MemTotal")?,
        available_bytes: bytes("MemAvailable")?,
        swap_total_bytes: bytes("SwapTotal")?,
        swap_free_bytes: bytes("SwapFree")?,
    };
    if result.available_bytes > result.total_bytes
        || result.swap_free_bytes > result.swap_total_bytes
    {
        return Err(ParseMetricError::InconsistentMemory);
    }
    Ok(result)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkTotals {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

pub fn parse_net_dev(input: &str) -> Result<NetworkTotals, ParseMetricError> {
    let mut totals = NetworkTotals {
        rx_bytes: 0,
        tx_bytes: 0,
    };
    let mut interfaces = 0_u32;
    for line in input.lines().skip(2) {
        let Some((interface, fields)) = line.split_once(':') else {
            continue;
        };
        if interface.trim() == "lo" {
            continue;
        }
        let fields = fields.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() < 9 {
            return Err(ParseMetricError::MissingNetworkFields);
        }
        let rx = fields[0]
            .parse::<u64>()
            .map_err(|_| ParseMetricError::InvalidNumber)?;
        let tx = fields[8]
            .parse::<u64>()
            .map_err(|_| ParseMetricError::InvalidNumber)?;
        totals.rx_bytes = totals
            .rx_bytes
            .checked_add(rx)
            .ok_or(ParseMetricError::ArithmeticOverflow)?;
        totals.tx_bytes = totals
            .tx_bytes
            .checked_add(tx)
            .ok_or(ParseMetricError::ArithmeticOverflow)?;
        interfaces += 1;
    }
    if interfaces == 0 {
        return Err(ParseMetricError::MissingNetworkInterface);
    }
    Ok(totals)
}

pub fn parse_psi_avg10(input: &str) -> Result<f64, ParseMetricError> {
    let some = input
        .lines()
        .find(|line| line.starts_with("some "))
        .ok_or(ParseMetricError::MissingPsiSome)?;
    let average = some
        .split_ascii_whitespace()
        .find_map(|field| field.strip_prefix("avg10="))
        .ok_or(ParseMetricError::MissingPsiAverage)?
        .parse::<f64>()
        .map_err(|_| ParseMetricError::InvalidNumber)?;
    if average.is_finite() {
        Ok(average)
    } else {
        Err(ParseMetricError::InvalidNumber)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ParseMetricError {
    #[error("CPU aggregate line is missing")]
    MissingCpuLine,
    #[error("CPU aggregate contains too few fields")]
    MissingCpuFields,
    #[error("load average contains too few fields")]
    MissingLoadFields,
    #[error("memory field {0} is missing")]
    MissingMemoryField(&'static str),
    #[error("memory values are inconsistent")]
    InconsistentMemory,
    #[error("network interface row contains too few fields")]
    MissingNetworkFields,
    #[error("no non-loopback network interface was found")]
    MissingNetworkInterface,
    #[error("PSI some row is missing")]
    MissingPsiSome,
    #[error("PSI avg10 is missing")]
    MissingPsiAverage,
    #[error("metric contains an invalid number")]
    InvalidNumber,
    #[error("metric arithmetic overflowed")]
    ArithmeticOverflow,
}
