use std::{fs, thread, time::Duration};

use rdashboard::metrics::{
    HostCollector, parse_loadavg, parse_meminfo, parse_net_dev, parse_proc_stat, parse_psi_avg10,
};
use tempfile::tempdir;

#[test]
fn proc_parsers_extract_units_and_skip_loopback_traffic() {
    let cpu = parse_proc_stat("cpu  100 2 30 400 10 3 4 1 0 0\ncpu0 1 2 3 4\n")
        .unwrap_or_else(|error| panic!("CPU fixture: {error}"));
    assert_eq!(cpu.idle, 410);
    assert_eq!(cpu.total, 550);

    let memory = parse_meminfo(
        "MemTotal: 1000 kB\nMemAvailable: 250 kB\nSwapTotal: 200 kB\nSwapFree: 150 kB\n",
    )
    .unwrap_or_else(|error| panic!("memory fixture: {error}"));
    assert_eq!(memory.total_bytes, 1_024_000);
    assert_eq!(memory.available_bytes, 256_000);

    let load = parse_loadavg("0.25 1.50 2.75 1/100 42\n")
        .unwrap_or_else(|error| panic!("load fixture: {error}"));
    assert_eq!((load.one, load.five, load.fifteen), (0.25, 1.5, 2.75));

    let network = parse_net_dev(
        "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\nlo: 100 0 0 0 0 0 0 0 100 0 0 0 0 0 0 0\neth0: 500 0 0 0 0 0 0 0 700 0 0 0 0 0 0 0\n",
    )
    .unwrap_or_else(|error| panic!("network fixture: {error}"));
    assert_eq!((network.rx_bytes, network.tx_bytes), (500, 700));

    let pressure = parse_psi_avg10("some avg10=1.25 avg60=0.50 avg300=0.10 total=7\n")
        .unwrap_or_else(|error| panic!("PSI fixture: {error}"));
    assert!((pressure - 1.25).abs() < f64::EPSILON);
}

#[test]
fn collector_reports_missing_sources_as_partial_instead_of_zero() {
    let proc = tempdir().unwrap_or_else(|error| panic!("temp proc: {error}"));
    let disk = tempdir().unwrap_or_else(|error| panic!("temp disk: {error}"));
    fs::write(proc.path().join("loadavg"), "0.25 0.50 0.75 1/10 99\n")
        .unwrap_or_else(|error| panic!("load fixture: {error}"));
    let mut collector = HostCollector::new(proc.path(), disk.path());
    let sample = collector.collect(1_000);

    assert_eq!(sample.load_1, Some(0.25));
    assert_eq!(sample.memory_total_bytes, None);
    assert!(
        sample
            .partial_reasons
            .iter()
            .any(|reason| reason.starts_with("meminfo:"))
    );
}

#[cfg(target_os = "linux")]
#[test]
fn collector_reads_real_linux_host_without_mock_values() {
    let disk = tempdir().unwrap_or_else(|error| panic!("temp disk: {error}"));
    let mut collector = HostCollector::linux(disk.path());
    let first = collector.collect(1_000);
    thread::sleep(Duration::from_millis(100));
    let second = collector.collect(1_100);

    assert!(first.memory_total_bytes.is_some());
    assert!(first.disk_total_bytes.is_some());
    assert!(first.load_1.is_some());
    assert!(second.cpu_percent.is_some());
}
