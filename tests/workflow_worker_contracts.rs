#[test]
fn generic_worker_service_is_shared_non_root_and_storage_bounded() {
    let service = include_str!("../deploy/systemd/rdashboard-worker.service");
    let lines = service.lines().collect::<Vec<_>>();

    for required in [
        "User=rdashboard-worker",
        "Group=rdashboard-worker",
        "SupplementaryGroups=rdashboard-build-readers",
        "EnvironmentFile=/etc/rdashboard/workflow-worker.env",
        "PrivateNetwork=yes",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "RestrictAddressFamilies=AF_UNIX",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
        "ReadOnlyPaths=/var/lib/rdashboard-build/source-exports",
        "ReadWritePaths=/var/lib/rdashboard-build/preparation",
        "TasksMax=128",
        "MemoryMax=256M",
        "MemorySwapMax=0",
        "CPUQuota=100%",
        "TimeoutStopSec=30s",
    ] {
        assert!(
            lines.contains(&required),
            "generic worker service must contain {required}"
        );
    }
    assert!(service.contains("rdashboard-workflow-gateway.service"));
    assert!(service.contains("rdashboard-workflow-launcher.service"));
    assert!(service.contains("/run/docker.sock"));
    assert!(service.contains("/run/containerd"));
    assert!(!service.contains("ralert-worker"));
    assert!(!service.contains("rimg-worker"));

    let tmpfiles = include_str!("../deploy/systemd/rdashboard-tmpfiles.conf");
    assert!(tmpfiles.lines().any(|line| {
        line == "d /var/lib/rdashboard-build/preparation 0700 rdashboard-worker rdashboard-worker -"
    }));
}
