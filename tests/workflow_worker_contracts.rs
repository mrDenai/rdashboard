#[test]
fn generic_worker_service_is_shared_non_root_and_storage_bounded() {
    let service = include_str!("../deploy/systemd/rdashboard-worker.service");
    let lines = service.lines().collect::<Vec<_>>();

    for required in [
        "User=rdashboard-worker",
        "Group=rdashboard-worker",
        "SupplementaryGroups=rdashboard-build-readers rdashboard-dependency-fetch",
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
    assert!(service.contains("rdashboard-dependency-fetcher.service"));
    assert!(service.contains("/run/docker.sock"));
    assert!(service.contains("/run/containerd"));
    assert!(!service.contains("ralert-worker"));
    assert!(!service.contains("rimg-worker"));

    let tmpfiles = include_str!("../deploy/systemd/rdashboard-tmpfiles.conf");
    assert!(tmpfiles.lines().any(|line| {
        line == "d /var/lib/rdashboard-build/preparation 0700 rdashboard-worker rdashboard-worker -"
    }));
}

#[test]
fn dependency_fetcher_has_one_public_registry_route_and_no_worker_state() {
    let service = include_str!("../deploy/systemd/rdashboard-dependency-fetcher.service");
    let lines = service.lines().collect::<Vec<_>>();
    for required in [
        "User=rdashboard-dependency-fetcher",
        "Group=rdashboard-dependency-fetch",
        "EnvironmentFile=/etc/rdashboard/workflow-worker.env",
        "RuntimeDirectory=rdashboard-dependency-fetcher",
        "RuntimeDirectoryMode=0750",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
        "MemoryMax=384M",
        "MemorySwapMax=0",
    ] {
        assert!(
            lines.contains(&required),
            "dependency fetcher service must contain {required}"
        );
    }
    assert!(service.contains("/etc/rdashboard/credentials"));
    assert!(service.contains("/var/lib/rdashboard-build"));
    assert!(service.contains("/var/lib/rdashboard-workflow-launcher"));
    assert!(service.contains("/run/docker.sock"));
    assert!(service.contains("UnsetEnvironment=ALL_PROXY HTTP_PROXY HTTPS_PROXY NO_PROXY"));
    assert!(!service.contains("LoadCredential="));
    assert!(!service.contains("ReadWritePaths="));
    assert!(!service.contains("PrivateNetwork=yes"));
}
