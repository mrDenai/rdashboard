pub const GIB: u64 = 1024 * 1024 * 1024;

/// The only persistent domain for repository-independent build inputs, bounded operation state and
/// final artifact assembly. Ownership still separates its children; capacity is shared so identical
/// toolchains and content-addressed inputs are not copied per project or worker.
pub const SHARED_BUILD_STORAGE_ROOT: &str = "/var/lib/rdashboard-build";
pub const SHARED_TOOLCHAIN_STORE_ROOT: &str = "/var/lib/rdashboard-build/toolchains";

/// The shared filesystem must hold one maximum-sized operation plus the reusable preparation and
/// packaging inputs needed to finish it. It is one bound for all projects, not a per-project quota.
pub const SHARED_BUILD_STORAGE_MIN_BYTES: u64 = 16 * GIB;

/// The final-assembly engine is disposable, but its peak overlaps the OCI archive write and must be
/// part of admission rather than treated as already-free cache space.
pub const BUILDKIT_MAX_USED_BYTES: u64 = 1536 * 1024 * 1024;

/// Reclamation starts before this target is crossed. A store may retain less when another owner of
/// the host filesystem consumes the missing space, but it must still attempt its own deterministic
/// cleanup before admitting more replaceable data.
pub const BUILD_STORAGE_GC_TARGET_FREE_BYTES: u64 = 30 * GIB;

/// No build, deployment or backup reservation may reduce host filesystem availability below this
/// recovery floor.
pub const BUILD_STORAGE_MIN_FREE_BYTES: u64 = 20 * GIB;

pub const fn recovery_reserve_bytes(filesystem_total_bytes: u64) -> u64 {
    let fifteen_percent = filesystem_total_bytes.saturating_mul(15).div_ceil(100);
    if fifteen_percent > BUILD_STORAGE_MIN_FREE_BYTES {
        fifteen_percent
    } else {
        BUILD_STORAGE_MIN_FREE_BYTES
    }
}

pub fn required_host_available_bytes(incoming_bytes: u64) -> Option<u64> {
    BUILD_STORAGE_MIN_FREE_BYTES.checked_add(incoming_bytes)
}

pub const fn should_collect(available_bytes: u64) -> bool {
    available_bytes < BUILD_STORAGE_GC_TARGET_FREE_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserve_and_gc_thresholds_are_distinct_and_overflow_safe() {
        assert_eq!(required_host_available_bytes(3 * GIB), Some(23 * GIB));
        assert!(required_host_available_bytes(u64::MAX).is_none());
        assert!(should_collect(29 * GIB));
        assert!(!should_collect(BUILD_STORAGE_GC_TARGET_FREE_BYTES));
        assert_eq!(recovery_reserve_bytes(100 * GIB), 20 * GIB);
        assert_eq!(recovery_reserve_bytes(200 * GIB), 30 * GIB);
    }
}
