use std::process::ExitCode;

use rdashboard::rootless_oci_build::execute_installed_rootless_oci_build;

fn main() -> ExitCode {
    if std::env::args_os().len() != 1 {
        eprintln!(
            "reason_code=rootless_oci_build_invocation_invalid summary=the fixed OCI build client accepts no arguments"
        );
        return ExitCode::FAILURE;
    }
    match execute_installed_rootless_oci_build() {
        Ok(result) => {
            println!(
                "rootless OCI build complete: result_digest={} image_digest={} archive_bytes={}",
                result.result_digest,
                result.image_manifest_digest.as_str(),
                result.archive_bytes
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("reason_code={} summary={error}", error.reason_code());
            ExitCode::FAILURE
        }
    }
}
