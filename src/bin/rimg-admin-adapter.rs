#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use rdashboard::{
        adapter_entrypoint::FixedAdapterInvocationV1,
        phase6::FixedAdapterProfileV1,
        rimg_adapter::{
            RimgAdapterError, execute_rimg_admin_step_with_clock,
            runtime::InstalledRimgAdminRuntimeV1,
        },
    };

    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let invocation = FixedAdapterInvocationV1::parse_installed(&arguments)?;
    let profile = match invocation.subcommand.as_str() {
        "drain-v1" => FixedAdapterProfileV1::RimgDrain,
        "schema-inspect-v1" => FixedAdapterProfileV1::RimgSchemaInspect,
        "migrate-v1" => FixedAdapterProfileV1::RimgMigrate,
        "readiness-v1" => FixedAdapterProfileV1::RimgReadiness,
        "consumer-smoke-v1" => FixedAdapterProfileV1::RimgConsumerSmoke,
        "soak-v1" => FixedAdapterProfileV1::RimgSoakObserve,
        _ => return Err("unsupported fixed rimg adapter subcommand".into()),
    };
    let job =
        rdashboard::adapter_entrypoint::LoadedAdapterJobV1::load_installed(&invocation, profile)?;
    if job.existing_result()?.is_some() || job.reconcile_pending_result()?.is_some() {
        return Ok(());
    }
    let job_directory = invocation
        .result_path
        .parent()
        .ok_or("fixed rimg adapter result path has no job directory")?;
    let mut runtime = InstalledRimgAdminRuntimeV1::new(job_directory, &job.spec)?;
    let result = execute_rimg_admin_step_with_clock(&job, &mut runtime, || {
        rdashboard::unix_time_ms().map_err(|_| RimgAdapterError::InvalidClock)
    })?;
    job.publish_result(&result)?;
    Ok(())
}

#[cfg(not(unix))]
fn main() {
    eprintln!("rimg-admin-adapter is supported only on Unix");
    std::process::exit(1);
}
