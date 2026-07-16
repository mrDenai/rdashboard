#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use rdashboard::{
        adapter_entrypoint::FixedAdapterInvocationV1,
        kamal_adapter::{
            KamalAdapterError, execute_kamal_step_with_clock, runtime::InstalledKamalRuntimeV1,
        },
        phase6::FixedAdapterProfileV1,
    };

    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let invocation = FixedAdapterInvocationV1::parse_installed(&arguments)?;
    let profile = match invocation.subcommand.as_str() {
        "bootstrap-v1" => FixedAdapterProfileV1::KamalBootstrapDeploy,
        "deploy-v1" => FixedAdapterProfileV1::KamalCandidateDeploy,
        "rollback-v1" => FixedAdapterProfileV1::KamalCodeRollback,
        _ => return Err("unsupported fixed Kamal adapter subcommand".into()),
    };
    let job =
        rdashboard::adapter_entrypoint::LoadedAdapterJobV1::load_installed(&invocation, profile)?;
    if job.existing_result()?.is_some() || job.reconcile_pending_result()?.is_some() {
        return Ok(());
    }
    let job_directory = invocation
        .result_path
        .parent()
        .ok_or("fixed Kamal adapter result path has no job directory")?;
    let mut runtime = InstalledKamalRuntimeV1::new(job_directory, &job.spec, job.request.sequence)?;
    let result = execute_kamal_step_with_clock(&job, &mut runtime, || {
        rdashboard::unix_time_ms().map_err(|_| KamalAdapterError::InvalidClock)
    })?;
    job.publish_result(&result)?;
    Ok(())
}

#[cfg(not(unix))]
fn main() {
    eprintln!("kamal-adapter is supported only on Unix");
    std::process::exit(1);
}
