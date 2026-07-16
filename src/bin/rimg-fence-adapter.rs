#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use rdashboard::{
        fence_adapter::{InstalledFenceAdapterRuntimeV1, execute_fence_adapter},
        fence_job::InstalledFenceInvocationV1,
    };

    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let invocation = InstalledFenceInvocationV1::parse(&arguments)?;
    let request = invocation.load_request()?;
    if invocation.existing_result(&request)?.is_some()
        || invocation.reconcile_pending_result(&request)?.is_some()
    {
        return Ok(());
    }
    let mut runtime = InstalledFenceAdapterRuntimeV1::new(std::path::Path::new("/job"), &request)?;
    let result = execute_fence_adapter(&request, &mut runtime, rdashboard::unix_time_ms()?)?;
    invocation.publish_result(&request, &result)?;
    Ok(())
}

#[cfg(not(unix))]
fn main() {
    eprintln!("rimg-fence-adapter is supported only on Unix");
    std::process::exit(1);
}
