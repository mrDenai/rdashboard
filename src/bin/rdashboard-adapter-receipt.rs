use rdashboard::{
    execution_receipt::{CaptureEnvironmentV1, capture_installed_terminal_receipt},
    unix_time_ms,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let finished_at_ms = unix_time_ms()?;
    capture_installed_terminal_receipt(&CaptureEnvironmentV1::installed(), finished_at_ms)?;
    Ok(())
}
