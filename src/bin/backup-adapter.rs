#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use rdashboard::{
        adapter_entrypoint::{FixedAdapterInvocationV1, LoadedAdapterJobV1},
        backup_adapter::{
            execute_backup_capture_step, execute_backup_encrypt_step, execute_backup_readback_step,
            execute_backup_upload_step, pipeline_runtime::InstalledBackupPipelineRuntimeV1,
        },
        phase6::FixedAdapterProfileV1,
        rimg_adapter::runtime::InstalledRimgAdminRuntimeV1,
    };

    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let invocation = FixedAdapterInvocationV1::parse_installed(&arguments)?;
    let profile = match invocation.subcommand.as_str() {
        "capture-v1" => FixedAdapterProfileV1::BackupCapture,
        "encrypt-v1" => FixedAdapterProfileV1::BackupEncryptAge,
        "upload-v1" => FixedAdapterProfileV1::BackupUploadGoogleDrive,
        "readback-v1" => FixedAdapterProfileV1::BackupReadbackVerify,
        _ => return Err("unsupported fixed backup adapter subcommand".into()),
    };
    let job = LoadedAdapterJobV1::load_installed(&invocation, profile)?;
    if job.existing_result()?.is_some() || job.reconcile_pending_result()?.is_some() {
        return Ok(());
    }
    let job_directory = invocation
        .result_path
        .parent()
        .ok_or("fixed backup adapter result path has no job directory")?;
    let result = match profile {
        FixedAdapterProfileV1::BackupCapture => {
            let mut runtime = InstalledRimgAdminRuntimeV1::new(job_directory, &job.spec)?;
            execute_backup_capture_step(&job, &mut runtime)?
        }
        FixedAdapterProfileV1::BackupEncryptAge => {
            let mut runtime = InstalledBackupPipelineRuntimeV1::new(
                job_directory,
                &job.spec,
                profile,
                job.request.sequence,
            )?;
            execute_backup_encrypt_step(&job, &mut runtime)?
        }
        FixedAdapterProfileV1::BackupUploadGoogleDrive => {
            let mut runtime = InstalledBackupPipelineRuntimeV1::new(
                job_directory,
                &job.spec,
                profile,
                job.request.sequence,
            )?;
            execute_backup_upload_step(&job, &mut runtime)?
        }
        FixedAdapterProfileV1::BackupReadbackVerify => {
            let mut runtime = InstalledBackupPipelineRuntimeV1::new(
                job_directory,
                &job.spec,
                profile,
                job.request.sequence,
            )?;
            execute_backup_readback_step(&job, &mut runtime)?
        }
        _ => return Err("unsupported fixed backup adapter profile".into()),
    };
    job.publish_result(&result)?;
    Ok(())
}

#[cfg(not(unix))]
fn main() {
    eprintln!("backup-adapter is supported only on Unix");
    std::process::exit(1);
}
