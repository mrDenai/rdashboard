fn main() -> Result<(), rdashboard::self_release_build::SelfReleaseBuildError> {
    if std::env::args_os().len() != 1 {
        return Err(rdashboard::self_release_build::SelfReleaseBuildError::InvalidRequest);
    }
    let _ = rdashboard::self_release_build::execute_installed_self_release_build()?;
    Ok(())
}
