use std::process::ExitCode;

use rdashboard::self_update::VERSIONED_SELF_RELEASE_BINARIES;

fn main() -> ExitCode {
    if std::env::args_os().nth(1).is_some() {
        eprintln!("ERROR: rdashboard-self-release-inventory accepts no arguments.");
        return ExitCode::from(64);
    }
    for binary in VERSIONED_SELF_RELEASE_BINARIES {
        println!("{binary}");
    }
    ExitCode::SUCCESS
}
