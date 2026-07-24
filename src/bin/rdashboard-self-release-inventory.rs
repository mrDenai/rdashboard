use std::{path::Path, process::ExitCode};

use rdashboard::{
    self_release_build::seal_versioned_self_release_inputs,
    self_update::VERSIONED_SELF_RELEASE_BINARIES,
};

fn main() -> ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    match (arguments.next(), arguments.next(), arguments.next()) {
        (None, None, None) => {
            for binary in VERSIONED_SELF_RELEASE_BINARIES {
                println!("{binary}");
            }
            ExitCode::SUCCESS
        }
        (Some(command), Some(root), None) if command == "--seal" => {
            if let Err(error) = seal_versioned_self_release_inputs(Path::new(&root)) {
                eprintln!("ERROR: could not seal canonical self-release inputs: {error}");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!(
                "ERROR: expected no arguments or --seal <absolute target/release directory>."
            );
            ExitCode::from(64)
        }
    }
}
