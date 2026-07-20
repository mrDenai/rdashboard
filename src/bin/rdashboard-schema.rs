use std::process::ExitCode;

use rdashboard::domain::{ProjectManifestV1, ProjectManifestV2};

fn main() -> ExitCode {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match run(&arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ERROR: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(arguments: &[String]) -> Result<(), SchemaToolError> {
    let [mode, path] = arguments else {
        return Err(SchemaToolError::Usage);
    };
    let mut rendered = if path.ends_with("project-manifest-v1.json") {
        serde_json::to_string_pretty(&schemars::schema_for!(ProjectManifestV1))?
    } else if path.ends_with("project-manifest-v2.json") {
        serde_json::to_string_pretty(&schemars::schema_for!(ProjectManifestV2))?
    } else {
        return Err(SchemaToolError::UnsupportedSchemaPath(path.clone()));
    };
    rendered.push('\n');
    match mode.as_str() {
        "--write" => std::fs::write(path, rendered).map_err(SchemaToolError::Io),
        "--check" => {
            let current = std::fs::read_to_string(path).map_err(SchemaToolError::Io)?;
            if current == rendered {
                Ok(())
            } else {
                Err(SchemaToolError::Drift(path.clone()))
            }
        }
        _ => Err(SchemaToolError::Usage),
    }
}

#[derive(Debug, thiserror::Error)]
enum SchemaToolError {
    #[error("usage: rdashboard-schema (--check|--write) PATH")]
    Usage,
    #[error("schema JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("schema file operation failed: {0}")]
    Io(std::io::Error),
    #[error("schema file {0} is stale; regenerate and review it")]
    Drift(String),
    #[error("schema path {0} does not name a supported project manifest version")]
    UnsupportedSchemaPath(String),
}
