//! `storagenode` binary. `HeadBucket` failure exits the process.

use std::process::ExitCode;

use storagenode::Config;

#[tokio::main]
async fn main() -> ExitCode {
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("storagenode: {err}");
            return ExitCode::from(1);
        }
    };
    if let Err(err) = storagenode::run(config).await {
        eprintln!("storagenode: {err}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}
