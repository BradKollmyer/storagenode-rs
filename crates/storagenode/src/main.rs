//! `storagenode` binary. `HeadBucket` failure exits the process.
//!
//! `storagenode` serves DRPC and the dashboard on `0.0.0.0:14002`.
//! `storagenode exit-satellite <id>` records a pending exit.
//! `storagenode exit-status` prints the stored rows.

use std::process::ExitCode;

use storagenode::{Command, Config};

#[tokio::main]
async fn main() -> ExitCode {
    let command = match storagenode::command(std::env::args().skip(1)) {
        Ok(command) => command,
        Err(err) => {
            eprintln!("storagenode: {err}");
            return ExitCode::from(1);
        }
    };
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("storagenode: {err}");
            return ExitCode::from(1);
        }
    };
    let result = match command {
        Command::Run => storagenode::run(config).await,
        Command::ExitSatellite(id) => storagenode::request_exit(&config, &id).map(|row| {
            println!("{}", storagenode::format_exit_row(&row));
        }),
        Command::ExitStatus => storagenode::exit_status(&config).map(|text| {
            print!("{text}");
        }),
    };
    if let Err(err) = result {
        eprintln!("storagenode: {err}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}
