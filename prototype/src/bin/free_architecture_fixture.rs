//! Launch the normal product. No HTTP, database or runtime lives in this binary.
use std::{
    env,
    ffi::OsString,
    io::{self, ErrorKind},
    path::PathBuf,
    process::Command,
};

const BINARY_ENV: &str = "PUSHGO_GATEWAY_PRODUCT_BINARY";

fn main() {
    if let Err(error) = launch() {
        eprintln!("product launcher: {error}");
        std::process::exit(2);
    }
}

fn launch() -> io::Result<()> {
    let mut binary: Option<PathBuf> = None;
    let mut product_args: Vec<OsString> = Vec::new();
    let mut args = env::args_os().skip(1);
    while let Some(argument) = args.next() {
        if argument == "--" {
            product_args.extend(args);
            break;
        }
        if argument == "--launcher-help" {
            println!(
                "Launch the normal pushgo-gateway binary.\n\
                 Usage: free_architecture_fixture --product-binary PATH -- [Gateway Args]\n\
                 PATH may instead come from PUSHGO_GATEWAY_PRODUCT_BINARY.\n\
                 All Gateway arguments are forwarded unchanged. Old fixture flags and\n\
                 __fixture endpoints are not provided. Unix replaces this process."
            );
            return Ok(());
        }
        if argument == "--product-binary" {
            if binary.is_some() {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "--product-binary must be supplied once",
                ));
            }
            binary = Some(PathBuf::from(args.next().ok_or_else(|| {
                io::Error::new(ErrorKind::InvalidInput, "--product-binary requires PATH")
            })?));
            continue;
        }
        product_args.push(argument);
    }
    let binary = binary
        .or_else(|| env::var_os(BINARY_ENV).map(PathBuf::from))
        .ok_or_else(|| {
            io::Error::new(
                ErrorKind::InvalidInput,
                "select a normal Gateway with --product-binary PATH or PUSHGO_GATEWAY_PRODUCT_BINARY",
            )
        })?
        .canonicalize()?;
    if !binary.metadata()?.is_file() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "the selected product binary is not a regular file",
        ));
    }
    if binary == env::current_exe()?.canonicalize()? {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "the product binary cannot be this launcher",
        ));
    }
    let mut command = Command::new(binary);
    command.args(product_args);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Process replacement preserves the normal Gateway PID, signals and
        // failure/shutdown lifecycle. There is no fixture child service.
        Err(command.exec())
    }
    #[cfg(not(unix))]
    {
        // Other hosts retain only this waiting launcher and one normal Gateway.
        // No second listener, database owner or Private runtime is constructed.
        let status = command.status()?;
        std::process::exit(status.code().unwrap_or(1));
    }
}
