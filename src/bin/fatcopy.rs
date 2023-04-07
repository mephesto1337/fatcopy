use std::{
    fmt::Write,
    io,
    os::{fd::FromRawFd, unix::net::UnixStream},
    process::{exit, Child, Command, Stdio},
};

use clap::Parser;
use fatcopy::FatCopy;
use nix::{
    sys::{
        socket::{socketpair, AddressFamily, SockFlag, SockType},
        wait::waitpid,
    },
    unistd::{fork, getpid, ForkResult},
};

mod pipe;
use pipe::Pipe;

#[derive(Debug, Parser)]
struct Cli {
    /// Use STDIO mode
    #[arg(long, default_value_t = false)]
    stdio: bool,

    /// Is launch through SSH (internal only)
    #[arg(long, default_value_t = false)]
    is_remote_ssh: bool,

    /// Block size to use
    #[arg(long, default_value_t = fatcopy::DEFAULT_BLOCK_SIZE, env)]
    block_size: u64,

    /// Block size to use
    #[arg(long, default_value_t = fatcopy::DEFAULT_BULK_SIZE, env)]
    bulk_size: u64,

    /// SSH command to use
    #[arg(
        short = 'e',
        long = "rsh",
        help = "Command will be split on whitespace characters ONLY"
    )]
    ssh_command: Option<String>,

    /// Remote location for fatcopy
    #[arg(long, default_value = "fatcopy")]
    remote_binary: String,

    source: String,
    destination: String,
}

fn split_on_remote(filename: &str) -> (Option<&str>, &str) {
    if let Some(idx) = filename.find(':') {
        (Some(&filename[..idx]), &filename[idx + 1..])
    } else {
        (None, filename)
    }
}

fn run_through_ssh(
    ssh_command: Option<&str>,
    hostname: &str,
    fatcopy_command: &str,
) -> io::Result<Child> {
    let mut command = if let Some(cmd) = ssh_command {
        let mut parts = cmd.split_whitespace();
        let mut cmd = Command::new(parts.next().unwrap());
        for a in parts {
            cmd.arg(a);
        }
        cmd
    } else {
        Command::new("ssh")
    };
    command
        .arg(hostname)
        .arg("--")
        .arg(fatcopy_command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    command.spawn()
}

fn prepare_remote_fatcopy(source: &str, destination: &str, args: &Cli) -> String {
    let mut command = String::new();
    write!(
        &mut command,
        "{} --stdio --is-remote-ssh ",
        args.remote_binary
    )
    .unwrap();
    write!(&mut command, "--block-size={} ", args.block_size).unwrap();
    write!(&mut command, "--bulk-size={} ", args.bulk_size).unwrap();
    write!(&mut command, "'{}' ", source.replace('\'', "'\\''")).unwrap();
    write!(&mut command, "'{}'", destination.replace('\'', "'\\''")).unwrap();
    command
}

fn main() {
    if let Err(e) = main_helper() {
        log::error!("{e:#?}");
        exit(1);
    }
    exit(0);
}

fn main_helper() -> io::Result<()> {
    let args = Cli::parse();
    let mut builder = env_logger::builder();

    builder
        .parse_default_env()
        .target(env_logger::Target::Stderr);

    if args.is_remote_ssh {
        builder.format(|buf, record| {
            use std::io::Write;

            let ts = buf.timestamp_millis();
            let level = buf.default_styled_level(record.level());
            write!(buf, "SSH    [{} {:<5}", ts, level)?;
            if let Some(p) = record.module_path() {
                writeln!(buf, " {}] {}", p, record.args())?;
            } else {
                writeln!(buf, "] {}", record.args())?;
            }
            Ok(())
        });
    } else {
        builder.format(|buf, record| {
            use std::io::Write;

            let ts = buf.timestamp_millis();
            write!(buf, "{:<6} [{} {:<5}", getpid(), ts, record.level())?;
            if let Some(p) = record.module_path() {
                writeln!(buf, " {}] {}", p, record.args())?;
            } else {
                writeln!(buf, "] {}", record.args())?;
            }
            Ok(())
        });
    }

    builder.init();

    let options = fatcopy::Options {
        block_size: args.block_size,
        bulk_size: args.bulk_size,
    };

    match options.block_size.checked_mul(args.block_size) {
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "block-size * bulk-size would overflow",
            ))
        }
        Some(read_size) => {
            if read_size > fatcopy::MAXIMUM_READ_SIZE {
                log::warn!(
                    "block-size * bulk-size is over 0x{:x} (maximum read size)",
                    fatcopy::MAXIMUM_READ_SIZE
                );
            }
        }
    }

    if args.stdio {
        // We are launch through SSH
        if args.source == "-" {
            let mut fatcopy = FatCopy::new_with_options(&args.destination, options)?;
            let mut stdio = Pipe::stdio();
            fatcopy.recv(&mut stdio)?;
        } else if args.destination == "-" {
            let mut fatcopy = FatCopy::new_with_options(&args.source, options)?;
            let mut stdio = Pipe::stdio();
            fatcopy.send(&mut stdio)?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "When runned with `--stdio` either source or destination must be set to `-`",
            ));
        }
        Ok(())
    } else {
        println!("{} -> {}", &args.source, &args.destination);
        let callback = move |args: fatcopy::CallbackArg| {
            let percentage = (args.offset as f64 * 100f64) / args.size as f64;
            print!("\r  -> {percentage:5.2}%");
        };

        match (
            split_on_remote(&args.source),
            split_on_remote(&args.destination),
        ) {
            ((Some(_), _), (Some(_), _)) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "At most one of source and destination can be a remote destination",
                ));
            }
            ((None, source), (None, destination)) => {
                let (a, b) = socketpair(
                    AddressFamily::Unix,
                    SockType::Stream,
                    None,
                    SockFlag::empty(),
                )?;

                match unsafe { fork() }? {
                    ForkResult::Parent { child } => {
                        let mut src = FatCopy::new_with_options(source, options)?;
                        src.register_callback(callback);
                        let mut sock = unsafe { UnixStream::from_raw_fd(a) };
                        src.send(&mut sock)?;
                        waitpid(Some(child), None)?;
                    }
                    ForkResult::Child => {
                        let mut dst = FatCopy::new_with_options(destination, options)?;
                        let mut sock = unsafe { UnixStream::from_raw_fd(b) };
                        dst.recv(&mut sock)?;
                        exit(0);
                    }
                }
            }
            ((None, source), (Some(hostname), destination)) => {
                let remote_command = prepare_remote_fatcopy(source, destination, &args);
                let mut ssh =
                    run_through_ssh(args.ssh_command.as_deref(), hostname, &remote_command)?;
                let mut stdio = Pipe::from_child(&mut ssh).unwrap();
                let mut src = FatCopy::new_with_options(source, options)?;
                src.register_callback(callback);

                src.send(&mut stdio)?;
                ssh.wait()?;
            }
            ((Some(hostname), source), (None, destination)) => {
                let remote_command = prepare_remote_fatcopy(source, destination, &args);
                let mut ssh =
                    run_through_ssh(args.ssh_command.as_deref(), hostname, &remote_command)?;
                let mut stdio = Pipe::from_child(&mut ssh).unwrap();
                let mut dst = FatCopy::new_with_options(source, options)?;
                dst.register_callback(callback);

                dst.recv(&mut stdio)?;
                ssh.wait()?;
            }
        }
        println!();

        Ok(())
    }
}
