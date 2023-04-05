use std::{
    io,
    os::{fd::FromRawFd, unix::net::UnixStream},
    process::{exit, Child, Command},
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
use ssh_control::{
    command::{Pipe, SshCommand},
    SshControl,
};

#[derive(Debug, Parser)]
struct Cli {
    /// Use STDIO mode
    #[arg(long, default_value_t = false)]
    stdio: bool,

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

fn run_ssh_master(hostname: &str) -> io::Result<(Child, String)> {
    let pid = getpid();
    let master_path = format!("/tmp/ssh-master-{hostname}-{pid}.sock");
    let master = Command::new("ssh")
        .args(&["-o", "ControlPersist=yes"][..])
        .args(&["-o", "ControlMaster=auto"][..])
        .args(&["-S", &master_path][..])
        .args(&["-f", "-N", "-n"])
        .arg(hostname)
        .env("RUST_LOG", "debug")
        .env("IS_REMOTE", "true")
        .spawn()?;
    log::info!("SSH master running with pid {pid}", pid = master.id());
    std::thread::sleep(std::time::Duration::from_secs(1));
    Ok((master, master_path))
}

fn main() -> anyhow::Result<()> {
    let mut builder = env_logger::builder();

    builder
        .parse_default_env()
        .target(env_logger::Target::Stderr);

    if std::env::var("IS_REMOTE").is_ok() {
        builder.format(|buf, record| {
            use std::io::Write;
            writeln!(buf, "SSH {}: {}", record.level(), record.args())
        });
    }

    builder.init();
    let args = Cli::parse();

    if args.stdio {
        // We are launch through SSH
        if args.source == "-" {
            let mut fatcopy = FatCopy::new(&args.destination)?;
            let mut stdio = Pipe::stdio();
            fatcopy.recv(&mut stdio)?;
        } else if args.destination == "-" {
            let mut fatcopy = FatCopy::new(&args.source)?;
            let mut stdio = Pipe::stdio();
            fatcopy.send(&mut stdio)?;
        } else {
            anyhow::bail!(
                "When runned with `--stdio` either source or destination must be set to `-`"
            );
        }
        Ok(())
    } else {
        match (
            split_on_remote(&args.source),
            split_on_remote(&args.destination),
        ) {
            ((Some(_), _), (Some(_), _)) => {
                anyhow::bail!("At most one of source and destination can be a remote destination");
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
                        let mut src = FatCopy::new(source)?;
                        let mut sock = unsafe { UnixStream::from_raw_fd(a) };
                        src.send(&mut sock)?;
                        waitpid(Some(child), None)?;
                    }
                    ForkResult::Child => {
                        let mut dst = FatCopy::new(destination)?;
                        let mut sock = unsafe { UnixStream::from_raw_fd(b) };
                        dst.recv(&mut sock)?;
                        exit(0);
                    }
                }
            }
            ((None, source), (Some(hostname), destination)) => {
                let (mut master, master_path) = run_ssh_master(hostname)?;
                let mut ctrl = SshControl::new(&master_path)?;
                let mut dst = SshCommand::new(&format!("fatcopy --stdio - {destination}"));
                dst.stdin(Pipe::new()?);
                dst.stdout(Pipe::new()?);
                let mut fatcopy = ctrl.new_session(dst)?;
                let (stdin, stdout) = (
                    fatcopy.stdin.take().unwrap(),
                    fatcopy.stdout.take().unwrap(),
                );
                let mut stdio = Pipe::with_pipes(stdout, stdin);
                let mut src = FatCopy::new(source)?;

                src.send(&mut stdio)?;
                ctrl.wait(&fatcopy)?;
                master.kill()?;
            }
            ((Some(hostname), source), (None, destination)) => {
                let (mut master, master_path) = run_ssh_master(hostname)?;
                let mut ctrl = SshControl::new(&master_path)?;
                let mut dst = SshCommand::new(&format!("fatcopy --stdio {source} -"));
                dst.stdin(Pipe::new()?);
                dst.stdout(Pipe::new()?);
                let mut fatcopy = ctrl.new_session(dst)?;
                let (stdin, stdout) = (
                    fatcopy.stdin.take().unwrap(),
                    fatcopy.stdout.take().unwrap(),
                );
                let mut stdio = Pipe::with_pipes(stdout, stdin);
                let mut dst = FatCopy::new(destination)?;

                dst.recv(&mut stdio)?;
                ctrl.wait(&fatcopy)?;
                master.kill()?;
            }
        }

        Ok(())
    }
}
