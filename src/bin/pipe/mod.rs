use std::{
    io::{self, Read, Write},
    os::unix::io::{IntoRawFd, RawFd},
    process::Child,
};

use nix::unistd::{read, write};

#[derive(Debug)]
pub struct Pipe {
    read: RawFd,
    write: RawFd,
}

impl<RW: IntoRawFd> From<RW> for Pipe {
    fn from(value: RW) -> Self {
        let fd = value.into_raw_fd();
        Self {
            read: fd,
            write: fd,
        }
    }
}

impl Pipe {
    pub fn from_child(child: &mut Child) -> Option<Self> {
        if child.stdin.is_none() || child.stdout.is_none() {
            return None;
        }
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();

        Some(Self {
            read: stdout.into_raw_fd(),
            write: stdin.into_raw_fd(),
        })
    }

    pub fn stdio() -> Self {
        Self { read: 0, write: 1 }
    }
}

impl Read for Pipe {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        read(self.read, buf).map_err(|errno| io::Error::from_raw_os_error(errno as i32))
    }
}

impl Write for Pipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        write(self.write, buf).map_err(|errno| io::Error::from_raw_os_error(errno as i32))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
