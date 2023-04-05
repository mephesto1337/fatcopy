use std::{
    fmt,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};

use sha2::{Digest, Sha256};

const BLOCK_SIZE: u64 = 4096;
const HASH_SIZE: usize = 32;

mod protocol;
use protocol::{Ack, Data, FileSize, Packet, Wire};
type Hash<'a> = protocol::Hash<'a, HASH_SIZE>;

pub struct CallbackArg {
    pub offset: u64,
    pub size: u64,
    pub hash_was_ok: bool,
}

pub struct FatCopy {
    file: File,
    has_reached_eof: bool,
    packet: Packet,
    callback: Option<Box<dyn FnMut(CallbackArg)>>,
}

impl fmt::Debug for FatCopy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FatCopy")
            .field("file", &self.file)
            .field("has_reached_eof", &self.has_reached_eof)
            .finish_non_exhaustive()
    }
}

impl FatCopy {
    pub fn new(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = File::options()
            .read(true)
            .write(true)
            .create(true)
            .open(path)?;
        Ok(Self {
            file,
            has_reached_eof: false,
            packet: Packet::default(),
            callback: None,
        })
    }

    pub fn register_callback(&mut self, callback: impl FnMut(CallbackArg) + 'static) {
        self.callback = Some(Box::new(callback));
    }

    fn send_wire<'a, S, T>(&mut self, stream: &mut S, obj: &'a T) -> io::Result<()>
    where
        T: Wire<'a> + std::fmt::Debug,
        S: Write,
    {
        self.packet.set(obj);
        log::debug!("Sending {obj:?}");
        self.packet.serialize(stream)?;
        Ok(())
    }

    fn recv_wire<'a, S, T>(&'a mut self, stream: &mut S) -> io::Result<T>
    where
        S: Read,
        T: 'a + Wire<'a> + std::fmt::Debug,
    {
        let obj = self.packet.recv(stream)?;
        log::debug!("Received {obj:?}");
        Ok(obj)
    }

    fn send_chunk<S>(&mut self, data: &[u8], stream: &mut S) -> io::Result<bool>
    where
        S: Write + Read,
    {
        let mut hasher = Sha256::new();
        let mut hash: sha2::digest::generic_array::GenericArray<_, _> = [0u8; HASH_SIZE].into();

        hasher.update(data);
        hasher.finalize_into(&mut hash);
        self.send_wire(
            stream,
            &Hash {
                size: data.len() as u32,
                hash: hash.as_slice().into(),
            },
        )?;
        let res: Ack = self.recv_wire(stream)?;
        match res {
            Ack::HashOk => Ok(true),
            Ack::NeedData => {
                self.send_wire(stream, &Data(data[..].into()))?;
                Ok(false)
            }
        }
    }

    fn recv_data<S>(&mut self, stream: &mut S, hash: Hash) -> io::Result<u64>
    where
        S: Read + Write,
    {
        self.send_wire(stream, &Ack::NeedData)?;
        let data: Data = self.recv_wire(stream)?;
        self.file.write_all(&data.0)?;
        #[cfg(debug_assertions)]
        {
            let mut hasher = Sha256::new();
            let mut local_hash: sha2::digest::generic_array::GenericArray<_, _> =
                [0u8; HASH_SIZE].into();
            hasher.update(&data.0);
            hasher.finalize_into(&mut local_hash);
            assert_eq!(&*hash.hash, local_hash.as_slice());
        }
        #[cfg(not(debug_assertions))]
        let _ = hash;

        Ok(data.0.len() as u64)
    }

    fn recv_chunk<S>(&mut self, stream: &mut S) -> io::Result<(u64, bool)>
    where
        S: Read + Write,
    {
        let mut hasher = Sha256::new();
        let mut hash: sha2::digest::generic_array::GenericArray<_, _> = [0u8; HASH_SIZE].into();
        let mut buffer = [0u8; BLOCK_SIZE as usize];
        let remote = self.recv_wire::<_, Hash>(stream)?.into_owned();

        if self.has_reached_eof {
            return Ok((self.recv_data(stream, remote)?, false));
        }
        let size = remote.size as usize;
        let position = self.file.stream_position()?;

        match self.file.read_exact(&mut buffer[..size]) {
            Ok(()) => {
                hasher.update(&buffer[..size]);
                hasher.finalize_into(&mut hash);
                if hash.as_slice() == &*remote.hash {
                    self.send_wire(stream, &Ack::HashOk)?;
                    log::debug!("read_exact OK, hashes OK");
                    Ok(((size as u64), true))
                } else {
                    self.file.seek(SeekFrom::Start(position))?;
                    log::debug!("read_exact OK, hashes KO, asking for data");
                    Ok((self.recv_data(stream, remote)?, false))
                }
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    log::debug!("EOF is reached");
                    self.has_reached_eof = true;
                    self.file.seek(SeekFrom::Start(position))?;
                    Ok((self.recv_data(stream, remote)?, false))
                } else {
                    Err(e)
                }
            }
        }
    }

    pub fn send<S>(&mut self, stream: &mut S) -> io::Result<()>
    where
        S: Read + Write,
    {
        let size = self.file.metadata()?.len();
        let mut offset = 0;

        self.send_wire(stream, &FileSize(size))?;
        let mut data = [0u8; BLOCK_SIZE as usize];
        while offset + BLOCK_SIZE < size {
            self.file.read_exact(&mut data[..])?;
            let hash_was_ok = self.send_chunk(&data[..], stream)?;
            if let Some(ref mut cb) = self.callback {
                cb(CallbackArg {
                    offset,
                    size,
                    hash_was_ok,
                });
            }
            offset += BLOCK_SIZE;
        }

        let n = self.file.read(&mut data[..])?;
        let hash_was_ok = self.send_chunk(&data[..n], stream)?;
        if let Some(ref mut cb) = self.callback {
            cb(CallbackArg {
                offset,
                size,
                hash_was_ok,
            });
        }

        Ok(())
    }

    pub fn recv<S>(&mut self, stream: &mut S) -> io::Result<()>
    where
        S: Read + Write,
    {
        let size = self.recv_wire::<_, FileSize>(stream)?.0;
        let mut offset = 0;

        while offset < size {
            let (count, hash_was_ok) = self.recv_chunk(stream)?;
            if let Some(cb) = self.callback.as_mut() {
                cb(CallbackArg {
                    offset,
                    size,
                    hash_was_ok,
                });
            }
            offset += count;
        }
        self.file.set_len(size)?;

        Ok(())
    }
}
