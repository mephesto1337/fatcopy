use std::{
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

#[derive(Debug)]
pub struct FatCopy {
    file: File,
    has_reached_eof: bool,
    packet: Packet,
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
        })
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

    fn send_chunk<S>(&mut self, data: &[u8], stream: &mut S) -> io::Result<()>
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
            Ack::HashOk => {}
            Ack::NeedData => {
                self.send_wire(stream, &Data(data[..].into()))?;
            }
        }
        Ok(())
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

        Ok(data.0.len() as u64)
    }

    fn recv_chunk<S>(&mut self, stream: &mut S) -> io::Result<u64>
    where
        S: Read + Write,
    {
        let mut hasher = Sha256::new();
        let mut hash: sha2::digest::generic_array::GenericArray<_, _> = [0u8; HASH_SIZE].into();
        let mut buffer = [0u8; BLOCK_SIZE as usize];
        let remote = self.recv_wire::<_, Hash>(stream)?.into_owned();

        if self.has_reached_eof {
            return self.recv_data(stream, remote);
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
                    Ok(size as u64)
                } else {
                    self.file.seek(SeekFrom::Start(position))?;
                    log::debug!("read_exact OK, hashes KO, asking for data");
                    self.recv_data(stream, remote)
                }
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    log::debug!("EOF is reached");
                    self.has_reached_eof = true;
                    self.file.seek(SeekFrom::Start(position))?;
                    self.recv_data(stream, remote)
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
            log::debug!("read_exact, offset={offset}, size={size}");
            self.file.read_exact(&mut data[..])?;
            offset += BLOCK_SIZE;
            self.send_chunk(&data[..], stream)?;
        }

        log::debug!("read, offset={offset}, size={size}");
        let n = self.file.read(&mut data[..])?;
        self.send_chunk(&data[..n], stream)?;

        Ok(())
    }

    pub fn recv<S>(&mut self, stream: &mut S) -> io::Result<()>
    where
        S: Read + Write,
    {
        let filesize = self.recv_wire::<_, FileSize>(stream)?.0;
        let mut offset = 0;

        while offset < filesize {
            offset += self.recv_chunk(stream)?;
        }
        self.file.set_len(filesize)?;

        Ok(())
    }
}
