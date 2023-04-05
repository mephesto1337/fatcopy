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
        })
    }

    fn send_wire<'a, S, T>(stream: &mut S, packet: &mut Packet, obj: &'a T) -> io::Result<()>
    where
        T: Wire<'a>,
        S: Write,
    {
        packet.set(obj);
        packet.serialize(stream)?;
        Ok(())
    }

    fn recv_wire<'a, 's, S, T>(stream: &mut S, packet: &'a mut Packet) -> io::Result<T>
    where
        's: 'a,
        S: Read,
        T: 'a + Wire<'a>,
    {
        packet.recv(stream)
    }

    fn send_chunk<S>(data: &[u8], stream: &mut S, packet: &mut Packet) -> io::Result<()>
    where
        S: Write + Read,
    {
        let mut hasher = Sha256::new();
        let mut hash: sha2::digest::generic_array::GenericArray<_, _> = [0u8; HASH_SIZE].into();

        hasher.update(data);
        hasher.finalize_into(&mut hash);
        Self::send_wire(
            stream,
            packet,
            &Hash {
                size: data.len() as u32,
                hash: hash.as_slice().into(),
            },
        )?;
        let res: Ack = Self::recv_wire(stream, packet)?;
        match res {
            Ack::Hash => {}
            Ack::NeedData => {
                Self::send_wire(stream, packet, &Data(data[..].into()))?;
            }
        }
        Ok(())
    }

    fn recv_data<S>(&mut self, stream: &mut S, hash: Hash, packet: &mut Packet) -> io::Result<u64>
    where
        S: Read + Write,
    {
        Self::send_wire(stream, packet, &Ack::NeedData)?;
        let data: Data = Self::recv_wire(stream, packet)?;
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

    fn recv_chunk<S>(&mut self, stream: &mut S, packet: &mut Packet) -> io::Result<u64>
    where
        S: Read + Write,
    {
        let mut hasher = Sha256::new();
        let mut hash: sha2::digest::generic_array::GenericArray<_, _> = [0u8; HASH_SIZE].into();
        let mut buffer = [0u8; BLOCK_SIZE as usize];
        let remote = Self::recv_wire::<_, Hash>(stream, packet)?.to_owned();

        if self.has_reached_eof {
            return self.recv_data(stream, remote, packet);
        }
        let size = remote.size as usize;
        let position = self.file.stream_position()?;

        match self.file.read_exact(&mut buffer[..size]) {
            Ok(()) => {
                hasher.update(&buffer[..size]);
                hasher.finalize_into(&mut hash);
                if hash.as_slice() == &*remote.hash {
                    Self::send_wire(stream, packet, &Ack::Hash)?;
                    Ok(size as u64)
                } else {
                    self.file.seek(SeekFrom::Start(position))?;
                    self.recv_data(stream, remote, packet)
                }
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    self.has_reached_eof = true;
                    self.file.seek(SeekFrom::Start(position))?;
                    self.recv_data(stream, remote, packet)
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
        let mut packet = Packet::default();

        Self::send_wire(stream, &mut packet, &FileSize(size))?;
        let mut data = [0u8; BLOCK_SIZE as usize];
        while offset + BLOCK_SIZE < size {
            self.file.read_exact(&mut data[..])?;
            offset += BLOCK_SIZE;
            Self::send_chunk(&data[..], stream, &mut packet)?;
        }

        let n = self.file.read(&mut data[..])?;
        Self::send_chunk(&data[..n], stream, &mut packet)?;

        Ok(())
    }

    pub fn recv<S>(&mut self, stream: &mut S) -> io::Result<()>
    where
        S: Read + Write,
    {
        let mut packet = Packet::default();
        let filesize = packet.recv::<FileSize, _>(stream)?.0;
        let mut offset = 0;

        while offset < filesize {
            offset += self.recv_chunk(stream, &mut packet)?;
        }
        self.file.set_len(filesize)?;

        Ok(())
    }
}
