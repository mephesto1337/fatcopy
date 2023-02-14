use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};

use sha2::{Digest, Sha256};

const BLOCK_SIZE: u64 = 4096;
const HASH_SIZE: usize = 32;

mod protocol;
use protocol::Wire;

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

    fn send_wire<S, T>(&mut self, stream: &mut S, obj: &T) -> io::Result<()>
    where
        T: Wire,
        S: Write,
    {
        obj.serialize(stream)?;
        Ok(())
    }

    fn recv_wire<S, T>(&mut self, stream: &mut S) -> io::Result<T>
    where
        S: Read,
        T: Wire,
    {
        let mut buffer = vec![0u8; T::size_hint()];
        stream.read_exact(&mut buffer[..])?;
        loop {
            match T::deserialize(&buffer[..]) {
                Ok((rest, obj)) => {
                    assert_eq!(rest.len(), 0);
                    return Ok(obj);
                }
                Err(nom::Err::Incomplete(n)) => match n {
                    nom::Needed::Unknown => todo!(),
                    nom::Needed::Size(s) => {
                        let offset = buffer.len();
                        buffer.resize(offset + s.get(), 0);
                        stream.read_exact(&mut buffer[offset..])?;
                        continue;
                    }
                },
                Err(nom::Err::Error(e)) | Err(nom::Err::Failure(e)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{e:#?}"),
                    ));
                }
            }
        }
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
            &protocol::Hash::<HASH_SIZE> {
                size: data.len() as u32,
                hash: hash.as_slice().into(),
            },
        )?;
        let res: protocol::Ack = self.recv_wire(stream)?;
        match res {
            protocol::Ack::Hash => {}
            protocol::Ack::NeedData => {
                self.send_wire(stream, &protocol::Data(data[..].into()))?;
            }
        }
        Ok(())
    }

    fn recv_data<S>(&mut self, stream: &mut S, hash: protocol::Hash<HASH_SIZE>) -> io::Result<u64>
    where
        S: Read + Write,
    {
        self.send_wire(stream, &protocol::Ack::NeedData)?;
        let data: protocol::Data = self.recv_wire(stream)?;
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
        let remote: protocol::Hash<HASH_SIZE> = self.recv_wire(stream)?;

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
                    self.send_wire(stream, &protocol::Ack::Hash)?;
                    Ok(size as u64)
                } else {
                    self.file.seek(SeekFrom::Start(position))?;
                    self.recv_data(stream, remote)
                }
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::UnexpectedEof {
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

        self.send_wire(stream, &protocol::FileSize(size))?;
        let mut data = [0u8; BLOCK_SIZE as usize];
        while offset + BLOCK_SIZE < size {
            self.file.read_exact(&mut data[..])?;
            offset += BLOCK_SIZE;
            self.send_chunk(&data[..], stream)?;
        }

        let n = self.file.read(&mut data[..])?;
        self.send_chunk(&data[..n], stream)?;

        Ok(())
    }

    pub fn recv<S>(&mut self, stream: &mut S) -> io::Result<()>
    where
        S: Read + Write,
    {
        let filesize: protocol::FileSize = self.recv_wire(stream)?;
        let mut offset = 0;

        while offset < filesize.0 {
            offset += self.recv_chunk(stream)?;
        }
        self.file.set_len(filesize.0)?;

        Ok(())
    }
}
