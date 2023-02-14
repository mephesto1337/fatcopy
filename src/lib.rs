use std::{
    fs::File,
    io::{self, BufRead, Read, Seek, SeekFrom, Write},
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

    fn send_wire<'a, S, T>(&'a mut self, obj: &T, stream: &mut S) -> io::Result<()>
    where
        T: Wire<'a>,
        S: Write,
    {
        obj.serialize(stream)?;
        Ok(())
    }

    fn recv_wire<'a, 's, S, T, O>(
        &mut self,
        stream: &'s mut S,
        stream_buffer: &'a mut Vec<u8>,
    ) -> io::Result<T>
    where
        T: Wire<'a>,
        O: Wire<'s>,
        S: BufRead,
    {
        self.try_recv_wire::<_, O>(stream, stream_buffer)?;
        let (_, obj) = T::deserialize::<()>(&stream_buffer[..]).unwrap();
        Ok(obj)
    }

    fn try_recv_wire<'a, S, T>(
        &mut self,
        stream: &'a mut S,
        stream_buffer: &mut Vec<u8>,
    ) -> io::Result<()>
    where
        T: Wire<'a>,
        S: BufRead,
    {
        loop {
            let (done, used) = {
                let input = stream.fill_buf()?;
                match T::can_deserialize(input) {
                    protocol::CanDeserialize::Yes { consumed } => (true, consumed),
                    protocol::CanDeserialize::Incomplete(_) => (false, 0),
                    protocol::CanDeserialize::No => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Cannot parse data from remote",
                        ));
                    }
                }
            };
            stream.consume(used);
            if done {
                return Ok(());
            }
        }
    }

    fn send_chunk<S>(
        &mut self,
        data: &[u8],
        stream: &mut S,
        stream_buffer: &mut Vec<u8>,
    ) -> io::Result<()>
    where
        S: Write + BufRead,
    {
        let mut hasher = Sha256::new();
        let mut hash: sha2::digest::generic_array::GenericArray<_, _> = [0u8; HASH_SIZE].into();
        hasher.update(&data[..]);
        hasher.finalize_into(&mut hash);
        self.send_wire(
            &protocol::Hash::<HASH_SIZE> {
                size: data.len() as u32,
                hash: hash.as_slice().into(),
            },
            stream,
        )?;
        let res: protocol::Ack = self.recv_wire::<_, _, protocol::Ack>(stream, stream_buffer)?;
        match res {
            protocol::Ack::Hash => {}
            protocol::Ack::NeedData => {
                self.send_wire(&protocol::Data(&data[..]), stream)?;
            }
        }
        Ok(())
    }

    fn recv_data<S>(
        &mut self,
        stream: &mut S,
        hash: protocol::Hash<'static, HASH_SIZE>,
        stream_buffer: &mut Vec<u8>,
    ) -> io::Result<u64>
    where
        S: BufRead + Write,
    {
        self.send_wire(&protocol::Ack::NeedData, stream)?;
        let data: protocol::Data =
            self.recv_wire::<_, _, protocol::Data<'_>>(stream, stream_buffer)?;
        self.file.write_all(data.0)?;
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

    fn recv_chunk<S>(&mut self, stream: &mut S, stream_buffer: &mut Vec<u8>) -> io::Result<u64>
    where
        S: BufRead + Write,
    {
        let mut hasher = Sha256::new();
        let mut hash: sha2::digest::generic_array::GenericArray<_, _> = [0u8; HASH_SIZE].into();
        let mut buffer = [0u8; BLOCK_SIZE as usize];
        let remote = self
            .recv_wire::<_, protocol::Hash<HASH_SIZE>, protocol::Hash<'_, HASH_SIZE>>(
                stream,
                stream_buffer,
            )?
            .into_owned();

        if self.has_reached_eof {
            return self.recv_data(stream, remote, stream_buffer);
        }
        let size = remote.size as usize;
        let position = self.file.stream_position()?;

        match self.file.read_exact(&mut buffer[..size]) {
            Ok(()) => {
                hasher.update(&buffer[..size]);
                hasher.finalize_into(&mut hash);
                if hash.as_slice() == &*remote.hash {
                    self.send_wire(&protocol::Ack::Hash, stream)?;
                    Ok(size as u64)
                } else {
                    self.file.seek(SeekFrom::Start(position))?;
                    self.recv_data(stream, remote, stream_buffer)
                }
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    self.has_reached_eof = true;
                    self.file.seek(SeekFrom::Start(position))?;
                    self.recv_data(stream, remote, stream_buffer)
                } else {
                    Err(e)
                }
            }
        }
    }

    pub fn send<S>(&mut self, stream: &mut S) -> io::Result<()>
    where
        S: BufRead + Write,
    {
        let size = self.file.metadata()?.len();
        let mut offset = 0;
        let mut stream_buffer = Vec::with_capacity(32);

        self.send_wire(&protocol::FileSize(size), stream)?;
        let mut data = [0u8; BLOCK_SIZE as usize];
        while offset + BLOCK_SIZE < size {
            self.file.read_exact(&mut data[..])?;
            offset += BLOCK_SIZE;
            self.send_chunk(&data[..], stream, &mut stream_buffer)?;
        }

        let n = self.file.read(&mut data[..])?;
        self.send_chunk(&data[..n], stream, &mut stream_buffer)?;

        Ok(())
    }

    pub fn recv<S>(&mut self, stream: &mut S) -> io::Result<()>
    where
        S: BufRead + Write,
    {
        let mut stream_buffer = Vec::with_capacity(BLOCK_SIZE as usize);
        let filesize: protocol::FileSize =
            self.recv_wire::<_, _, protocol::FileSize>(stream, &mut stream_buffer)?;
        let mut offset = 0;

        while offset < filesize.0 {
            offset += self.recv_chunk(stream, &mut stream_buffer)?;
        }
        self.file.set_len(filesize.0)?;

        Ok(())
    }
}
