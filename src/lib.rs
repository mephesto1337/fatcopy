use std::{
    fmt,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};

use sha2::{Digest, Sha256};

const HASH_SIZE: usize = 32;

pub const DEFAULT_BLOCK_SIZE: u64 = 4096;
pub const DEFAULT_BULK_SIZE: u64 = 32;

mod protocol;
use protocol::{Ack, AckResult, Data, FileSize, Packet, Wire};

type Hash = protocol::Hash<HASH_SIZE>;

pub struct CallbackArg {
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct Options {
    pub block_size: u64,
    pub bulk_size: u64,
}

pub struct FatCopy {
    file: File,
    has_reached_eof: bool,
    packet: Packet,
    callback: Box<dyn FnMut(CallbackArg)>,
    filesize: u64,
    options: Options,
}

impl fmt::Debug for FatCopy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FatCopy")
            .field("file", &self.file)
            .field("has_reached_eof", &self.has_reached_eof)
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl FatCopy {
    pub fn new_with_options(path: impl AsRef<Path>, options: Options) -> io::Result<Self> {
        let file = File::options()
            .read(true)
            .write(true)
            .create(true)
            .open(path)?;
        let filesize = file.metadata()?.len();
        Ok(Self {
            file,
            has_reached_eof: false,
            packet: Packet::default(),
            callback: Box::new(|_| {}),
            options,
            filesize,
        })
    }

    pub fn new(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::new_with_options(
            path,
            Options {
                block_size: DEFAULT_BLOCK_SIZE,
                bulk_size: DEFAULT_BULK_SIZE,
            },
        )
    }

    pub fn register_callback(&mut self, callback: impl FnMut(CallbackArg) + 'static) {
        self.callback = Box::new(callback);
    }

    fn get_data(buffer: &[u8], offset: usize, size: usize) -> Option<&[u8]> {
        if offset > buffer.len() {
            None
        } else {
            Some(if offset + size > buffer.len() {
                &buffer[offset..]
            } else {
                &buffer[offset..][..size]
            })
        }
    }

    fn send_chunks<S>(&mut self, data: &[u8], offset: u64, stream: &mut S) -> io::Result<()>
    where
        S: Write + Read,
    {
        self.packet.clear();
        let mut hasher = Sha256::new();
        let mut hash_data: sha2::digest::generic_array::GenericArray<_, _> =
            [0u8; HASH_SIZE].into();

        let mut hash = Hash {
            size: self.options.block_size as u32,
            offset,
            hash: [0u8; HASH_SIZE],
        };

        let mut o = 0;
        let mut hashes_sent = 0usize;
        for _ in 0..self.options.bulk_size {
            if let Some(d) = Self::get_data(data, o as usize, self.options.block_size as usize) {
                hasher.update(d);
                hasher.finalize_into_reset(&mut hash_data);
                hash.hash.copy_from_slice(hash_data.as_slice());
                self.packet.add(&hash);

                hashes_sent += 1;
                hash.offset += self.options.block_size;
                o += self.options.block_size;
            } else {
                break;
            }
        }

        self.packet.serialize(stream)?;

        // Now get replies
        let count = self.packet.recv_next_bulk(stream)?;

        assert_eq!(count, hashes_sent);

        while let Some(ack) = self.packet.get_next::<Ack>()? {
            match ack.status {
                AckResult::HashOk => {}
                AckResult::NeedData => {
                    self.send_data(ack.offset, ack.size, stream)?;
                }
            }
        }
        (self.callback)(CallbackArg {
            offset: offset + data.len() as u64,
            size: self.filesize,
        });

        Ok(())
    }

    fn send_data<S>(&mut self, offset: u64, size: u32, stream: &mut S) -> io::Result<()>
    where
        S: Write,
    {
        self.file.seek(SeekFrom::Start(offset))?;
        self.packet
            .set_data(offset, size as usize, &mut self.file)?;
        self.packet.serialize(stream)?;

        Ok(())
    }

    fn recv_chunks<S>(&mut self, stream: &mut S) -> io::Result<u64>
    where
        S: Read + Write,
    {
        self.packet.recv_next_bulk(stream)?;

        let mut read_size = 0;
        let mut hashes = Vec::with_capacity(self.options.bulk_size as usize);

        while let Some(hash) = self.packet.get_next::<Hash>()? {
            read_size += hash.size as usize;
            hashes.push(hash);
        }

        let start_offset = hashes[0].offset;
        let mut buffer = vec![0u8; read_size];

        if self.file.stream_position()? != start_offset {
            self.file.seek(SeekFrom::Start(start_offset))?;
        }
        match self.file.read_exact(&mut buffer[..]) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                buffer.clear();
                self.file.read_to_end(&mut buffer)?;
            }
            Err(e) => {
                return Err(e);
            }
        }

        self.packet.clear();
        let mut data_needed = 0usize;
        for hash in &hashes {
            let status = if Self::check_hash(&buffer[..], start_offset, hash) {
                AckResult::HashOk
            } else {
                data_needed += 1;
                AckResult::NeedData
            };
            let ack = Ack {
                status,
                size: hash.size,
                offset: hash.offset,
            };
            self.packet.add(&ack);
        }

        self.packet.serialize(stream)?;

        for _ in 0..data_needed {
            self.packet.recv_next_bulk(stream)?;
            let data = match self.packet.get_next::<Data>()? {
                Some(d) => d,
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Empty bulk receive?!",
                    ));
                }
            };
            self.file.seek(SeekFrom::Start(data.offset))?;
            self.file.write_all(&data.buffer)?;
        }

        let size = hashes.iter().map(|h| h.size as u64).sum::<u64>();

        (self.callback)(CallbackArg {
            offset: start_offset + size,
            size: self.filesize,
        });

        Ok(size)
    }

    fn check_hash(buffer: &[u8], offset: u64, hash: &Hash) -> bool {
        if let Some(data) =
            Self::get_data(buffer, (hash.offset - offset) as usize, hash.size as usize)
        {
            let mut hasher = Sha256::new();
            let mut hash_data: sha2::digest::generic_array::GenericArray<_, _> =
                [0u8; HASH_SIZE].into();

            assert_eq!(hash.size as usize, data.len());
            hasher.update(data);
            hasher.finalize_into(&mut hash_data);
            if hash_data.as_slice() == hash.hash {
                true
            } else {
                log::debug!("offset: {offset}");
                log::debug!("hash = {hash:?}");
                log::debug!("Computed: {:02x?}", hash_data.as_slice());
                log::debug!("Received: {:02x?}", &hash.hash[..]);
                panic!();
            }
        } else {
            false
        }
    }

    pub fn send<S>(&mut self, stream: &mut S) -> io::Result<()>
    where
        S: Read + Write,
    {
        let size = self.file.metadata()?.len();
        let mut offset = 0;

        self.packet.clear();
        self.packet.add(&FileSize(size));
        self.packet.serialize(stream)?;
        let read_size = self
            .options
            .block_size
            .checked_mul(self.options.bulk_size)
            .expect("u64 Overflow, please deceasing eitehr `bulk_size` or `block_size`");

        let mut data = vec![0u8; read_size as usize];

        while offset + read_size < size {
            self.file.read_exact(&mut data[..])?;
            self.send_chunks(&data[..], offset, stream)?;
            offset += read_size;
        }

        data.clear();
        self.file.read_to_end(&mut data)?;
        if !data.is_empty() {
            self.send_chunks(&data[..], offset, stream)?;
        }

        Ok(())
    }

    pub fn recv<S>(&mut self, stream: &mut S) -> io::Result<()>
    where
        S: Read + Write,
    {
        self.packet.recv_next_bulk(stream)?;
        let filesize = match self.packet.get_next::<FileSize>()? {
            Some(fs) => fs.0,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "First bulk of data is empty",
                ));
            }
        };
        self.filesize = filesize;
        let mut offset = 0;

        while offset < filesize {
            let count = self.recv_chunks(stream)?;
            offset += count;
        }
        self.file.set_len(filesize)?;

        Ok(())
    }
}
