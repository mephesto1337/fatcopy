use std::{
    fmt,
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};

use sha2::{Digest, Sha256};

const HASH_SIZE: usize = 32;

/// Default block size to split files on
pub const DEFAULT_BLOCK_SIZE: u64 = 4096;

/// Maximum read size on Linux according to man (2) read.
pub const MAXIMUM_READ_SIZE: u64 = 0x7fff_f000;

/// Default number of blocks to read at once
pub const DEFAULT_BULK_SIZE: u64 = 256;

mod protocol;
use protocol::{Ack, AckResult, Data, FileSize, Packet, Wire};

type Hash = protocol::Hash<HASH_SIZE>;

/// Callback's argument on update
pub struct CallbackArg {
    /// The current offset of the file **after** the packets are proceeded
    pub offset: u64,

    /// The total size of the "new"/"source" file.
    pub size: u64,
}

/// Options to tune I/Os performance
#[derive(Debug, Clone)]
pub struct Options {
    /// The partition size of the file. The file will be divided by `block_size` bytes unit blocks.
    pub block_size: u64,

    /// How many blocks to threat on each loop (to do a bigger read) and send a "full" packet of
    /// update (not just a few bytes).
    pub bulk_size: u64,
}

/// Represent a file to be copied (from or to)
pub struct FatCopy {
    /// The file it self
    file: File,

    /// Has the file reached EOF, then do not check hashes, just ask for data
    has_reached_eof: bool,

    /// The underlying serialization structure
    packet: Packet,

    /// A callback for updates
    callback: Box<dyn FnMut(CallbackArg)>,

    /// At construction time, the `file`'s size, then the size of the "destination" file.
    old_filesize: u64,

    /// At construction time, the `file`'s size, then the size of the "source" file.
    new_filesize: u64,

    /// Options to maximize performance between disks I/Os and network I/Os.
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
    pub fn open_as_source(path: impl AsRef<Path>) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .write(false)
            .create(false)
            .open(path)
    }

    pub fn open_as_destination(path: impl AsRef<Path>) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)
    }

    /// Creates a file to be copied from/to with options.
    pub fn new_with_options(file: File, options: Options) -> io::Result<Self> {
        let filesize = file.metadata()?.len();
        Ok(Self {
            file,
            has_reached_eof: false,
            packet: Packet::default(),
            callback: Box::new(|_| {}),
            options,
            new_filesize: filesize,
            old_filesize: filesize,
        })
    }

    /// Same as [`FatCopy::new_with_options`] but uses default values.
    pub fn new(file: File) -> io::Result<Self> {
        Self::new_with_options(
            file,
            Options {
                block_size: DEFAULT_BLOCK_SIZE,
                bulk_size: DEFAULT_BULK_SIZE,
            },
        )
    }

    /// Register a custom callback. The default one does nothing.
    pub fn register_callback(&mut self, callback: impl FnMut(CallbackArg) + 'static) {
        self.callback = Box::new(callback);
    }

    /// Internal: gets slice starting at offset `offset` with a `size` bytes maximum.
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

        // Computes hash of each block
        let mut o = 0;
        let mut hashes_sent = 0usize;
        for _ in 0..self.options.bulk_size {
            if let Some(d) = Self::get_data(data, o as usize, self.options.block_size as usize) {
                let mut hash = Hash {
                    size: d.len() as u32,
                    offset: offset + o,
                    hash: [0u8; HASH_SIZE],
                };

                sha2::digest::DynDigest::update(&mut hasher, d);
                sha2::digest::DynDigest::finalize_into_reset(&mut hasher, &mut hash.hash[..])
                    .unwrap();
                self.packet.add(&hash);

                hashes_sent += 1;
                o += self.options.block_size;
            } else {
                break;
            }
        }

        // Sends the hashes
        self.packet.serialize(stream)?;

        // Now get replies
        let count = self.packet.recv_next_bulk(stream)?;

        // Saves the replies in a local buffer.
        let mut acks = Vec::with_capacity(count);
        while let Some(ack) = self.packet.get_next::<Ack>()? {
            acks.push(ack);
        }

        // Sanity check
        assert_eq!(count, hashes_sent);

        // Process the replies
        for ack in acks {
            match ack.status {
                // Hash was OK, nothing to do, we can move forward
                AckResult::HashOk => {}
                // Hash does not match on the other side, sends the data
                AckResult::NeedData => {
                    let d = Data {
                        offset: ack.offset,
                        // Sure, `ack` is a user control data, but if its bad it will just crash.
                        buffer: Self::get_data(data, ack.offset as usize, ack.size as usize)
                            .unwrap()
                            .into(),
                    };
                    self.packet.clear();
                    self.packet.add(&d);
                    self.packet.serialize(stream)?;
                }
            }
        }

        // Calls callback
        (self.callback)(CallbackArg {
            offset: offset + data.len() as u64,
            size: self.new_filesize,
        });

        Ok(())
    }

    fn recv_chunks<S>(&mut self, stream: &mut S) -> io::Result<u64>
    where
        S: Read + Write,
    {
        // Gets next hashes
        self.packet.recv_next_bulk(stream)?;

        // Total amount of bytes describes by hashes
        let mut read_size = 0;

        // Collects hashes in a local buffer to avoid locking self.packet's memory
        let mut hashes = Vec::with_capacity(self.options.bulk_size as usize);
        while let Some(hash) = self.packet.get_next::<Hash>()? {
            read_size += hash.size as usize;
            hashes.push(hash);
        }

        let start_offset = hashes[0].offset;

        // Clear self.packet
        self.packet.clear();

        // Number of invalid hashes found
        let mut data_blocks_needed = 0usize;

        let data_blocks_needed = if self.has_reached_eof {
            // If EOF il already reached, just ask for all the chunks
            for hash in &hashes {
                self.packet.add(&Ack {
                    status: AckResult::NeedData,
                    size: hash.size,
                    offset: hash.offset,
                });
            }
            hashes.len()
        } else {
            // Buffer to read as mamny bytes as described by hashes
            let mut buffer = Vec::with_capacity(read_size);

            if start_offset + read_size as u64 <= self.old_filesize {
                // We are too away for our EOF, so we can do a read_exact and not get an
                // [`std::io::ErrorKind::UnexpectedEof`].
                let buf: &mut [u8] = unsafe { std::mem::transmute(buffer.spare_capacity_mut()) };
                log::info!(
                    "[5] Trying read_exact of {n} bytes at offset {start_offset}",
                    n = buf.len()
                );
                self.file.read_exact(buf)?;
                // SAFETY: read_size is <= than capacity and data is initialized up to `read_size`
                unsafe { buffer.set_len(read_size) };
            } else {
                // start_offset + read_size will go beyond EOF, so just reads unitl EOF.
                self.file.read_to_end(&mut buffer)?;

                // Mark self as done reading
                self.has_reached_eof = true;
                log::info!("EOF is reached, will use fast-path for next iteration");
            }

            // Now checks hashes
            for hash in &hashes {
                let status = if Self::check_hash(&buffer[..], start_offset, hash) {
                    AckResult::HashOk
                } else {
                    data_blocks_needed += 1;
                    AckResult::NeedData
                };
                let ack = Ack {
                    status,
                    size: hash.size,
                    offset: hash.offset,
                };
                self.packet.add(&ack);
            }
            data_blocks_needed
        };

        // Sends `Ack`
        self.packet.serialize(stream)?;

        // Gets data blocks
        for _ in 0..data_blocks_needed {
            self.packet.recv_next_bulk(stream)?;
            let data = self.packet.get_data()?;
            self.file.seek(SeekFrom::Start(data.offset))?;
            self.file.write_all(&data.buffer)?;
        }

        // Number of bytes proceeded
        let size = hashes.iter().map(|h| h.size as u64).sum::<u64>();

        if data_blocks_needed > 0 {
            // We might not a at the right position so let's seek
            let position = start_offset + size;
            self.file.seek(SeekFrom::Start(position))?;
        }

        // Calls callback
        (self.callback)(CallbackArg {
            offset: start_offset + size,
            size: self.new_filesize,
        });

        Ok(size)
    }

    fn check_hash(buffer: &[u8], offset: u64, hash: &Hash) -> bool {
        if let Some(data) =
            Self::get_data(buffer, (hash.offset - offset) as usize, hash.size as usize)
        {
            // If our data is too short, do not compute hash and early return falsee
            if data.len() != hash.size as usize {
                return false;
            }
            let mut hasher = Sha256::new();
            let mut hash_data = [0u8; HASH_SIZE];

            log::debug!("checking {hash:x?}");
            assert_eq!(hash.size as usize, data.len());
            sha2::digest::DynDigest::update(&mut hasher, data);
            sha2::digest::DynDigest::finalize_into(hasher, &mut hash_data[..]).unwrap();
            if hash_data[..] == hash.hash {
                true
            } else {
                log::debug!("Computed: {:02x?}", hash_data.as_slice());
                log::debug!("Received: {:02x?}", &hash.hash[..]);
                false
            }
        } else {
            // If offset was beyond buffer, then hash cannot match
            false
        }
    }

    /// Sends our filesize and receive, then return their filesize
    fn exchange_sizes<S>(&mut self, stream: &mut S) -> io::Result<u64>
    where
        S: Read + Write,
    {
        self.packet.clear();
        self.packet.add(&FileSize(self.old_filesize));
        self.packet.serialize(stream)?;

        self.packet.recv_next_bulk(stream)?;
        match self.packet.get_next::<FileSize>()? {
            Some(fs) => Ok(fs.0),
            None => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "First bulk of data is empty",
            )),
        }
    }

    /// Sends a file through an Read/Write object
    pub fn send<S>(&mut self, stream: &mut S) -> io::Result<()>
    where
        S: Read + Write,
    {
        self.old_filesize = self.exchange_sizes(stream)?;
        let mut offset = 0;

        let read_size = self
            .options
            .block_size
            .checked_mul(self.options.bulk_size)
            .expect("u64 Overflow, please deceasing eitehr `bulk_size` or `block_size`");

        log::info!("Using {read_size} buffer size for reads");
        let mut data = vec![0u8; read_size as usize];

        // 1. set hashes and maybe data if hash do not match
        while offset + read_size < self.new_filesize.min(self.old_filesize) {
            self.file.read_exact(&mut data[..])?;
            self.send_chunks(&data[..], offset, stream)?;
            offset += read_size;
        }

        if self.new_filesize <= self.old_filesize {
            // 2. If new size is smaller, just then the rest of data as chunks
            let n = self.new_filesize - offset;
            if n > 0 {
                log::info!("[2] Trying read_exact of {n} bytes at offset 0x{offset:x}");
                self.file.read_exact(&mut data[..n as usize])?;
                self.send_chunks(&data[..n as usize], offset, stream)?;
            }

            return Ok(());
        }

        // 3. New size is bigger, Sends chunks until `self.old_filesize`
        let n = self.old_filesize - offset;
        assert!(n < read_size);
        log::info!("[3] Trying read_exact of {n} bytes at offset 0x{offset:x}");
        self.file.read_exact(&mut data[..n as usize])?;
        self.send_chunks(&data[..n as usize], offset, stream)?;
        offset += n;

        // 4. Just send data for now on
        while offset + read_size < self.new_filesize {
            self.packet
                .set_data(offset, read_size as usize, &mut self.file)?;
            self.packet.serialize(stream)?;
            offset += read_size;
        }

        // 5. Sends the rest
        if offset < self.new_filesize {
            log::info!(
                "offset=0x{offset:x}, new_filesize=0x{:x}",
                self.new_filesize
            );
            let n = self.new_filesize - offset;
            self.packet.set_data(offset, n as usize, &mut self.file)?;
            self.packet.serialize(stream)?;
        }

        Ok(())
    }

    /// Sends a file's updates through an Read/Write object
    pub fn recv<S>(&mut self, stream: &mut S) -> io::Result<()>
    where
        S: Read + Write,
    {
        self.new_filesize = self.exchange_sizes(stream)?;

        let mut offset = 0;

        // 1. received hashes until min sized
        while offset < self.old_filesize.min(self.new_filesize) {
            let count = self.recv_chunks(stream)?;
            offset += count;
        }

        // 2. If new size is smaller, we are done
        if self.new_filesize <= self.old_filesize {
            self.file.set_len(self.new_filesize)?;
            return Ok(());
        }

        // 3. Now we will only receive data

        // 3.a Checks than offset and file position are in sync
        #[cfg(debug_assertions)]
        {
            let position = self.file.stream_position()?;
            log::warn!("Offset ({offset}) and file.position ({position}) were not in sync");
            if position != offset {
                self.file.seek(SeekFrom::Start(offset))?;
            }
        }
        while offset < self.new_filesize {
            self.packet.recv_next_bulk(stream)?;
            let data = self.packet.get_next::<Data>()?.unwrap();

            assert_eq!(offset, data.offset);

            self.file.write_all(&data.buffer)?;
            offset += data.buffer.len() as u64;

            (self.callback)(CallbackArg {
                offset: offset + data.buffer.len() as u64,
                size: self.new_filesize,
            });
        }

        Ok(())
    }
}
