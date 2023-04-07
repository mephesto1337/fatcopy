use std::{
    borrow::Cow,
    fmt,
    io::{self, Read, Write},
    mem::size_of,
};

use nom::{
    bytes::streaming::take,
    combinator::{map, map_opt, rest, verify},
    error::context,
    multi::length_data,
    number::streaming::{be_u32, be_u64, be_u8},
    sequence::{preceded, tuple},
    Offset,
};

pub type IResult<'a, O> = nom::IResult<&'a [u8], O, nom::error::VerboseError<&'a [u8]>>;

pub trait Wire<'a>: Sized {
    fn deserialize(input: &'a [u8]) -> IResult<'a, Self>;

    fn serialize<W>(&self, writer: &mut W) -> io::Result<usize>
    where
        W: Write;
}

macro_rules! impl_wire_for_integer {
    ($type:ty, $nom_parser:ident) => {
        impl<'a> Wire<'a> for $type {
            fn deserialize(input: &'a [u8]) -> IResult<'a, $type> {
                $nom_parser(input)
            }

            fn serialize<W>(&self, writer: &mut W) -> io::Result<usize>
            where
                W: Write,
            {
                let bytes = self.to_be_bytes();
                writer.write_all(&bytes[..])?;
                Ok(bytes.len())
            }
        }
    };
}

impl_wire_for_integer!(u8, be_u8);
impl_wire_for_integer!(u32, be_u32);
impl_wire_for_integer!(u64, be_u64);

type SizeType = u32;
const SIZE: usize = size_of::<SizeType>();
const VARIANT_FILESIZE: u8 = 0;
const VARIANT_HASH: u8 = 1;
const VARIANT_DATA: u8 = 2;
const VARIANT_ACK: u8 = 3;

#[derive(Debug)]
pub struct FileSize(pub u64);

impl<'a> Wire<'a> for FileSize {
    fn deserialize(input: &'a [u8]) -> IResult<'a, Self> {
        context(
            "Filesize",
            preceded(verify(be_u8, |v| *v == VARIANT_FILESIZE), map(be_u64, Self)),
        )(input)
    }

    fn serialize<W>(&self, writer: &mut W) -> io::Result<usize>
    where
        W: Write,
    {
        let mut size = VARIANT_FILESIZE.serialize(writer)?;
        size += self.0.serialize(writer)?;
        Ok(size)
    }
}

pub struct Hash<const N: usize> {
    pub size: u32,
    pub offset: u64,
    pub hash: [u8; N],
}

impl<const N: usize> fmt::Debug for Hash<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use std::fmt::Write;
        let mut hash = String::with_capacity(N * 2);
        for b in &self.hash[..] {
            write!(&mut hash, "{b:02x}")?;
        }
        f.debug_struct("Hash")
            .field("size", &self.size)
            .field("offset", &self.offset)
            .field("hash", &hash)
            .finish()
    }
}

impl<'a, const N: usize> Wire<'a> for Hash<N> {
    fn deserialize(input: &'a [u8]) -> IResult<'a, Self> {
        context(
            "Hash",
            preceded(
                verify(be_u8, |v| *v == VARIANT_HASH),
                map(
                    tuple((be_u32::<&'a [u8], _>, be_u64, take(N))),
                    |(size, offset, hash_data)| {
                        let mut hash = [0u8; N];
                        hash.copy_from_slice(hash_data);
                        Self { size, offset, hash }
                    },
                ),
            ),
        )(input)
    }

    fn serialize<W>(&self, writer: &mut W) -> io::Result<usize>
    where
        W: Write,
    {
        let mut size = VARIANT_HASH.serialize(writer)?;
        size += self.size.serialize(writer)?;
        size += self.offset.serialize(writer)?;
        writer.write_all(&self.hash[..])?;

        Ok(size + N)
    }
}

pub struct Data<'a> {
    pub offset: u64,
    pub buffer: Cow<'a, [u8]>,
}

impl fmt::Debug for Data<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Data")
            .field("offset", &self.offset)
            .field("size", &self.buffer.len())
            .finish()
    }
}

impl<'a> Wire<'a> for Data<'a> {
    fn deserialize(input: &'a [u8]) -> IResult<'a, Self> {
        context(
            "Data",
            preceded(
                verify(be_u8, |v| *v == VARIANT_DATA),
                map(tuple((be_u64::<&[u8], _>, rest)), |(offset, buffer)| Self {
                    offset,
                    buffer: buffer.into(),
                }),
            ),
        )(input)
    }

    fn serialize<W>(&self, writer: &mut W) -> io::Result<usize>
    where
        W: Write,
    {
        let mut size = VARIANT_DATA.serialize(writer)?;
        size += self.offset.serialize(writer)?;
        writer.write_all(&self.buffer)?;
        Ok(size + self.buffer.len())
    }
}

#[derive(Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AckResult {
    HashOk,
    NeedData,
}

impl<'a> Wire<'a> for AckResult {
    fn deserialize(input: &'a [u8]) -> IResult<'a, Self> {
        context(
            "AckResult",
            map_opt(be_u8, |v| match v {
                0 => Some(Self::HashOk),
                1 => Some(Self::NeedData),
                _ => None,
            }),
        )(input)
    }

    fn serialize<W>(&self, writer: &mut W) -> io::Result<usize>
    where
        W: Write,
    {
        let value = match self {
            Self::HashOk => 0u8,
            Self::NeedData => 1u8,
        };
        value.serialize(writer)
    }
}

#[derive(Debug)]
pub struct Ack {
    pub status: AckResult,
    pub size: u32,
    pub offset: u64,
}

impl<'a> Wire<'a> for Ack {
    fn deserialize(input: &'a [u8]) -> IResult<'a, Self> {
        context(
            "Ack",
            preceded(
                verify(be_u8, |v| *v == VARIANT_ACK),
                map(
                    tuple((AckResult::deserialize, be_u32, be_u64)),
                    |(status, size, offset)| Self {
                        status,
                        size,
                        offset,
                    },
                ),
            ),
        )(input)
    }

    fn serialize<W>(&self, writer: &mut W) -> io::Result<usize>
    where
        W: Write,
    {
        let mut size = VARIANT_ACK.serialize(writer)?;
        size += self.status.serialize(writer)?;
        size += self.size.serialize(writer)?;
        size += self.offset.serialize(writer)?;

        Ok(size)
    }
}

#[derive(Debug, Default)]
pub struct Packet {
    /// Packet may contains several structs :
    /// offset      0:  u32: total size (excluding it-self)
    /// offset      4:  u32: size of first packet (N) (excluding it-self)
    /// offset      8: [u8]: first packet
    /// offset  8 + N:  u32: size of second packet (M) (excluding it-self)
    /// offset 12 + N: [u8]: second packet
    buffer: Vec<u8>,

    /// Internal offset of next value to yeild for `get_next` (so 4 initially)
    offset: usize,
}

impl<'a> Wire<'a> for Packet {
    fn deserialize(_input: &'a [u8]) -> IResult<'a, Self> {
        unreachable!("This `Packet::deserialize` should not be used")
    }

    fn serialize<W>(&self, writer: &mut W) -> io::Result<usize>
    where
        W: Write,
    {
        writer.write_all(&self.buffer[..])?;
        log::debug!("Serialized Packet of {} bytes", self.buffer.len());
        Ok(self.buffer.len())
    }
}

fn parse_packet(input: &'_ [u8]) -> IResult<'_, usize> {
    let (rest, mut data) = context("Packet", length_data(be_u32))(input)?;
    let mut values_count = 0;

    // Checks than we do contains only value LENGTH:DATA packets
    while !data.is_empty() {
        let (r, _) = length_data(be_u32)(data)?;
        values_count += 1;
        data = r;
    }

    Ok((rest, values_count))
}

impl Packet {
    fn parse(&mut self) -> io::Result<usize> {
        match parse_packet(&self.buffer[..]) {
            Ok((rest, c)) => {
                assert!(rest.is_empty());
                self.offset = SIZE;
                log::debug!("Got Packet with {c} values");
                Ok(c)
            }
            Err(e) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{e:?}"),
            )),
        }
    }

    pub fn clear(&mut self) {
        self.buffer.clear();
        self.buffer.resize(SIZE, 0);
        self.offset = self.buffer.len();
    }

    fn set_total_size(&mut self) {
        let total_size = self.buffer.len() - SIZE;
        let total_size32: u32 = total_size
            .try_into()
            .expect("Cannot serialize packets of 4GB+ data");

        self.buffer[..SIZE].copy_from_slice(&total_size32.to_be_bytes()[..]);
    }

    pub fn add<'a, T: Wire<'a> + std::fmt::Debug>(&mut self, value: &'a T) {
        let value_size_offset = self.buffer.len();

        // Add space for value's size
        self.buffer.resize(value_size_offset + SIZE, 0);

        // Serialize value
        let size = value
            .serialize(&mut self.buffer)
            .expect("Writing into memory should not fail");
        let size32: SizeType = size
            .try_into()
            .expect("Cannot serialize values of more than 4GB");

        self.buffer[value_size_offset..][..SIZE].copy_from_slice(&size32.to_be_bytes()[..]);
        self.set_total_size();
        log::trace!(
            "Added {value:?}, buffer increased of {} bytes ({value_size_offset} -> {})",
            self.buffer.len() - value_size_offset,
            self.buffer.len()
        );
    }

    pub fn set_data<R: Read>(
        &mut self,
        offset: u64,
        size: usize,
        reader: &mut R,
    ) -> io::Result<()> {
        self.clear();
        self.add(&Data {
            offset,
            buffer: b""[..].into(),
        });

        self.buffer.reserve(size);

        // SAFETY:
        // Read::read_exact only accepts  `&mut [u8]`, not `&mut [MaybeUninit<u8>]`
        let remaining: &mut [u8] = unsafe { std::mem::transmute(self.buffer.spare_capacity_mut()) };
        log::info!("[4] Trying read_exact of {size} bytes at offset 0x{offset:x}",);
        if let Err(e) = reader.read_exact(&mut remaining[..size]) {
            self.buffer.clear();
            Err(e)
        } else {
            // SAFETY:
            // Read succeed, so data is initialized
            let old_len = self.buffer.len();
            unsafe {
                self.buffer.set_len(old_len + size);
            }
            let data_size = self.buffer.len() - 2 * SIZE;
            let data_size32: u32 = data_size
                .try_into()
                .expect("Cannot serialize packets of 4GB+ data");

            self.buffer[SIZE..][..SIZE].copy_from_slice(&data_size32.to_be_bytes()[..]);
            self.set_total_size();
            Ok(())
        }
    }

    pub fn get_data(&self) -> io::Result<Data<'_>> {
        let (_, data_buf) = length_data(be_u32::<&[u8], ()>)(&self.buffer[self.offset..]).unwrap();
        match Data::deserialize(data_buf) {
            Ok((_, d)) => Ok(d),
            Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}"))),
        }
    }

    pub fn recv_next_bulk<R: Read>(&mut self, reader: &mut R) -> io::Result<usize> {
        self.clear();

        reader.read_exact(&mut self.buffer[..])?;
        let (_, size32) = be_u32::<&[u8], ()>(&self.buffer[..]).unwrap();
        let size: usize = size32.try_into().unwrap();
        log::debug!("Will receive a {size} bytes packet");
        self.buffer.reserve(size);

        // SAFETY:
        // Read::read_exact only accepts  `&mut [u8]`, not `&mut [MaybeUninit<u8>]`
        let remaining: &mut [u8] = unsafe { std::mem::transmute(self.buffer.spare_capacity_mut()) };
        if let Err(e) = reader.read_exact(&mut remaining[..size]) {
            self.buffer.clear();
            Err(e)
        } else {
            // SAFETY:
            // Read succeed, so data is initialized
            unsafe {
                self.buffer.set_len(SIZE + size);
            }
            self.parse()
        }
    }

    pub fn get_next<'a, T: Wire<'a>>(&'a mut self) -> io::Result<Option<T>> {
        if self.offset == self.buffer.len() {
            return Ok(None);
        }

        let (rest, data) = length_data(be_u32::<&[u8], ()>)(&self.buffer[self.offset..]).unwrap();
        match T::deserialize(data) {
            Ok((_, value)) => {
                self.offset = self.buffer.offset(rest);
                Ok(Some(value))
            }
            Err(e) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{e:x?}"),
            )),
        }
    }
}
