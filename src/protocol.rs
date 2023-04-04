use std::{
    borrow::Cow,
    io::{self, Read, Write},
    mem::size_of,
};

use nom::{
    bytes::streaming::take,
    combinator::{map, map_opt, verify},
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
        let mut buffer = [0u8; 9];
        buffer[0] = VARIANT_FILESIZE;
        buffer[1..].copy_from_slice(&self.0.to_be_bytes()[..]);
        writer.write_all(&buffer[..])?;
        Ok(buffer.len())
    }
}

#[derive(Debug)]
pub struct Hash<'a, const N: usize> {
    pub size: u32,
    pub hash: Cow<'a, [u8]>,
}

impl<'a, const N: usize> Wire<'a> for Hash<'a, N> {
    fn deserialize(input: &'a [u8]) -> IResult<'a, Self> {
        context(
            "Hash",
            preceded(
                verify(be_u8, |v| *v == VARIANT_HASH),
                map(tuple((be_u32::<&'a [u8], _>, take(N))), |(size, hash)| {
                    Self {
                        size,
                        hash: Cow::Owned(hash.to_vec()),
                    }
                }),
            ),
        )(input)
    }

    fn serialize<W>(&self, writer: &mut W) -> io::Result<usize>
    where
        W: Write,
    {
        debug_assert_eq!(self.hash.len(), N);

        writer.write_all(&[VARIANT_HASH])?;
        writer.write_all(&self.size.to_be_bytes()[..])?;
        writer.write_all(&self.hash)?;

        Ok(5 + self.hash.len())
    }
}

impl<'a, const N: usize> Hash<'a, N> {
    pub fn to_owned(self) -> Hash<'static, N> {
        Hash {
            size: self.size,
            hash: Cow::Owned(self.hash.into_owned()),
        }
    }
}

#[derive(Debug)]
pub struct Data<'a>(pub Cow<'a, [u8]>);

impl<'a> Wire<'a> for Data<'_> {
    fn deserialize(input: &'a [u8]) -> IResult<'a, Self> {
        context(
            "Data",
            preceded(
                verify(be_u8, |v| *v == VARIANT_DATA),
                map(length_data(be_u32), |data: &[u8]| {
                    Self(data.to_vec().into())
                }),
            ),
        )(input)
    }

    fn serialize<W>(&self, writer: &mut W) -> io::Result<usize>
    where
        W: Write,
    {
        writer.write_all(&[VARIANT_DATA][..])?;
        writer.write_all(&self.0)?;
        Ok(1 + self.0.len())
    }
}

#[derive(Debug)]
pub enum Ack {
    Hash,
    NeedData,
}

impl<'a> Wire<'a> for Ack {
    fn deserialize(input: &'a [u8]) -> IResult<'a, Self> {
        context(
            "Ack",
            preceded(
                verify(be_u8, |v| *v == VARIANT_ACK),
                map_opt(be_u8, |v| match v {
                    0 => Some(Self::Hash),
                    1 => Some(Self::NeedData),
                    _ => None,
                }),
            ),
        )(input)
    }

    fn serialize<W>(&self, writer: &mut W) -> io::Result<usize>
    where
        W: Write,
    {
        let value = match self {
            Ack::Hash => 0,
            Ack::NeedData => 1,
        };
        let buffer = [VARIANT_ACK, value];
        writer.write_all(&buffer[..])?;
        Ok(2)
    }
}

#[derive(Debug, Default)]
pub struct Packet {
    buffer: Vec<u8>,
}

impl<'a> Wire<'a> for Packet {
    fn deserialize(input: &'a [u8]) -> IResult<'a, Self> {
        let (rest, _) = context("Packet", length_data(be_u32))(input)?;

        let size = input.offset(rest);
        Ok((
            rest,
            Self {
                buffer: input[..size].to_owned(),
            },
        ))
    }

    fn serialize<W>(&self, writer: &mut W) -> io::Result<usize>
    where
        W: Write,
    {
        writer.write_all(&self.buffer[..])?;
        Ok(self.buffer.len())
    }
}

impl Packet {
    pub fn set<'a, T: Wire<'a>>(&mut self, value: &'a T) {
        self.buffer.clear();
        self.buffer.resize(SIZE, 0);
        let size = value
            .serialize(&mut self.buffer)
            .expect("Writing into memory should not fail");
        let size32: SizeType = size.try_into().unwrap_or_else(|_| {
            panic!("Buffer is over 0x{:x}", SizeType::MAX);
        });
        self.buffer[..SIZE].copy_from_slice(&size32.to_be_bytes()[..]);
    }

    pub fn recv<'a, T: Wire<'a>, R: Read>(&'a mut self, reader: &mut R) -> io::Result<T> {
        self.buffer.clear();
        self.buffer.reserve(SIZE);

        reader.read_exact(&mut self.buffer[..])?;
        let (_, size32) = be_u32::<&[u8], ()>(&self.buffer[..]).unwrap();
        let size: usize = size32.try_into().unwrap();
        self.buffer.reserve(size);

        // SAFETY:
        // If next read succeed, then data is initialized, otherwise buffer is cleared
        unsafe {
            self.buffer.set_len(SIZE + size);
        }
        match reader.read_exact(&mut self.buffer[SIZE..]) {
            Ok(()) => {}
            Err(e) => {
                self.buffer.clear();
                return Err(e);
            }
        }

        match T::deserialize(&self.buffer[SIZE..]) {
            Ok((rest, value)) => {
                debug_assert!(rest.is_empty());
                Ok(value)
            }
            Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}"))),
        }
    }
}
