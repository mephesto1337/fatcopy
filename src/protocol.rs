use std::{
    borrow::Cow,
    io::{self, Write},
    mem::{size_of, size_of_val},
};

use nom::{
    bytes::streaming::take,
    combinator::{map, map_opt, verify},
    error::context,
    multi::length_data,
    number::streaming::{be_u32, be_u64, be_u8},
    sequence::{preceded, tuple},
};

pub type IResult<'a, O> = nom::IResult<&'a [u8], O, nom::error::VerboseError<&'a [u8]>>;

pub trait Wire: Sized {
    fn deserialize(input: &[u8]) -> IResult<'_, Self>;

    fn size_hint() -> usize;

    fn serialize<W>(&self, writer: &mut W) -> io::Result<()>
    where
        W: Write;

    fn serialize_into(&self, buffer: &mut Vec<u8>) {
        self.serialize(buffer)
            .expect("Write into a buffer should never fail");
    }
}

const VARIANT_FILESIZE: u8 = 0;
const VARIANT_HASH: u8 = 1;
const VARIANT_DATA: u8 = 2;
const VARIANT_ACK: u8 = 3;

#[derive(Debug)]
pub struct FileSize(pub u64);

impl Wire for FileSize {
    fn deserialize(input: &[u8]) -> IResult<'_, Self> {
        context(
            "Filesize",
            preceded(verify(be_u8, |v| *v == VARIANT_FILESIZE), map(be_u64, Self)),
        )(input)
    }

    fn size_hint() -> usize {
        size_of_val(&VARIANT_FILESIZE) + size_of::<u64>()
    }

    fn serialize<W>(&self, writer: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        let mut buffer = [0u8; 9];
        buffer[0] = VARIANT_FILESIZE;
        buffer[1..].copy_from_slice(&self.0.to_be_bytes()[..]);
        writer.write_all(&buffer[..])
    }

    fn serialize_into(&self, buffer: &mut Vec<u8>) {
        buffer.push(VARIANT_FILESIZE);
        buffer.extend_from_slice(&self.0.to_be_bytes()[..]);
    }
}

#[derive(Debug)]
pub struct Hash<'a, const N: usize> {
    pub size: u32,
    pub hash: Cow<'a, [u8]>,
}

impl<const N: usize> Wire for Hash<'_, N> {
    fn deserialize<'a>(input: &'a [u8]) -> IResult<'a, Self> {
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

    fn size_hint() -> usize {
        size_of_val(&VARIANT_HASH) + size_of::<u32>() + N
    }

    fn serialize<W>(&self, writer: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        let mut buffer = Vec::new();
        self.serialize_into(&mut buffer);
        writer.write_all(&buffer[..])
    }

    fn serialize_into(&self, buffer: &mut Vec<u8>) {
        buffer.push(VARIANT_HASH);
        buffer.extend_from_slice(&self.size.to_be_bytes()[..]);
        buffer.extend_from_slice(&self.hash);
    }
}

#[derive(Debug)]
pub struct Data<'a>(pub Cow<'a, [u8]>);

impl Wire for Data<'_> {
    fn deserialize(input: &[u8]) -> IResult<'_, Self> {
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

    fn size_hint() -> usize {
        size_of_val(&VARIANT_DATA) + size_of::<u32>()
    }

    fn serialize<W>(&self, writer: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        let mut header = [0u8; 5];
        header[0] = VARIANT_DATA;
        let size: u32 = self.0.len().try_into().expect("Buffer is over 4GB?!");
        header[1..].copy_from_slice(&size.to_be_bytes()[..]);
        writer.write_all(&header[..])?;
        writer.write_all(&self.0)
    }
}

#[derive(Debug)]
pub enum Ack {
    Hash,
    NeedData,
}

impl Wire for Ack {
    fn deserialize(input: &[u8]) -> IResult<'_, Self> {
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

    fn size_hint() -> usize {
        2
    }

    fn serialize<W>(&self, writer: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        let value = match self {
            Ack::Hash => 0,
            Ack::NeedData => 1,
        };
        let buffer = [VARIANT_ACK, value];
        writer.write_all(&buffer[..])
    }
}
