use std::{
    borrow::Cow,
    io::{self, Write},
    mem::{size_of, size_of_val},
};

use nom::{
    bytes::streaming::take,
    combinator::{map, map_opt, verify},
    error::{context, ContextError, ParseError},
    multi::length_data,
    number::streaming::{be_u32, be_u64, be_u8},
    sequence::{preceded, tuple},
};

pub enum CanDeserialize {
    Yes { consumed: usize },
    Incomplete(nom::Needed),
    No,
}

pub trait NomError<'a>: ParseError<&'a [u8]> + ContextError<&'a [u8]> {}

impl<'a, E> NomError<'a> for E where E: ParseError<&'a [u8]> + ContextError<&'a [u8]> {}

pub trait Wire<'a>: Sized {
    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>;

    fn can_deserialize(input: &'a [u8]) -> CanDeserialize {
        match Self::deserialize::<()>(input) {
            Ok((rest, _)) => CanDeserialize::Yes {
                consumed: input.len() - rest.len(),
            },
            Err(nom::Err::Incomplete(n)) => CanDeserialize::Incomplete(n),
            Err(_) => CanDeserialize::No,
        }
    }

    fn min_size() -> usize;

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

impl<'a> Wire<'a> for FileSize {
    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        context(
            "Filesize",
            preceded(
                verify(be_u8, |v| *v == VARIANT_FILESIZE),
                map(be_u64, |size| Self(size)),
            ),
        )(input)
    }

    fn min_size() -> usize {
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

impl<'a, const N: usize> Wire<'a> for Hash<'a, N> {
    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        context(
            "Hash",
            preceded(
                verify(be_u8, |v| *v == VARIANT_HASH),
                map(tuple((be_u32, take(N))), |(size, hash)| Self {
                    size,
                    hash: Cow::Borrowed(hash),
                }),
            ),
        )(input)
    }

    fn min_size() -> usize {
        1 + size_of::<u32>() + N
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

impl<'a, const N: usize> Hash<'a, N> {
    pub fn into_owned(self) -> Hash<'static, N> {
        Hash {
            size: self.size,
            hash: Cow::Owned(self.hash.into_owned()),
        }
    }
}

#[derive(Debug)]
pub struct Data<'a>(pub &'a [u8]);

impl<'a> Wire<'a> for Data<'a> {
    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        context(
            "Data",
            preceded(
                verify(be_u8, |v| *v == VARIANT_DATA),
                map(length_data(be_u32), |data| Self(data)),
            ),
        )(input)
    }

    fn min_size() -> usize {
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
        writer.write_all(self.0)
    }
}

#[derive(Debug)]
pub enum Ack {
    Hash,
    NeedData,
}

impl<'a> Wire<'a> for Ack {
    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
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

    fn min_size() -> usize {
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
