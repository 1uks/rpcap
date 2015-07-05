extern crate byteorder;

use std::io;
use self::byteorder::ByteOrder;

pub trait ReadExact : io::Read {
    fn read_exact(&mut self, len: usize) -> io::Result<Vec<u8>> {
        let mut v = Vec::with_capacity(len);
        unsafe { v.set_len(len) };
        let mut count = 0usize;
        while count != len {
            count += match self.read(&mut v[count..]) {
                Ok(n) => {
                    if n == 0 {
                        return Err(io::Error::new(io::ErrorKind::Other, "Premature EOF"))
                    }
                    n
                },
                Err(e) => {
                    if e.kind() != io::ErrorKind::Interrupted {
                        return Err(e);
                    }
                    0
                },
            };
        }
        Ok(v)
    }
}

impl<R: io::Read + ?Sized> ReadExact for R {}

pub struct LittleEndian;
pub struct BigEndian;

pub trait NumConversion {
    fn to_u32(&self, &[u8]) -> u32;
    fn to_i32(&self, &[u8]) -> i32;
    fn to_u16(&self, &[u8]) -> u16;
}

impl NumConversion for LittleEndian {
    fn to_u32(&self, buf: &[u8]) -> u32 {
        byteorder::LittleEndian::read_u32(buf)
    }

    fn to_i32(&self, buf: &[u8]) -> i32 {
        byteorder::LittleEndian::read_i32(buf)
    }

    fn to_u16(&self, buf: &[u8]) -> u16 {
        byteorder::LittleEndian::read_u16(buf)
    }
}

impl NumConversion for BigEndian {
    fn to_u32(&self, buf: &[u8]) -> u32 {
        byteorder::BigEndian::read_u32(buf)
    }

    fn to_i32(&self, buf: &[u8]) -> i32 {
        byteorder::BigEndian::read_i32(buf)
    }

    fn to_u16(&self, buf: &[u8]) -> u16 {
        byteorder::BigEndian::read_u16(buf)
    }
}

pub fn get_conv_for_endianess(endianess: Endianess) -> Box<NumConversion> {
    match endianess {
        Endianess::Little => Box::new(LittleEndian),
        Endianess::Big => Box::new(BigEndian),
    }
}

#[derive(Debug)]
pub enum Endianess {
    Little,
    Big,
}

#[cfg(target_endian = "little")]
pub fn get_native_endianess() -> Endianess {
    Endianess::Little
}

#[cfg(target_endian = "big")]
pub fn get_native_endianess() -> Endianess {
    Endianess::Big
}

#[cfg(target_endian = "little")]
pub fn get_inverse_endianess() -> Endianess {
    Endianess::Big
}

#[cfg(target_endian = "big")]
pub fn get_inverse_endianess() -> Endianess {
    Endianess::Little
}
