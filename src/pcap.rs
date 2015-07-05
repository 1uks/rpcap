extern crate byteorder;

const MAGIC_VALUE: u32 = 0xa1b2c3d4;
const REVERSED_MAGIC_VALUE: u32 = 0xd4c3b2a1;

use std::io;
use std::iter;
use std::mem;

use utils::*;
use self::byteorder::{ReadBytesExt, ByteOrder};

#[derive(Debug)]
struct PcapHeader {
    magic_number: u32,
    version_major: u16,
    version_minor: u16,
    thiszone: i32,
    sigfigs: u32,
    snaplen: u32,
    network: u32,
}

#[derive(Debug)]
struct PacketHeader {
    ts_sec: u32,
    ts_usec: u32,
    incl_len: u32,
    orig_len: u32,
}

#[derive(Debug)]
pub struct Packet {
    header: PacketHeader,
    data: Vec<u8>
}

pub struct PcapParser<R: io::Read> {
    reader: R,
    conv: Box<NumConversion>,
    header: PcapHeader,
}

#[derive(Debug)]
pub enum ParserError {
    InvalidMagicNumber,
    PrematureEof,
    IOError(io::Error),
}

impl From<io::Error> for ParserError {
    fn from(err: io::Error) -> ParserError {
        ParserError::IOError(err)
    }
}

impl From<byteorder::Error> for ParserError {
    fn from(err: byteorder::Error) -> ParserError {
        match err {
            byteorder::Error::Io(e) => ParserError::IOError(e),
            byteorder::Error::UnexpectedEOF => ParserError::PrematureEof,
        }
    }
}

impl<R: io::Read> PcapParser<R> {
    pub fn from_reader(mut reader: R) -> Result<PcapParser<R>, ParserError> {
        let header_bytes = try!(reader.read_exact(mem::size_of::<PcapHeader>()));
        let magic_number = byteorder::NativeEndian::read_u32(&header_bytes[0..4]);
        let byteorder = match magic_number {
            MAGIC_VALUE => {
                get_native_endianess()
            },
            REVERSED_MAGIC_VALUE => {
                get_inverse_endianess()
            },
            _ => {
                return Err(ParserError::InvalidMagicNumber);
            }
        };

        let conv = get_conv_for_endianess(byteorder);

        let header = PcapHeader {
            magic_number: MAGIC_VALUE,
            version_major: conv.to_u16(&header_bytes[4..6]),
            version_minor: conv.to_u16(&header_bytes[6..8]),
            thiszone: conv.to_i32(&header_bytes[8..12]),
            sigfigs: conv.to_u32(&header_bytes[12..16]),
            snaplen: conv.to_u32(&header_bytes[16..20]),
            network: conv.to_u32(&header_bytes[20..24]),
        };

        Ok(PcapParser {
            reader: reader,
            header: header,
            conv: conv,
        })
    }

    pub fn parse_packet(&mut self) -> Result<Packet, ParserError> {
        let header = try!(self.parse_packet_header());
        Ok(Packet {
            data: try!(self.reader.read_exact(header.incl_len as usize)),
            header: header,
        })
    }

    fn parse_packet_header(&mut self) -> Result<PacketHeader, ParserError> {
        let header_bytes = try!(self.reader.read_exact(mem::size_of::<PacketHeader>()));
        Ok(PacketHeader {
            ts_sec: self.conv.to_u32(&header_bytes[0..4]),
            ts_usec: self.conv.to_u32(&header_bytes[4..8]),
            incl_len: self.conv.to_u32(&header_bytes[8..12]),
            orig_len: self.conv.to_u32(&header_bytes[12..16]),
        })
    }
}

impl<R: io::Read> iter::Iterator for PcapParser<R> {
    type Item = Packet;

    fn next(&mut self) -> Option<Self::Item> {
        self.parse_packet().ok()
    }

}
