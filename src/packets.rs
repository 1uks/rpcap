extern crate byteorder;

use std::fmt;
use std::convert;
use std::net::Ipv4Addr;
use self::byteorder::ByteOrder;
use utils::*;

trait Checksum {
    fn checksum_valid(&self) -> bool;
}

pub struct MacAddress(pub u8, pub u8, pub u8, pub u8, pub u8, pub u8);

impl MacAddress {
    fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> MacAddress {
        MacAddress(a, b, c, d, e, f)
    }
}

impl fmt::Debug for MacAddress {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            self.0, self.1, self.2, self.3, self.4, self.5)
    }
}

// FIXME add more types (https://en.wikipedia.org/wiki/EtherType)
#[derive(Debug)]
pub enum EtherType {
    IPv4,
    ARP,
    IPv6,
    Unknown(u16),
}

impl convert::Into<EtherType> for u16 {
    fn into(self) -> EtherType {
        match self {
            0x0800 => EtherType::IPv4,
            0x0806 => EtherType::ARP,
            0x86dd => EtherType::IPv6,
            value => EtherType::Unknown(value),
        }
    }
}

#[derive(Debug)]
pub struct EthernetFrame<'a> {
    pub dst: MacAddress,
    pub src: MacAddress,
    pub ethertype: EtherType,
    pub payload: &'a [u8],
    pub raw: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    pub fn new(buf: &'a [u8]) -> Option<EthernetFrame<'a>> {
        if buf.len() < Self::min_size() {
            return None
        }
        let src = MacAddress::new(buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
        let dst = MacAddress::new(buf[6], buf[7], buf[8], buf[9], buf[10], buf[11]);
        let ethertype = byteorder::BigEndian::read_u16(&buf[12..14]).into();
        let payload = &buf[14..];

        Some(EthernetFrame {
            dst: dst,
            src: src,
            ethertype: ethertype,
            payload: payload,
            raw: buf,
        })
    }

    pub fn min_size() -> usize { // FIXME trait function?
        6 /* dest */ + 6 /* src*/ + 2 /* ethertype */ + 0 /* payload */
    }
}

// FIXME add more types (https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers)
#[derive(Debug)]
pub enum IpProtocol {
    Tcp,
    Udp,
    Unknown(u8),
}

impl convert::Into<IpProtocol> for u8 {
    fn into(self) -> IpProtocol {
        match self {
            0x06 => IpProtocol::Tcp,
            0x11 => IpProtocol::Udp,
            value => IpProtocol::Unknown(value),
        }
    }
}

#[derive(Debug)]
pub struct IpFlags {
    pub dont_fragment: bool,
    pub more_fragments: bool,
}

impl convert::Into<IpFlags> for u8 {
    fn into(self) -> IpFlags {
        IpFlags {
            dont_fragment: is_bit_set(self, BitPosition::Second),
            more_fragments: is_bit_set(self, BitPosition::First),
        }
    }
}

#[derive(Debug)]
pub struct Ipv4Packet<'a> {
    pub version: u8,
    pub ihl: u8,
    pub tos: u8,
    pub length: u16,
    pub id: u16,
    pub flags: IpFlags,
    pub offset: u16,
    pub ttl: u8,
    pub proto: IpProtocol,
    pub checksum: u16,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub options: Option<&'a [u8]>,
    pub payload: &'a [u8],
    pub raw: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    pub fn new(buf: &'a [u8]) -> Option<Ipv4Packet<'a>> {
        if buf.len() < 20 {
            return None
        }

        let version = buf[0] >> 4;
        let ihl = buf[0] & 0xf;
        let tos = buf[1];
        let length = byteorder::BigEndian::read_u16(&buf[2..4]);
        let id = byteorder::BigEndian::read_u16(&buf[4..6]);
        let flags = (buf[6] >> 5).into();
        let offset = byteorder::BigEndian::read_u16(&[buf[6] & 0b00011111, buf[7]]);
        let ttl = buf[8];
        let proto = buf[9].into();
        let checksum = byteorder::BigEndian::read_u16(&buf[10..12]);
        let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
        let dst = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
        let num_options = ihl * 4 - 20;

        if num_options > 0 {
            return None; // FIXME implement
        }

        Some(Ipv4Packet {
            version: version,
            ihl: ihl,
            tos: tos,
            length: length,
            id: id,
            flags: flags,
            offset: offset,
            ttl: ttl,
            proto: proto,
            checksum: checksum,
            src: src,
            dst: dst,
            options: None,
            payload: &buf[20..],
            raw: &buf,
        })
    }
}

#[derive(Debug)]
pub struct TcpFlags {
    ns: bool,
    cwr: bool,
    ece: bool, 
    urg: bool, 
    ack: bool, 
    psh: bool, 
    rst: bool,
    syn: bool, 
    fin: bool,
}

impl Default for TcpFlags {
    fn default() -> TcpFlags {
        TcpFlags {
            ns: false,
            cwr: false,
            ece: false,
            urg: false,
            ack: false,
            psh: false,
            rst: false,
            syn: false,
            fin: false,
        }
    }
}

impl TcpFlags {
    fn new(buf: &[u8]) -> Option<TcpFlags> {
        if buf.len() != 2 {
            None
        } else {
            Some(TcpFlags {
                ns: is_bit_set(buf[0], BitPosition::First),
                cwr: is_bit_set(buf[1], BitPosition::Eighth),
                ece: is_bit_set(buf[1], BitPosition::Seventh),
                urg: is_bit_set(buf[1], BitPosition::Sixth),
                ack: is_bit_set(buf[1], BitPosition::Fifth),
                psh: is_bit_set(buf[1], BitPosition::Fourth),
                rst: is_bit_set(buf[1], BitPosition::Third),
                syn: is_bit_set(buf[1], BitPosition::Second),
                fin: is_bit_set(buf[1], BitPosition::First),
            })
        }
    }
}

#[derive(Debug)]
pub struct TcpSegment<'a> {
    pub src: u16,
    pub dst: u16,
    pub seq: u32,
    pub ack: u32,
    pub data_offset: u8,
    pub flags: TcpFlags,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: Option<u16>,
    pub options: Option<&'a [u8]>,
    pub payload: &'a [u8],
    pub raw: &'a [u8],
}

impl<'a> TcpSegment<'a> {
    pub fn new(buf: &'a [u8]) -> Option<TcpSegment<'a>> {
        if buf.len() < 20 { // FIXME add more strict check
            return None;
        }

        let src = byteorder::BigEndian::read_u16(&buf[0..2]);
        let dst = byteorder::BigEndian::read_u16(&buf[2..4]);
        let seq = byteorder::BigEndian::read_u32(&buf[4..8]);
        let ack = byteorder::BigEndian::read_u32(&buf[8..12]);
        let data_offset = buf[12] >> 4;
        let flags = TcpFlags::new(&buf[12..14]).unwrap();
        let window = byteorder::BigEndian::read_u16(&buf[14..16]);
        let checksum = byteorder::BigEndian::read_u16(&buf[16..18]);
        let urgent_ptr = if flags.urg {
            Some(byteorder::BigEndian::read_u16(&buf[18..20]))
        } else {
            None
        };

        if data_offset as usize * 4 > buf.len() {
            return None;
        }

        let options = if data_offset > 5 {
            Some(&buf[20..data_offset as usize * 4])
        } else {
            None
        };
        let payload = &buf[data_offset as usize * 4..];

        Some(TcpSegment {
            src: src,
            dst: dst,
            seq: seq,
            ack: ack,
            data_offset: data_offset,
            flags: flags,
            window: window,
            checksum: checksum,
            urgent_ptr: urgent_ptr,
            options: options,
            payload: payload,
            raw: buf,
        })
    }
}
