extern crate byteorder;

const MAGIC_NUMBER: u32 = 0xa1b2c3d4;
const REVERSED_MAGIC_NUMBER: u32 = 0xd4c3b2a1;

use std::io;
use std::iter;
use std::mem;

use utils::*;
use self::byteorder::{ReadBytesExt, ByteOrder};

#[derive(Debug)]
enum LinkType {
    Null,
    Ethernet,
    Ax25,
    Ieee8025,
    ArcnetBsd,
    Slip,
    Ppp,
    Fddi,
    PppHdlc,
    PppEther,
    AtmRfc1483,
    Raw,
    CHdlc,
    Ieee80211,
    Frelay,
    Loop,
    LinuxSll,
    Ltalk,
    Pflog,
    Ieee80211Prism,
    IpOverFc,
    Sunatm,
    Ieee80211Radiotap,
    ArcnetLinux,
    AppleIpOverIeee1394,
    Mtp2WithPhdr,
    Mtp2,
    Mtp3,
    Sccp,
    Docsis,
    LinuxIrda,
    User0LinktypeUser15,
    Ieee80211Avs,
    BacnetMsTp,
    PppPppd,
    GprsLlc,
    LinuxLapd,
    BluetoothHciH4,
    UsbLinux,
    Ppi,
    Ieee802154,
    Sita,
    Erf,
    BluetoothHciH4WithPhdr,
    Ax25Kiss,
    Lapd,
    PppWithDir,
    CHdlcWithDir,
    FrelayWithDir,
    IpmbLinux,
    Ieee802154NonaskPhy,
    UsbLinuxMmapped,
    Fc2,
    Fc2WithFrameDelims,
    Ipnet,
    CanSocketcan,
    Ipv4,
    Ipv6,
    Ieee802154Nofcs,
    Dbus,
    DvbCi,
    Mux27010,
    Stanag5066DPdu,
    Nflog,
    Netanalyzer,
    NetanalyzerTransparent,
    Ipoib,
    Mpeg2Ts,
    Ng40,
    NfcLlcp,
    Infiniband,
    Sctp,
    Usbpcap,
    RtacSerial,
    BluetoothLeLl,
    Netlink,
    BluetoothLinuxMonitor,
    BluetoothBredrBb,
    BluetoothLeLlWithPhdr,
    ProfibusDl,
    Pktap,
    Epon,
    IpmiHpm2,
    ZwaveR1R2,
    ZwaveR3,
    WattstopperDlm,
}

impl LinkType {
    fn from_u32(value: u32) -> Option<LinkType> {

        match value {
            0 => Some(LinkType::Null),
            1 => Some(LinkType::Ethernet),
            3 => Some(LinkType::Ax25),
            6 => Some(LinkType::Ieee8025),
            7 => Some(LinkType::ArcnetBsd),
            8 => Some(LinkType::Slip),
            9 => Some(LinkType::Ppp),
            10 => Some(LinkType::Fddi),
            50 => Some(LinkType::PppHdlc),
            51 => Some(LinkType::PppEther),
            100 => Some(LinkType::AtmRfc1483),
            101 => Some(LinkType::Raw),
            104 => Some(LinkType::CHdlc),
            105 => Some(LinkType::Ieee80211),
            107 => Some(LinkType::Frelay),
            108 => Some(LinkType::Loop),
            113 => Some(LinkType::LinuxSll),
            114 => Some(LinkType::Ltalk),
            117 => Some(LinkType::Pflog),
            119 => Some(LinkType::Ieee80211Prism),
            122 => Some(LinkType::IpOverFc),
            123 => Some(LinkType::Sunatm),
            127 => Some(LinkType::Ieee80211Radiotap),
            129 => Some(LinkType::ArcnetLinux),
            138 => Some(LinkType::AppleIpOverIeee1394),
            139 => Some(LinkType::Mtp2WithPhdr),
            140 => Some(LinkType::Mtp2),
            141 => Some(LinkType::Mtp3),
            142 => Some(LinkType::Sccp),
            143 => Some(LinkType::Docsis),
            144 => Some(LinkType::LinuxIrda),
            147...162 => Some(LinkType::User0LinktypeUser15),
            163 => Some(LinkType::Ieee80211Avs),
            165 => Some(LinkType::BacnetMsTp),
            166 => Some(LinkType::PppPppd),
            169 => Some(LinkType::GprsLlc),
            177 => Some(LinkType::LinuxLapd),
            187 => Some(LinkType::BluetoothHciH4),
            189 => Some(LinkType::UsbLinux),
            192 => Some(LinkType::Ppi),
            195 => Some(LinkType::Ieee802154),
            196 => Some(LinkType::Sita),
            197 => Some(LinkType::Erf),
            201 => Some(LinkType::BluetoothHciH4WithPhdr),
            202 => Some(LinkType::Ax25Kiss),
            203 => Some(LinkType::Lapd),
            204 => Some(LinkType::PppWithDir),
            205 => Some(LinkType::CHdlcWithDir),
            206 => Some(LinkType::FrelayWithDir),
            209 => Some(LinkType::IpmbLinux),
            215 => Some(LinkType::Ieee802154NonaskPhy),
            220 => Some(LinkType::UsbLinuxMmapped),
            224 => Some(LinkType::Fc2),
            225 => Some(LinkType::Fc2WithFrameDelims),
            226 => Some(LinkType::Ipnet),
            227 => Some(LinkType::CanSocketcan),
            228 => Some(LinkType::Ipv4),
            229 => Some(LinkType::Ipv6),
            230 => Some(LinkType::Ieee802154Nofcs),
            231 => Some(LinkType::Dbus),
            235 => Some(LinkType::DvbCi),
            236 => Some(LinkType::Mux27010),
            237 => Some(LinkType::Stanag5066DPdu),
            239 => Some(LinkType::Nflog),
            240 => Some(LinkType::Netanalyzer),
            241 => Some(LinkType::NetanalyzerTransparent),
            242 => Some(LinkType::Ipoib),
            243 => Some(LinkType::Mpeg2Ts),
            244 => Some(LinkType::Ng40),
            245 => Some(LinkType::NfcLlcp),
            247 => Some(LinkType::Infiniband),
            248 => Some(LinkType::Sctp),
            249 => Some(LinkType::Usbpcap),
            250 => Some(LinkType::RtacSerial),
            251 => Some(LinkType::BluetoothLeLl),
            253 => Some(LinkType::Netlink),
            254 => Some(LinkType::BluetoothLinuxMonitor),
            255 => Some(LinkType::BluetoothBredrBb),
            256 => Some(LinkType::BluetoothLeLlWithPhdr),
            257 => Some(LinkType::ProfibusDl),
            258 => Some(LinkType::Pktap),
            259 => Some(LinkType::Epon),
            260 => Some(LinkType::IpmiHpm2),
            261 => Some(LinkType::ZwaveR1R2),
            262 => Some(LinkType::ZwaveR3),
            263 => Some(LinkType::WattstopperDlm),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct PcapHeader {
    magic_number: u32,
    version_major: u16,
    version_minor: u16,
    thiszone: i32,
    sigfigs: u32,
    snaplen: u32,
    network: LinkType,
}

#[derive(Debug)]
pub struct PacketHeader {
    ts_sec: u32,
    ts_usec: u32,
    incl_len: u32,
    orig_len: u32,
}

#[derive(Debug)]
pub struct Packet {
    pub header: PacketHeader,
    pub data: Vec<u8>
}

pub struct PcapParser<R: io::Read> {
    reader: R,
    conv: Box<NumConversion>,
    pub header: PcapHeader,
}

#[derive(Debug)]
pub enum ParserError {
    InvalidMagicNumber,
    UnknownLinkType,
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
            MAGIC_NUMBER => {
                get_native_endianess()
            },
            REVERSED_MAGIC_NUMBER => {
                get_inverse_endianess()
            },
            _ => {
                return Err(ParserError::InvalidMagicNumber);
            }
        };

        let conv = get_conv_for_endianess(byteorder);

        let network = match LinkType::from_u32(conv.to_u32(&header_bytes[20..24])) {
            Some(linktype) => linktype,
            None => return Err(ParserError::UnknownLinkType),
        };

        let header = PcapHeader {
            magic_number: MAGIC_NUMBER,
            version_major: conv.to_u16(&header_bytes[4..6]),
            version_minor: conv.to_u16(&header_bytes[6..8]),
            thiszone: conv.to_i32(&header_bytes[8..12]),
            sigfigs: conv.to_u32(&header_bytes[12..16]),
            snaplen: conv.to_u32(&header_bytes[16..20]),
            network: network,
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
