use std::fs::File;

mod pcap;
mod utils;
mod packets;

use pcap::*;
use packets::*;


fn handle_frame(frame: EthernetFrame) {
    match frame.ethertype {
        EtherType::IPv4 => {
            if let Some(packet) = Ipv4Packet::new(frame.payload) {
                handle_ipv4(packet);
            }
        },
        _ => {
            println!("EtherType: {:?}", frame.ethertype);
        },
    }
}

fn handle_ipv4(packet: Ipv4Packet) {
    match packet.proto {
        IpProtocol::Tcp => {
            if let Some(segment) = TcpSegment::new(packet.payload) {
                handle_segment(segment);
            }
        }
        _ => { },
    }
}

fn handle_segment(segment: TcpSegment) {
    println!("{:#?}", segment);
}

fn main() {
    use std::env;

    for filename in env::args().skip(1) {
        let file = match File::open(&filename) {
            Ok(f) => f,
            Err(e) => {
                println!("{}", e);
                continue;
            }
        };
        let mut parser = match PcapParser::from_reader(file) {
            Ok(p) => p,
            Err(e) => {
                println!("{:?}", e);
                continue;
            },
        };

        println!("{}", filename);
        println!("{:#?}", parser.header);

        for packet in parser {
            if let Some(frame) = EthernetFrame::new(&packet.data) {
                handle_frame(frame);
            }
        }

    }
}
