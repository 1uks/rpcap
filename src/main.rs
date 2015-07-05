use std::fs::File;

mod pcap;
mod utils;

use pcap::*;

fn main() {
    use std::env;

    for filename in env::args().skip(1) {
        println!("{}", filename);
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
        for packet in parser {
            println!("{:?}", packet);
        }
    }
}
