#![recursion_limit = "1024"]
extern crate pcap;
#[macro_use]
extern crate error_chain;
extern crate libc;

pub mod ethernet;
pub mod capture_ext;
pub mod amazon_macs;

use pcap::{Capture, Device};
use std::io::{self};
use std::io::Write;
use errors::*;
use capture_ext::*;
use amazon_macs::*;

mod errors {
    error_chain! {
        foreign_links {
            Pcap(::pcap::Error);
            Io(::std::io::Error);
            ParseError(::std::num::ParseIntError);
        }
    }
}

fn main() {
    if let Err(ref e) = run() {
        println!("error: {}", e);
        for e in e.iter().skip(1) {
            println!("caused by: {}", e);
        }
        if let Some(backtrace) = e.backtrace() {
            println!("backtrace: {:?}", backtrace);
        }
        std::process::exit(1);
    }
}

pub const FILTER_ARP: &str = "arp";
pub const FILTER_UDP: &str = "udp and ( port 67 or port 68 )";
pub const FILTER_ALL: &str = "arp or ( udp and ( port 67 or port 68 ) )";

fn run() -> Result<()> {
    let devices = Device::list()?;
    println!("Found devices:");
    for (i, device) in devices.iter().enumerate() {
        println!("{}) {}\t{}", i + 1, device.name,
                 device.desc.as_ref().map(|x| x.as_str()).unwrap_or("<no description>"));
    }
    print!("\nDevice to use [1]: ");
    io::stdout().flush()?;
    let mut choice = String::new();
    io::stdin().read_line(&mut choice)?;
    let choice = choice.trim();
    let choice: usize = if choice.is_empty() {
        1
    } else {
        choice.parse()?
    } - 1;

    let device = devices.into_iter().nth(choice).ok_or("index out of bounds")?;

    let cap = Capture::from_device(device)?.promisc(true).snaplen(500);
    let mut cap = cap.open_immediate()?;
    cap.filter(FILTER_ALL)?;

    while let Ok(packet) = cap.next() {
        let frame = ethernet::Frame(packet.data);
        if AMAZON_MACS.iter().any(|x: &[u8; 3]| &*x == &frame.source()[..x.len()]) {
            println!("Amazon dash button with mac {:?} pressed", frame.source());
            io::stdout().flush()?;
        }
    }

    Ok(())
}


