#![recursion_limit = "1024"]
extern crate pcap;
#[macro_use]
extern crate error_chain;
extern crate libc;
extern crate try_from;

pub mod ethernet;
pub mod capture_ext;
pub mod amazon_macs;
pub mod duration_ext;
pub mod amazon_dash_button;


use pcap::{Capture, Device};
use std::io::{self};
use std::io::Write;
use std::time::Duration;
use errors::*;
use capture_ext::*;
use amazon_macs::*;
use duration_ext::*;
use amazon_dash_button::*;

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

    use amazon_dash_button::*;

    let button = AmazonDashButton::from_mac("000000000000")?.listen_on(device);

    for DashButtonEvent { mac, time } in button.events()? {
        println!("Dash button with mac {:?} pressed at time {:?}!", mac, time);
    }

    Ok(())
}

