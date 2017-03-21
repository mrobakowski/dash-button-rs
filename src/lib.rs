#![recursion_limit = "1024"]
extern crate pcap;
#[macro_use]
extern crate error_chain;
extern crate libc;
extern crate try_from;

use std::time::Duration;
pub use pcap::Device;
use pcap::{Capture, Active};
use errors::*;
use try_from::*;
use capture_ext::*;
use ethernet::*;
use amazon_macs::*;
use duration_ext::*;

mod ethernet;
mod capture_ext;
mod amazon_macs;
mod duration_ext;

pub mod errors {
    error_chain! {
        foreign_links {
            Pcap(::pcap::Error);
            Io(::std::io::Error);
            ParseError(::std::num::ParseIntError);
        }
    }
}

pub const FILTER_ARP: &str = "arp";
pub const FILTER_UDP: &str = "udp and ( port 67 or port 68 )";
pub const FILTER_ALL: &str = "arp or ( udp and ( port 67 or port 68 ) )";

#[derive(Debug, Clone)]
pub enum Mac {
    Specific([u8; 6]),
    Any
}

use std::fmt;

impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Mac::*;
        match self {
            &Any => write!(f, "*"),
            &Specific(ref addr) => write!(f, "{:X}:{:X}:{:X}:{:X}:{:X}:{:X}", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5])
        }
    }
}

impl<'a> TryFrom<&'a str> for Mac {
    type Err = Error;
    fn try_from(mac: &'a str) -> Result<Self> {
        let mac = mac.replace(":", "");

        Ok(Mac::Specific([
            u8::from_str_radix(&mac[..2], 16)?,
            u8::from_str_radix(&mac[2..4], 16)?,
            u8::from_str_radix(&mac[4..6], 16)?,
            u8::from_str_radix(&mac[6..8], 16)?,
            u8::from_str_radix(&mac[8..10], 16)?,
            u8::from_str_radix(&mac[10..12], 16)?
        ]))
    }
}

impl TryFrom<[u8; 6]> for Mac {
    type Err = Error;

    fn try_from(mac: [u8; 6]) -> Result<Self> {
        Ok(Mac::Specific(mac))
    }
}

impl<'a> TryFrom<&'a [u8]> for Mac {
    type Err = Error;

    fn try_from(mac: &'a [u8]) -> Result<Self> {
        if mac.len() != 6 { Err(format!("Malformed mac, expected 6 bytes, got {}", mac.len()))? }
        let mac: [u8; 6] = [mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]];
        Ok(Mac::Specific(mac))
    }
}

impl TryFrom<Mac> for Mac {
    type Err = Error;
    fn try_from(mac: Mac) -> Result<Mac> { Ok(mac) }
}

pub struct AmazonDashButton {
    mac: Mac,
    device: Device,
    debounce: Duration
}

pub struct DashButtonEvents<'a> {
    button: &'a AmazonDashButton,
    capture: Capture<Active>,
    last_time: Duration
}

impl AmazonDashButton {
    pub fn from_mac<T: TryInto<Mac>>(mac: T) -> Result<AmazonDashButton>
        where Error: From<<T as TryInto<Mac>>::Err> {
        // that line is bs tbh
        Ok(AmazonDashButton {
            mac: mac.try_into()?,
            device: Device::lookup()?,
            debounce: Duration::from_millis(500),
        })
    }

    pub fn discover() -> Result<Mac> {
        let all_buttons = AmazonDashButton::from_mac(Mac::Any)?;
        for DashButtonEvent { mac, .. } in all_buttons.events()? {
            return Ok(mac)
        }
        return Err("could not find suitable mac address".into())
    }

    pub fn discover_on<T: Into<Device>>(dev: T) -> Result<Mac> {
        let all_buttons = AmazonDashButton::from_mac(Mac::Any)?.listen_on(dev);
        for DashButtonEvent { mac, .. } in all_buttons.events()? {
            return Ok(mac)
        }
        return Err("could not find suitable mac address".into())
    }

    pub fn listen_on<T: Into<Device>>(self, device: T) -> AmazonDashButton {
        AmazonDashButton { device: device.into(), ..self }
    }

    pub fn debounce<T: Into<Duration>>(self, debounce: T) -> AmazonDashButton {
        AmazonDashButton { debounce: debounce.into(), ..self }
    }

    pub fn events(&self) -> Result<DashButtonEvents> {
        Ok(DashButtonEvents {
            button: self,
            capture: {
                let cap = Capture::from_device(self.device.name.as_str())?.promisc(true).snaplen(500);
                let mut cap = cap.open_immediate()?;
                cap.filter(FILTER_ALL)?;
                cap
            },
            last_time: Duration::new(0, 0)
        })
    }
}

pub struct DashButtonEvent {
    pub mac: Mac,
    pub time: Duration
}

impl<'a> Iterator for DashButtonEvents<'a> {
    type Item = DashButtonEvent;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.capture.next() {
                Ok(packet) => {
                    let frame = Frame(packet.data);
                    let packet_time = Duration::from_timeval(packet.header.ts);

                    if packet_time - self.last_time > self.button.debounce &&
                        match self.button.mac {
                            Mac::Any => AMAZON_MACS.iter().any(|x: &[u8; 3]| &*x == &frame.source()[..x.len()]),
                            Mac::Specific(ref mac) => mac == &frame.source()[..mac.len()]
                        } {
                        // TODO: filter by exact mac
                        self.last_time = packet_time;
                        return Some(DashButtonEvent {
                            mac: frame.source().try_into().expect("malformed mac"),
                            time: packet_time
                        })
                    }
                },
                err @ Err(_) => { err.unwrap(); unreachable!() }
            }
        }
    }
}
