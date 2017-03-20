use std::time::Duration;
use pcap::{Device, Capture, State, Active};
use errors::*;
use try_from::*;
use capture_ext::*;
use ethernet::*;
use amazon_macs::*;
use duration_ext::*;

pub const FILTER_ARP: &str = "arp";
pub const FILTER_UDP: &str = "udp and ( port 67 or port 68 )";
pub const FILTER_ALL: &str = "arp or ( udp and ( port 67 or port 68 ) )";

#[derive(Debug, Clone)]
pub struct Mac([u8; 6]);

impl<'a> TryFrom<&'a str> for Mac {
    type Err = Error;
    fn try_from(mac: &'a str) -> Result<Self> {
        let mac = mac.replace(":", "");

        Ok(Mac([
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
        Ok(Mac(mac))
    }
}

impl<'a> TryFrom<&'a [u8]> for Mac {
    type Err = Error;

    fn try_from(mac: &'a [u8]) -> Result<Self> {
        if mac.len() != 6 { Err(format!("Malformed mac, expected 6 bytes, got {}", mac.len()))? }
        let mac: [u8; 6] = [mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]];
        Ok(Mac(mac))
    }
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
        while let Ok(packet) = self.capture.next() {
            let frame = Frame(packet.data);
            let packet_time = Duration::from_timeval(packet.header.ts);

            if packet_time - self.last_time > self.button.debounce &&
                AMAZON_MACS.iter().any(|x: &[u8; 3]| &*x == &frame.source()[..x.len()]) {
                // TODO: filter by exact mac
                self.last_time = packet_time;
                return Some(DashButtonEvent {
                    mac: frame.source().try_into().expect("malformed mac"),
                    time: packet_time
                })
            }
        }
        panic!("Packet capture failed!!!")
    }
}
