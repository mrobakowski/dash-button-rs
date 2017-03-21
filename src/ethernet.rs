use std::ops;
use std::fmt;

pub struct Frame<'a>(pub &'a [u8]);

#[doc(hidden)]
impl<'a> ops::Deref for Frame<'a> {
    type Target = &'a [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> Frame<'a> {
    pub fn destination(&self) -> &[u8] {
        &self[..6]
    }

    pub fn source(&self) -> &[u8] {
        &self[6..12]
    }

    pub fn ethertype(&self) -> EtherType {
        pub fn be_u16(data: &[u8]) -> u16 {
            ((data[0] as u16) << 8) | data[1] as u16
        }

        be_u16(&self[12..]).into()
    }

    pub fn payload(&self) -> &[u8] {
        &self[14..]
    }
}

impl<'a> fmt::Debug for Frame<'a> {
    fn fmt(&self, fmtr: &mut fmt::Formatter) -> fmt::Result {
        fmtr.debug_struct("ethernet::Frame")
            .field("destination", &self.destination())
            .field("source", &self.source())
            .field("ethertype", &self.ethertype())
            .field("payload", &self.payload())
            .finish()
    }
}

#[derive(Debug, PartialEq)]
pub enum EtherType {
    IPv4,
    ARP,
    IPv6,
    Unknown(u16),
}

impl From<u16> for EtherType {
    fn from(value: u16) -> Self {
        use self::EtherType::*;
        match value {
            0x0800 => IPv4,
            0x0806 => ARP,
            0x86DD => IPv6,
            otherwise => Unknown(otherwise),
        }
    }
}
