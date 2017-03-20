extern crate libc;
extern crate pcap;

use errors::*;
use pcap::Capture;
use std;

pub trait CaptureExt {
    fn open_immediate(self) -> Result<Capture<pcap::Active>>;
}

impl CaptureExt for Capture<pcap::Inactive> {
    #[cfg(windows)]
    fn open_immediate(self) -> Result<Capture<pcap::Active>> {
        let mut cap = self.open()?;
        set_immediate(&mut cap)?;
        Ok(cap)
    }

    #[cfg(not(windows))]
    fn open_immediate(mut self) -> Result<Capture<pcap::Active>> {
        set_immediate(&mut self)?;
        Ok(self.open()?)
    }
}

#[cfg(windows)]
fn set_immediate<T: pcap::State>(capture: &mut Capture<T>) -> Result<()> {
    unsafe {
        assert!(std::mem::size_of::<Capture<pcap::Inactive>>() == std::mem::size_of::<*mut libc::c_void>());
        let ptr_ptr: *mut *mut libc::c_void = std::mem::transmute(capture);
        if pcap_setmintocopy(*ptr_ptr, 500) != 0 {
            Err("error while setting immediate")?
        }
        Ok(())
    }
}

#[cfg(not(windows))]
fn set_immediate<T: pcap::State>(capture: &mut Capture<T>) -> Result<()> {
    unsafe {
        assert!(std::mem::size_of::<Capture<pcap::Inactive>>() == std::mem::size_of::<*mut libc::c_void>());
        let ptr_ptr: *mut *mut libc::c_void = std::mem::transmute(capture);
        if pcap_set_immediate_mode(*ptr_ptr, 1) != 0 {
            Err("error while setting immediate")?
        }
        Ok(())
    }
}

extern "C" {
    #[cfg(windows)]
    fn pcap_setmintocopy(pcap: *mut libc::c_void, size: libc::c_int) -> libc::c_int;

    #[cfg(not(windows))]
    fn pcap_set_immediate_mode(pcap: *mut libc::c_void, value: libc::c_int) -> libc::c_int;
}
