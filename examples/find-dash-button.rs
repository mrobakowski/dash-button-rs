extern crate dash_button_rs;
extern crate chrono;

use dash_button_rs::*;
use std::io::{self, Write};
use errors::*;

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
    let device = choose_device()?;

    println!("\n🔍 Searching for Amazon Dash Button...");
    let mac = AmazonDashButton::discover_on(device.name.as_str())?; // for some reason Device isn't Clone, but this works
    println!("Discovered Amazon Dash Button with mac {}\n\n👂 Listening for presses...", mac);

    use chrono::prelude::*;
    for DashButtonEvent { time, .. } in AmazonDashButton::from_mac(mac)?.listen_on(device).events()? {
        let time = Local.timestamp(time.as_secs() as i64, time.subsec_nanos());
        println!("🔘 button pressed at {}", time);
    }

    Ok(())
}

fn choose_device() -> Result<Device> {
    let devices = Device::list()?;

    println!("Found devices:");
    for (i, device) in devices.iter().enumerate() {
        println!("{}) {}\t{}", i + 1, device.name,
                 device.desc.as_ref().map(|x| x.as_str()).unwrap_or("<no description>"));
    }

    print!("Device to use [1]: ");
    io::stdout().flush()?;

    let mut choice = String::new();
    io::stdin().read_line(&mut choice)?;

    let choice = choice.trim();
    let choice: usize = if choice.is_empty() { 1 } else { choice.parse()? };
    let choice = choice - 1;

    Ok(devices.into_iter().nth(choice).ok_or("index out of bounds")?)
}

