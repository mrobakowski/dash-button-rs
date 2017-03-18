extern crate csv;

use std::fs::File;
use std::io::prelude::*;

fn main() {
    let macs = include_bytes!("./macs.csv");
    let mut amazon_macs = vec![];
    let mut reader = csv::Reader::from_bytes(&macs[..]).has_headers(true);

    for row in reader.decode() {
        let (_, mac, company, _): (String, String, String, String) = row.unwrap();
        if company.contains("Amazon") {
            amazon_macs.push(vec![
                u8::from_str_radix(&mac[..2], 16).unwrap(),
                u8::from_str_radix(&mac[2..4], 16).unwrap(),
                u8::from_str_radix(&mac[4..6], 16).unwrap(),
            ]);
        }
    }

    let path = format!("{}/amazon_macs_generated.rs", std::env::var("OUT_DIR").unwrap());
    let mut out_file = File::create(path).unwrap();
    write!(&mut out_file, "pub const AMAZON_MACS: [[u8; 3]; {}] = {:?};",
           amazon_macs.len(), amazon_macs).unwrap();
    out_file.flush().unwrap();
}