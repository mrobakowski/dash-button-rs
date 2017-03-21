extern crate csv;

use std::fs::File;
use std::io::prelude::*;

fn main() {
    // file macs.csv was downloaded from https://standards.ieee.org/develop/regauth/oui/oui.csv
    // on March 19th 2017
    // it might need to be updated
    let macs = include_bytes!("./macs.csv");
    let mut amazon_macs = vec![];
    let mut reader = csv::Reader::from_bytes(&macs[..]).has_headers(true);

    for row in reader.decode() {
        let (_, mac, company, _): (String, String, String, String) = row.unwrap();
        // as of time of writing, Amazon has only registered Large MAC Address Blocks
        // Large MAC Address Blocks are characterized by three prefix octets
        if company.contains("Amazon Technologies") {
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