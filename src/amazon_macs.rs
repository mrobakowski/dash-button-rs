// this file contains MAC address prefixes that Amazon registered in IEEE
// the macs are preprocessed by build.rs build script

include!(concat!(env!("OUT_DIR"), "/amazon_macs_generated.rs"));
