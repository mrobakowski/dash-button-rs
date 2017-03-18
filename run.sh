#!/bin/bash
cargo build && sudo setcap cap_net_raw,cap_net_admin=eip ./target/debug/dash-button-rs && ./target/debug/dash-button-rs
