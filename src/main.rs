use std::env;

mod pcap_file;
use pcap_file::process_pcap;

mod deframe;

fn main() {
    let args: Vec<String> = env::args().collect();

    let cmd = &args[0];
    if args.len() < 2 {
        println!("Expecting input pcap file");
        println!("Usage: {} <input> <output>", cmd);
        return;
    }

    if args.len() < 3 {
        println!("Expecting output pcap file");
        println!("Usage: {} <input> <output>", cmd);
        return;
    }

    let input = &args[1];
    let output = &args[2];

    println!("Input: {}", input);
    println!("Output: {}", output);
    process_pcap(input, output);
}
