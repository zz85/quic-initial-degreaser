use pcap::Capture;

use crate::deframe::process_entry;

pub fn process_pcap(input: &str, output: &str) {
    let mut cap = Capture::from_file(input).unwrap();
    let mut output = cap.savefile(output).unwrap();

    let mut buf = [0u8; 3000]; // a jumbo frame ought to be enough
    let mut rewritten = 0;
    let mut total = 0;

    while let Ok(mut packet) = cap.next() {
        let payload = &mut buf[..packet.header.caplen as usize];
        payload.clone_from_slice(packet.data);

        if let Some(_) = process_entry(payload) {
            packet.data = &buf;
            rewritten += 1;
        }
        total += 1;
        output.write(&packet);
    }

    println!("\nInitial QUIC Packets rewritten: {}", rewritten);
    println!("Total entries written: {}", total);
}
