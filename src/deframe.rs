use pnet::packet::{
    ethernet::MutableEthernetPacket, ip::IpNextHeaderProtocols, ipv4::MutableIpv4Packet,
    udp::MutableUdpPacket, MutablePacket, Packet,
};
use quic_initial_degreaser::quic_initial_degreaser::degrease_initial_packet;

pub fn process_entry(slice: &mut [u8]) -> Option<()> {
    let mut ether = MutableEthernetPacket::new(slice).unwrap();

    // care only about IPv4 for now, YOLO, use at your own risk
    let mut ipv4packet = MutableIpv4Packet::new(ether.payload_mut()).unwrap();

    let protocol = ipv4packet.get_next_level_protocol();

    match protocol {
        IpNextHeaderProtocols::Udp => {}
        _ => {
            return None;
        }
    }

    let mut udp = MutableUdpPacket::new(ipv4packet.payload_mut()).unwrap();

    let len = udp.get_length() as usize;
    let payload = udp.payload();
    let diff = len - payload.len();

    if let Some(new_payload) = degrease_initial_packet(payload) {
        udp.set_length((new_payload.len() + diff) as u16);
        udp.set_payload(&new_payload);

        return Some(())
    }

    None
}
