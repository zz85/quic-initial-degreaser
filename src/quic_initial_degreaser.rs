use s2n_codec::{DecoderBufferMut, EncoderBuffer, EncoderValue};
use s2n_quic_core::{
    connection::id::ConnectionInfo,
    crypto::InitialKey,
    frame::{Crypto, Frame, FrameMut},
    inet::SocketAddress,
    packet::{encoding::PacketEncoder, initial::Initial, number::PacketNumber, ProtectedPacket},
};

/// Attempts to parse UDP payloads to match Intial Packets with ClientHello
/// then generate a QUIC packet with a single contiguous Crypto frame
pub fn degrease_initial_packet(udp_slice: &[u8]) -> Option<Vec<u8>> {
    let packet = extract_initial_packet(udp_slice)?;
    generate_initial_packet(packet)
}

/// Minimal details to generate a valid QUIC packet with crypto
pub struct MinimalQuicPacket {
    version: u32,
    packet_number: PacketNumber,
    dcid: Vec<u8>,
    scid: Vec<u8>,
    crypto_bytes: Vec<u8>,
}

/// Extracts crypto and essentials information from initial packet
pub fn extract_initial_packet(udp_slice: &[u8]) -> Option<MinimalQuicPacket> {
    // copy slice so we can mutate to decrypt packet
    let mut data = [0; 1500];
    let decode_buffer = &mut data[..udp_slice.len()];
    decode_buffer.copy_from_slice(udp_slice);

    let payload = DecoderBufferMut::new(decode_buffer);
    let remote_address = SocketAddress::default();
    let connection_info = ConnectionInfo::new(&remote_address);

    let (packet, _remaining) = ProtectedPacket::decode(payload, &connection_info, &0).ok()?;
    let version = packet.version()?;

    let protected_packet = match packet {
        ProtectedPacket::Initial(packet) => packet,
        _ => {
            return None;
        }
    };

    let (initial_key, initial_header_key) = s2n_quic_crypto::initial::InitialKey::new_server(
        protected_packet.destination_connection_id(),
    );
    let intial_encrypted = protected_packet
        .unprotect(&initial_header_key, Default::default())
        .expect("unprotect");

    let clear_initial = intial_encrypted
        .decrypt(&initial_key)
        .map_err(|_err| {
            // just move on if we can't decrypt packet
        })
        .ok()?;

    let packet_number = clear_initial.packet_number;
    let dcid = clear_initial.destination_connection_id().to_vec();
    let scid = clear_initial.source_connection_id().to_vec();

    let mut payload = clear_initial.payload;
    let mut crypto = [0u8; 1 << 16];
    let mut crypto_size = 0;

    // iterate frames from the QUIC packet
    while !payload.is_empty() {
        let (frame, remaining) = payload.decode::<FrameMut>().unwrap();

        if let Frame::Crypto(frame) = frame {
            // we care only about crypto frames
            let slice = frame.data.as_less_safe_slice();
            let offset = frame.offset.as_u64() as usize;
            let to = offset + slice.len();
            crypto[offset..to].copy_from_slice(slice);
            // track sum of crypto payload
            crypto_size = crypto_size.max(to);
        }

        payload = remaining;
    }

    let bytes = &crypto[..crypto_size];

    Some(MinimalQuicPacket {
        version,
        packet_number,
        dcid,
        scid,
        crypto_bytes: bytes.to_vec(),
    })
}

/// Return bytes of generated encrypted Initial Packet
pub fn generate_initial_packet(intial: MinimalQuicPacket) -> Option<Vec<u8>> {
    let MinimalQuicPacket {
        version,
        packet_number,
        dcid,
        scid,
        crypto_bytes,
    } = intial;
    let new_crypto_frame = Crypto {
        offset: Default::default(),
        data: &crypto_bytes[..],
    };

    // create a buffer for frames, then place crypto contents in there
    let mut encoder_bytes = [0u8; 1500];
    let mut payload_buffer = EncoderBuffer::new(&mut encoder_bytes);
    new_crypto_frame.encode(&mut payload_buffer);

    // prepare the packet
    let packet = Initial {
        version,
        destination_connection_id: &dcid[..],
        source_connection_id: &scid[..],
        token: &[][..],
        packet_number,
        payload: payload_buffer.as_mut_slice(),
    };

    // prepare the initial keys
    let (client_key, client_header_key) =
        s2n_quic_crypto::initial::InitialKey::new_client(&dcid[..]);

    let mut output_bytes = [0u8; 1500];

    let len = {
        // scope here to effectively drop
        // buffer and encoder, since we only need the encrypted bytes
        let encoder = EncoderBuffer::new(&mut output_bytes);
        // encrypt and protect packet
        let (protected_packet, _buffer) = packet
            .encode_packet(
                &client_key,
                &client_header_key,
                Default::default(),
                None,
                encoder,
            )
            .map_err(|e| {
                println!("Err {:?}", e);
            })
            .expect("packet protection failed");
        protected_packet.len()
    };

    let new_bytes = &output_bytes[..len];
    Some(new_bytes.to_vec())
}
