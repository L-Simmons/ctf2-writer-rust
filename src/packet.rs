use crate::byte_order::ByteOrder;
use crate::encoder::BitEncoder;

const PACKET_MAGIC: u32 = 0xC1FC1FC1;

pub struct PacketWriter {
    encoder: BitEncoder,
    packet_size_bits: usize,
    // Bit positions we need to patch on finalize
    content_length_pos: usize,
    end_timestamp_pos: usize,
    begin_timestamp: u64,
    event_count: u64,
    stream_class_id: u64,
    stream_id: u64,
    sequence_number: u64,
    byte_order: ByteOrder,
}

impl PacketWriter {
    pub fn new(
        packet_size_bytes: usize,
        byte_order: ByteOrder,
        trace_uuid: &[u8; 16],
        stream_class_id: u64,
        stream_id: u64,
        sequence_number: u64,
        begin_timestamp: u64,
    ) -> Self {
        let packet_size_bits = packet_size_bytes * 8;
        let mut encoder = BitEncoder::new(packet_size_bytes, byte_order);

        // -- Packet header --
        // magic (32-bit, role: packet-magic-number)
        encoder.write_unsigned(PACKET_MAGIC as u64, 32);
        // trace UUID (128-bit BLOB, role: metadata-stream-uuid)
        encoder.write_bytes(trace_uuid);
        // stream class ID (role: data-stream-class-id)
        encoder.write_unsigned(stream_class_id, 64);
        // stream ID (role: data-stream-id)
        encoder.write_unsigned(stream_id, 64);

        // -- Packet context --
        // packet-total-length (bits)
        encoder.write_unsigned(packet_size_bits as u64, 64);
        // packet-content-length placeholder (we patch this on finalize)
        let content_length_pos = encoder.bit_pos();
        encoder.write_unsigned(0, 64);
        // packet-beginning-timestamp
        encoder.write_unsigned(begin_timestamp, 64);
        // packet-end-timestamp placeholder
        let end_timestamp_pos = encoder.bit_pos();
        encoder.write_unsigned(0, 64);
        // discarded-event-record-counter-snapshot
        encoder.write_unsigned(0, 64);
        // packet-sequence-number
        encoder.write_unsigned(sequence_number, 64);

        Self {
            encoder,
            packet_size_bits,
            content_length_pos,
            end_timestamp_pos,
            begin_timestamp,
            event_count: 0,
            stream_class_id,
            stream_id,
            sequence_number,
            byte_order,
        }
    }

    pub fn remaining_bits(&self) -> usize {
        self.packet_size_bits.saturating_sub(self.encoder.bit_pos())
    }

    pub fn packet_size_bits(&self) -> usize {
        self.packet_size_bits
    }

    pub fn bit_pos(&self) -> usize {
        self.encoder.bit_pos()
    }

    pub fn encoder_mut(&mut self) -> &mut BitEncoder {
        &mut self.encoder
    }

    pub fn record_event(&mut self) {
        self.event_count += 1;
    }

    pub fn finalize(mut self, end_timestamp: u64) -> Vec<u8> {
        let content_length_bits = self.encoder.bit_pos() as u64;

        // Patch content-length
        self.encoder.set_bit_pos(self.content_length_pos);
        self.encoder.write_unsigned(content_length_bits, 64);

        // Patch end-timestamp
        self.encoder.set_bit_pos(self.end_timestamp_pos);
        self.encoder.write_unsigned(end_timestamp, 64);

        // Restore position and pad to packet size
        self.encoder.set_bit_pos(self.packet_size_bits);
        self.encoder.into_bytes()
    }
}
