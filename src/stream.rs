use crate::byte_order::ByteOrder;
use crate::packet::PacketWriter;
use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;

pub struct StreamWriter {
    file: File,
    path: PathBuf,
    stream_class_id: u64,
    stream_id: u64,
    byte_order: ByteOrder,
    trace_uuid: [u8; 16],
    packet_size_bytes: usize,
    packet: Option<PacketWriter>,
    sequence_number: u64,
    last_timestamp: u64,
}

impl StreamWriter {
    pub fn new(
        path: PathBuf,
        stream_class_id: u64,
        stream_id: u64,
        byte_order: ByteOrder,
        trace_uuid: [u8; 16],
        packet_size_bytes: usize,
    ) -> io::Result<Self> {
        let file = File::create(&path)?;
        Ok(Self {
            file,
            path,
            stream_class_id,
            stream_id,
            byte_order,
            trace_uuid,
            packet_size_bytes,
            packet: None,
            sequence_number: 0,
            last_timestamp: 0,
        })
    }

    fn ensure_packet(&mut self) {
        if self.packet.is_none() {
            self.packet = Some(PacketWriter::new(
                self.packet_size_bytes,
                self.byte_order,
                &self.trace_uuid,
                self.stream_class_id,
                self.stream_id,
                self.sequence_number,
                self.last_timestamp,
            ));
        }
    }

    pub fn write_event(
        &mut self,
        event_class_id: u64,
        timestamp: u64,
        write_payload: impl Fn(&mut crate::encoder::BitEncoder),
    ) -> io::Result<()> {
        self.ensure_packet();

        // Try writing the event with checkpoint/rollback
        {
            let packet = self.packet.as_mut().unwrap();
            let size_limit = packet.packet_size_bits();
            let enc = packet.encoder_mut();
            let cp = enc.checkpoint();

            enc.write_unsigned(event_class_id, 64);
            enc.write_unsigned(timestamp, 64);
            write_payload(enc);

            if enc.bit_pos() <= size_limit {
                packet.record_event();
                self.last_timestamp = timestamp;
                return Ok(());
            }

            // Overflowed — roll back
            enc.rollback(cp);
        }

        // Flush current packet and retry in a fresh one
        self.flush_packet()?;
        self.ensure_packet();

        let packet = self.packet.as_mut().unwrap();
        let enc = packet.encoder_mut();
        enc.write_unsigned(event_class_id, 64);
        enc.write_unsigned(timestamp, 64);
        write_payload(enc);

        packet.record_event();
        self.last_timestamp = timestamp;

        Ok(())
    }

    fn flush_packet(&mut self) -> io::Result<()> {
        if let Some(packet) = self.packet.take() {
            let data = packet.finalize(self.last_timestamp);
            self.file.write_all(&data)?;
            self.sequence_number += 1;
        }
        Ok(())
    }

    pub fn close(mut self) -> io::Result<()> {
        self.flush_packet()?;
        self.file.flush()
    }
}

impl Drop for StreamWriter {
    fn drop(&mut self) {
        if self.packet.is_some() {
            let _ = self.flush_packet();
            let _ = self.file.flush();
        }
    }
}
