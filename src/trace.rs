use crate::byte_order::ByteOrder;
use crate::metadata::*;
use crate::stream::StreamWriter;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct EventClassDef {
    pub id: u64,
    pub name: String,
    pub payload_field_class: Option<FieldClass>,
}

pub struct StreamClassDef {
    pub id: u64,
    pub name: Option<String>,
    pub clock_name: Option<String>,
    pub event_classes: Vec<EventClassDef>,
}

pub struct TraceConfig {
    pub byte_order: ByteOrder,
    pub packet_size_bytes: usize,
    pub clocks: Vec<Clock>,
    pub stream_classes: Vec<StreamClassDef>,
}

use crate::clock::Clock;

impl Default for TraceConfig {
    fn default() -> Self {
        Self {
            byte_order: ByteOrder::LittleEndian,
            packet_size_bytes: 65536,
            clocks: Vec::new(),
            stream_classes: Vec::new(),
        }
    }
}

pub struct TraceWriter {
    dir: PathBuf,
    config: TraceConfig,
    uuid: [u8; 16],
    next_stream_id: u64,
}

/// A version 4 UUID from the wall clock and the process id, with no random source.
pub fn trace_uuid() -> [u8; 16] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    let mut uuid = nanos.to_le_bytes();
    uuid[12..].copy_from_slice(&std::process::id().to_le_bytes());
    uuid[6] = (uuid[6] & 0x0f) | 0x40;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    uuid
}

fn byte_order_str(byte_order: ByteOrder) -> &'static str {
    match byte_order {
        ByteOrder::LittleEndian => "little-endian",
        ByteOrder::BigEndian => "big-endian",
    }
}

fn unsigned(length: u32, byte_order: ByteOrder, role: &str) -> FieldClass {
    FieldClass::FixedLengthUnsignedInteger {
        length,
        byte_order: byte_order_str(byte_order).to_string(),
        alignment: None,
        preferred_display_base: None,
        roles: Some(vec![role.to_string()]),
        mappings: None,
    }
}

fn member(name: &str, field_class: FieldClass) -> MemberClass {
    MemberClass {
        name: name.to_string(),
        field_class,
    }
}

/// The packet header PacketWriter writes: magic, uuid, stream class id, stream id.
pub fn packet_header_field_class(byte_order: ByteOrder) -> FieldClass {
    FieldClass::Structure {
        member_classes: Some(vec![
            member(
                "magic",
                FieldClass::FixedLengthUnsignedInteger {
                    length: 32,
                    byte_order: byte_order_str(byte_order).to_string(),
                    alignment: None,
                    preferred_display_base: Some(16),
                    roles: Some(vec!["packet-magic-number".to_string()]),
                    mappings: None,
                },
            ),
            member(
                "uuid",
                FieldClass::StaticLengthBlob {
                    length: 16,
                    media_type: None,
                    roles: Some(vec!["metadata-stream-uuid".to_string()]),
                },
            ),
            member(
                "stream_class_id",
                unsigned(64, byte_order, "data-stream-class-id"),
            ),
            member("stream_id", unsigned(64, byte_order, "data-stream-id")),
        ]),
        minimum_alignment: None,
    }
}

/// The packet context PacketWriter writes: the two lengths, the two timestamps,
/// the discarded count and the sequence number.
pub fn packet_context_field_class(byte_order: ByteOrder) -> FieldClass {
    FieldClass::Structure {
        member_classes: Some(vec![
            member(
                "packet_total_length",
                unsigned(64, byte_order, "packet-total-length"),
            ),
            member(
                "packet_content_length",
                unsigned(64, byte_order, "packet-content-length"),
            ),
            member(
                "timestamp_begin",
                unsigned(64, byte_order, "default-clock-timestamp"),
            ),
            member(
                "timestamp_end",
                unsigned(64, byte_order, "packet-end-default-clock-timestamp"),
            ),
            member(
                "events_discarded",
                unsigned(64, byte_order, "discarded-event-record-counter-snapshot"),
            ),
            member(
                "packet_seq_num",
                unsigned(64, byte_order, "packet-sequence-number"),
            ),
        ]),
        minimum_alignment: None,
    }
}

impl TraceWriter {
    pub fn create(dir: &Path, config: TraceConfig) -> io::Result<Self> {
        fs::create_dir_all(dir)?;

        let trace = Self {
            dir: dir.to_path_buf(),
            config,
            uuid: trace_uuid(),
            next_stream_id: 0,
        };

        trace.write_metadata()?;
        Ok(trace)
    }

    fn write_metadata(&self) -> io::Result<()> {
        let mut fragments: Vec<Fragment> = Vec::new();

        fragments.push(Fragment::Preamble(Preamble {
            version: 2,
            uuid: Some(self.uuid.to_vec()),
        }));

        for clock in &self.config.clocks {
            fragments.push(Fragment::ClockClass(ClockClass {
                id: clock.name.clone(),
                frequency: clock.frequency,
                offset_from_origin: if clock.offset_seconds != 0 || clock.offset_cycles != 0 {
                    Some(ClockOffset {
                        seconds: Some(clock.offset_seconds),
                        cycles: Some(clock.offset_cycles),
                    })
                } else {
                    None
                },
                origin: Some(ClockOrigin::UnixEpoch("unix-epoch".to_string())),
                precision: None,
                description: None,
                namespace: None,
                name: None,
                uid: None,
            }));
        }

        let bo = self.config.byte_order;

        fragments.push(Fragment::TraceClass(TraceClass {
            namespace: None,
            name: None,
            uid: None,
            packet_header_field_class: Some(packet_header_field_class(bo)),
            attributes: None,
        }));

        for sc in &self.config.stream_classes {
            fragments.push(Fragment::DataStreamClass(DataStreamClass {
                id: sc.id,
                namespace: None,
                name: sc.name.clone(),
                default_clock_class_id: sc.clock_name.clone(),
                packet_context_field_class: Some(packet_context_field_class(bo)),
                event_record_header_field_class: Some(FieldClass::Structure {
                    member_classes: Some(vec![
                        member("event_id", unsigned(64, bo, "event-record-class-id")),
                        member("timestamp", unsigned(64, bo, "default-clock-timestamp")),
                    ]),
                    minimum_alignment: None,
                }),
                event_record_common_context_field_class: None,
            }));

            for ec in &sc.event_classes {
                fragments.push(Fragment::EventRecordClass(EventRecordClass {
                    id: ec.id,
                    data_stream_class_id: sc.id,
                    namespace: None,
                    name: Some(ec.name.clone()),
                    specific_context_field_class: None,
                    payload_field_class: ec.payload_field_class.clone(),
                }));
            }
        }

        let metadata_path = self.dir.join("metadata");
        let mut file = fs::File::create(metadata_path)?;
        write_metadata(&mut file, &fragments)
    }

    pub fn create_stream(&mut self, stream_class_id: u64) -> io::Result<StreamWriter> {
        let stream_id = self.next_stream_id;
        self.next_stream_id += 1;

        let filename = format!("stream_{}", stream_id);
        let path = self.dir.join(filename);

        StreamWriter::new(
            &path,
            stream_class_id,
            stream_id,
            self.config.byte_order,
            self.uuid,
            self.config.packet_size_bytes,
        )
    }
}
