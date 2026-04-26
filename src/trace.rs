use crate::byte_order::ByteOrder;
use crate::clock::Clock;
use crate::metadata::*;
use crate::stream::StreamWriter;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

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

impl TraceWriter {
    pub fn create(dir: &Path, config: TraceConfig) -> io::Result<Self> {
        fs::create_dir_all(dir)?;

        let uuid_val = uuid::Uuid::new_v4();
        let uuid_bytes: [u8; 16] = *uuid_val.as_bytes();

        let trace = Self {
            dir: dir.to_path_buf(),
            config,
            uuid: uuid_bytes,
            next_stream_id: 0,
        };

        trace.write_metadata()?;
        Ok(trace)
    }

    fn byte_order_str(&self) -> &'static str {
        match self.config.byte_order {
            ByteOrder::LittleEndian => "little-endian",
            ByteOrder::BigEndian => "big-endian",
        }
    }

    fn write_metadata(&self) -> io::Result<()> {
        let mut fragments: Vec<Fragment> = Vec::new();

        // Preamble
        fragments.push(Fragment::Preamble(Preamble {
            version: 2,
            uuid: Some(self.uuid.to_vec()),
        }));

        // Clock classes
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

        let bo = self.byte_order_str();

        // Trace class with packet header
        fragments.push(Fragment::TraceClass(TraceClass {
            namespace: None,
            name: None,
            uid: None,
            packet_header_field_class: Some(FieldClass::Structure {
                member_classes: Some(vec![
                    MemberClass {
                        name: "magic".to_string(),
                        field_class: FieldClass::FixedLengthUnsignedInteger {
                            length: 32,
                            byte_order: bo.to_string(),
                            alignment: None,
                            preferred_display_base: Some(16),
                            roles: Some(vec!["packet-magic-number".to_string()]),
                            mappings: None,
                        },
                    },
                    MemberClass {
                        name: "uuid".to_string(),
                        field_class: FieldClass::StaticLengthBlob {
                            length: 16,
                            media_type: None,
                            roles: Some(vec!["metadata-stream-uuid".to_string()]),
                        },
                    },
                    MemberClass {
                        name: "stream_class_id".to_string(),
                        field_class: FieldClass::FixedLengthUnsignedInteger {
                            length: 64,
                            byte_order: bo.to_string(),
                            alignment: None,
                            preferred_display_base: None,
                            roles: Some(vec!["data-stream-class-id".to_string()]),
                            mappings: None,
                        },
                    },
                    MemberClass {
                        name: "stream_id".to_string(),
                        field_class: FieldClass::FixedLengthUnsignedInteger {
                            length: 64,
                            byte_order: bo.to_string(),
                            alignment: None,
                            preferred_display_base: None,
                            roles: Some(vec!["data-stream-id".to_string()]),
                            mappings: None,
                        },
                    },
                ]),
                minimum_alignment: None,
            }),
            attributes: None,
        }));

        // Data stream classes and event record classes
        for sc in &self.config.stream_classes {
            fragments.push(Fragment::DataStreamClass(DataStreamClass {
                id: sc.id,
                namespace: None,
                name: sc.name.clone(),
                default_clock_class_id: sc.clock_name.clone(),
                packet_context_field_class: Some(FieldClass::Structure {
                    member_classes: Some(vec![
                        MemberClass {
                            name: "packet_total_length".to_string(),
                            field_class: FieldClass::FixedLengthUnsignedInteger {
                                length: 64,
                                byte_order: bo.to_string(),
                                alignment: None,
                                preferred_display_base: None,
                                roles: Some(vec!["packet-total-length".to_string()]),
                                mappings: None,
                            },
                        },
                        MemberClass {
                            name: "packet_content_length".to_string(),
                            field_class: FieldClass::FixedLengthUnsignedInteger {
                                length: 64,
                                byte_order: bo.to_string(),
                                alignment: None,
                                preferred_display_base: None,
                                roles: Some(vec!["packet-content-length".to_string()]),
                                mappings: None,
                            },
                        },
                        MemberClass {
                            name: "timestamp_begin".to_string(),
                            field_class: FieldClass::FixedLengthUnsignedInteger {
                                length: 64,
                                byte_order: bo.to_string(),
                                alignment: None,
                                preferred_display_base: None,
                                roles: Some(vec!["default-clock-timestamp".to_string()]),
                                mappings: None,
                            },
                        },
                        MemberClass {
                            name: "timestamp_end".to_string(),
                            field_class: FieldClass::FixedLengthUnsignedInteger {
                                length: 64,
                                byte_order: bo.to_string(),
                                alignment: None,
                                preferred_display_base: None,
                                roles: Some(vec!["packet-end-default-clock-timestamp".to_string()]),
                                mappings: None,
                            },
                        },
                        MemberClass {
                            name: "events_discarded".to_string(),
                            field_class: FieldClass::FixedLengthUnsignedInteger {
                                length: 64,
                                byte_order: bo.to_string(),
                                alignment: None,
                                preferred_display_base: None,
                                roles: Some(vec![
                                    "discarded-event-record-counter-snapshot".to_string(),
                                ]),
                                mappings: None,
                            },
                        },
                        MemberClass {
                            name: "packet_seq_num".to_string(),
                            field_class: FieldClass::FixedLengthUnsignedInteger {
                                length: 64,
                                byte_order: bo.to_string(),
                                alignment: None,
                                preferred_display_base: None,
                                roles: Some(vec!["packet-sequence-number".to_string()]),
                                mappings: None,
                            },
                        },
                    ]),
                    minimum_alignment: None,
                }),
                event_record_header_field_class: Some(FieldClass::Structure {
                    member_classes: Some(vec![
                        MemberClass {
                            name: "event_id".to_string(),
                            field_class: FieldClass::FixedLengthUnsignedInteger {
                                length: 64,
                                byte_order: bo.to_string(),
                                alignment: None,
                                preferred_display_base: None,
                                roles: Some(vec!["event-record-class-id".to_string()]),
                                mappings: None,
                            },
                        },
                        MemberClass {
                            name: "timestamp".to_string(),
                            field_class: FieldClass::FixedLengthUnsignedInteger {
                                length: 64,
                                byte_order: bo.to_string(),
                                alignment: None,
                                preferred_display_base: None,
                                roles: Some(vec!["default-clock-timestamp".to_string()]),
                                mappings: None,
                            },
                        },
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
            path,
            stream_class_id,
            stream_id,
            self.config.byte_order,
            self.uuid,
            self.config.packet_size_bytes,
        )
    }
}
