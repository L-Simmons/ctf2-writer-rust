use ctf2_writer::*;
use std::path::Path;
use std::process::Command;

const BT2: &str = "/tmp/babeltrace2-install/bin/babeltrace2";

fn babeltrace2_read(trace_dir: &Path) -> (bool, String) {
    let output = Command::new(BT2)
        .arg(trace_dir)
        .output()
        .expect("failed to run babeltrace2");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() {
        eprintln!("babeltrace2 stderr:\n{}", stderr);
    }
    (output.status.success(), stdout)
}

fn babeltrace2_read_verbose(trace_dir: &Path) -> (bool, String, String) {
    let output = Command::new(BT2)
        .arg("--log-level=WARNING")
        .arg(trace_dir)
        .output()
        .expect("failed to run babeltrace2");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (output.status.success(), stdout, stderr)
}

fn clean_dir(dir: &Path) {
    if dir.exists() {
        std::fs::remove_dir_all(dir).unwrap();
    }
}

fn make_uint_fc(length: u32, bo: &str) -> FieldClass {
    FieldClass::FixedLengthUnsignedInteger {
        length,
        byte_order: bo.to_string(),
        alignment: None,
        preferred_display_base: None,
        roles: None,
        mappings: None,
    }
}

fn make_sint_fc(length: u32, bo: &str) -> FieldClass {
    FieldClass::FixedLengthSignedInteger {
        length,
        byte_order: bo.to_string(),
        alignment: None,
        roles: None,
        mappings: None,
    }
}

fn make_float_fc(length: u32, bo: &str) -> FieldClass {
    FieldClass::FixedLengthFloatingPointNumber {
        length,
        byte_order: bo.to_string(),
        alignment: None,
    }
}

fn make_bool_fc(bo: &str) -> FieldClass {
    FieldClass::FixedLengthBoolean {
        length: 8,
        byte_order: bo.to_string(),
        alignment: None,
    }
}

// ---------- Test 1: Basic happy path (existing test) ----------

#[test]
fn write_simple_trace() {
    let dir = Path::new("/tmp/ctf2-test-trace");
    clean_dir(dir);

    let clock = Clock::new("monotonic", 1_000_000_000).with_unix_epoch_offset();

    let config = TraceConfig {
        byte_order: ByteOrder::LittleEndian,
        packet_size_bytes: 4096,
        clocks: vec![clock],
        stream_classes: vec![StreamClassDef {
            id: 0,
            name: Some("default".to_string()),
            clock_name: Some("monotonic".to_string()),
            event_classes: vec![
                EventClassDef {
                    id: 0,
                    name: "simple_event".to_string(),
                    payload_field_class: Some(FieldClass::Structure {
                        member_classes: Some(vec![metadata::MemberClass {
                            name: "value".to_string(),
                            field_class: make_uint_fc(32, "little-endian"),
                        }]),
                        minimum_alignment: None,
                    }),
                },
                EventClassDef {
                    id: 1,
                    name: "string_event".to_string(),
                    payload_field_class: Some(FieldClass::Structure {
                        member_classes: Some(vec![metadata::MemberClass {
                            name: "message".to_string(),
                            field_class: FieldClass::NullTerminatedString { encoding: None },
                        }]),
                        minimum_alignment: None,
                    }),
                },
            ],
        }],
    };

    let mut trace = TraceWriter::create(dir, config).unwrap();
    let mut stream = trace.create_stream(0).unwrap();

    for i in 0..10 {
        let timestamp = i * 1_000_000;
        stream
            .write_event(0, timestamp, |enc| {
                enc.write_unsigned(i * 42, 32);
            })
            .unwrap();
    }

    stream
        .write_event(1, 10_000_000, |enc| {
            enc.write_null_terminated_string("hello CTF2 from Rust");
        })
        .unwrap();

    stream.close().unwrap();

    let (ok, stdout) = babeltrace2_read(dir);
    assert!(ok, "babeltrace2 failed to read trace");
    assert_eq!(stdout.lines().count(), 11, "expected 11 events");
    assert!(stdout.contains("simple_event"));
    assert!(stdout.contains("string_event"));
    assert!(stdout.contains("hello CTF2 from Rust"));
}

// ---------- Test 2: Packet overflow ----------

#[test]
fn packet_overflow_multiple_packets() {
    let dir = Path::new("/tmp/ctf2-test-overflow");
    clean_dir(dir);

    let clock = Clock::new("monotonic", 1_000_000_000).with_unix_epoch_offset();

    // Packet header = 36 bytes, context = 48 bytes, overhead = 84 bytes
    // Each event = 16 (header) + 4 (u32 payload) = 20 bytes
    // With 256-byte packets: (256 - 84) / 20 = 8.6, so 8 events per packet
    // Writing 50 events should produce ~7 packets
    let config = TraceConfig {
        byte_order: ByteOrder::LittleEndian,
        packet_size_bytes: 256,
        clocks: vec![clock],
        stream_classes: vec![StreamClassDef {
            id: 0,
            name: Some("default".to_string()),
            clock_name: Some("monotonic".to_string()),
            event_classes: vec![EventClassDef {
                id: 0,
                name: "counter".to_string(),
                payload_field_class: Some(FieldClass::Structure {
                    member_classes: Some(vec![metadata::MemberClass {
                        name: "value".to_string(),
                        field_class: make_uint_fc(32, "little-endian"),
                    }]),
                    minimum_alignment: None,
                }),
            }],
        }],
    };

    let mut trace = TraceWriter::create(dir, config).unwrap();
    let mut stream = trace.create_stream(0).unwrap();

    let num_events = 50u64;
    for i in 0..num_events {
        stream
            .write_event(0, i * 1_000_000, |enc| {
                enc.write_unsigned(i, 32);
            })
            .unwrap();
    }
    stream.close().unwrap();

    // Verify file is larger than one packet
    let file_size = std::fs::metadata(dir.join("stream_0")).unwrap().len();
    assert!(
        file_size > 256,
        "stream file should span multiple packets, got {} bytes",
        file_size
    );
    assert_eq!(
        file_size % 256,
        0,
        "stream file size should be a multiple of packet size"
    );

    let (ok, stdout) = babeltrace2_read(dir);
    assert!(ok, "babeltrace2 failed to read multi-packet trace");
    let event_count = stdout.lines().count();
    assert_eq!(
        event_count, num_events as usize,
        "expected {} events, got {}",
        num_events, event_count
    );

    // Verify first and last event values
    let first_line = stdout.lines().next().unwrap();
    assert!(first_line.contains("value = 0"), "first event: {}", first_line);
    let last_line = stdout.lines().last().unwrap();
    assert!(
        last_line.contains(&format!("value = {}", num_events - 1)),
        "last event: {}",
        last_line
    );
}

// ---------- Test 3: Big-endian trace ----------

#[test]
fn big_endian_trace() {
    let dir = Path::new("/tmp/ctf2-test-bigendian");
    clean_dir(dir);

    let clock = Clock::new("monotonic", 1_000_000_000).with_unix_epoch_offset();

    let config = TraceConfig {
        byte_order: ByteOrder::BigEndian,
        packet_size_bytes: 4096,
        clocks: vec![clock],
        stream_classes: vec![StreamClassDef {
            id: 0,
            name: Some("default".to_string()),
            clock_name: Some("monotonic".to_string()),
            event_classes: vec![
                EventClassDef {
                    id: 0,
                    name: "be_event".to_string(),
                    payload_field_class: Some(FieldClass::Structure {
                        member_classes: Some(vec![
                            metadata::MemberClass {
                                name: "val_u32".to_string(),
                                field_class: make_uint_fc(32, "big-endian"),
                            },
                            metadata::MemberClass {
                                name: "val_u64".to_string(),
                                field_class: make_uint_fc(64, "big-endian"),
                            },
                        ]),
                        minimum_alignment: None,
                    }),
                },
                EventClassDef {
                    id: 1,
                    name: "be_string".to_string(),
                    payload_field_class: Some(FieldClass::Structure {
                        member_classes: Some(vec![metadata::MemberClass {
                            name: "msg".to_string(),
                            field_class: FieldClass::NullTerminatedString { encoding: None },
                        }]),
                        minimum_alignment: None,
                    }),
                },
            ],
        }],
    };

    let mut trace = TraceWriter::create(dir, config).unwrap();
    let mut stream = trace.create_stream(0).unwrap();

    stream
        .write_event(0, 0, |enc| {
            enc.write_unsigned(0xDEADBEEF, 32);
            enc.write_unsigned(0x0123456789ABCDEF, 64);
        })
        .unwrap();

    stream
        .write_event(0, 1_000_000, |enc| {
            enc.write_unsigned(42, 32);
            enc.write_unsigned(999, 64);
        })
        .unwrap();

    stream
        .write_event(1, 2_000_000, |enc| {
            enc.write_null_terminated_string("big-endian works");
        })
        .unwrap();

    stream.close().unwrap();

    let (ok, stdout) = babeltrace2_read(dir);
    assert!(ok, "babeltrace2 failed to read big-endian trace");
    assert_eq!(stdout.lines().count(), 3, "expected 3 events");
    assert!(stdout.contains("val_u32 = 3735928559")); // 0xDEADBEEF
    assert!(stdout.contains("val_u64 = 81985529216486895")); // 0x0123456789ABCDEF
    assert!(stdout.contains("big-endian works"));
}

// ---------- Test 4: Multiple field types ----------

#[test]
fn multiple_field_types() {
    let dir = Path::new("/tmp/ctf2-test-fieldtypes");
    clean_dir(dir);

    let bo = "little-endian";
    let clock = Clock::new("monotonic", 1_000_000_000).with_unix_epoch_offset();

    let config = TraceConfig {
        byte_order: ByteOrder::LittleEndian,
        packet_size_bytes: 4096,
        clocks: vec![clock],
        stream_classes: vec![StreamClassDef {
            id: 0,
            name: Some("default".to_string()),
            clock_name: Some("monotonic".to_string()),
            event_classes: vec![
                // Event with various unsigned integer widths
                EventClassDef {
                    id: 0,
                    name: "uint_sizes".to_string(),
                    payload_field_class: Some(FieldClass::Structure {
                        member_classes: Some(vec![
                            metadata::MemberClass {
                                name: "val_u8".to_string(),
                                field_class: make_uint_fc(8, bo),
                            },
                            metadata::MemberClass {
                                name: "val_u16".to_string(),
                                field_class: make_uint_fc(16, bo),
                            },
                            metadata::MemberClass {
                                name: "val_u32".to_string(),
                                field_class: make_uint_fc(32, bo),
                            },
                            metadata::MemberClass {
                                name: "val_u64".to_string(),
                                field_class: make_uint_fc(64, bo),
                            },
                        ]),
                        minimum_alignment: None,
                    }),
                },
                // Event with signed integers
                EventClassDef {
                    id: 1,
                    name: "signed_ints".to_string(),
                    payload_field_class: Some(FieldClass::Structure {
                        member_classes: Some(vec![
                            metadata::MemberClass {
                                name: "neg_i8".to_string(),
                                field_class: make_sint_fc(8, bo),
                            },
                            metadata::MemberClass {
                                name: "neg_i32".to_string(),
                                field_class: make_sint_fc(32, bo),
                            },
                            metadata::MemberClass {
                                name: "pos_i32".to_string(),
                                field_class: make_sint_fc(32, bo),
                            },
                            metadata::MemberClass {
                                name: "neg_i64".to_string(),
                                field_class: make_sint_fc(64, bo),
                            },
                        ]),
                        minimum_alignment: None,
                    }),
                },
                // Event with floats
                EventClassDef {
                    id: 2,
                    name: "floats".to_string(),
                    payload_field_class: Some(FieldClass::Structure {
                        member_classes: Some(vec![
                            metadata::MemberClass {
                                name: "f32_val".to_string(),
                                field_class: make_float_fc(32, bo),
                            },
                            metadata::MemberClass {
                                name: "f64_val".to_string(),
                                field_class: make_float_fc(64, bo),
                            },
                        ]),
                        minimum_alignment: None,
                    }),
                },
                // Event with boolean
                EventClassDef {
                    id: 3,
                    name: "booleans".to_string(),
                    payload_field_class: Some(FieldClass::Structure {
                        member_classes: Some(vec![
                            metadata::MemberClass {
                                name: "flag_true".to_string(),
                                field_class: make_bool_fc(bo),
                            },
                            metadata::MemberClass {
                                name: "flag_false".to_string(),
                                field_class: make_bool_fc(bo),
                            },
                        ]),
                        minimum_alignment: None,
                    }),
                },
                // Event with nested struct
                EventClassDef {
                    id: 4,
                    name: "nested_struct".to_string(),
                    payload_field_class: Some(FieldClass::Structure {
                        member_classes: Some(vec![
                            metadata::MemberClass {
                                name: "position".to_string(),
                                field_class: FieldClass::Structure {
                                    member_classes: Some(vec![
                                        metadata::MemberClass {
                                            name: "x".to_string(),
                                            field_class: make_float_fc(32, bo),
                                        },
                                        metadata::MemberClass {
                                            name: "y".to_string(),
                                            field_class: make_float_fc(32, bo),
                                        },
                                        metadata::MemberClass {
                                            name: "z".to_string(),
                                            field_class: make_float_fc(32, bo),
                                        },
                                    ]),
                                    minimum_alignment: None,
                                },
                            },
                            metadata::MemberClass {
                                name: "label".to_string(),
                                field_class: FieldClass::NullTerminatedString { encoding: None },
                            },
                        ]),
                        minimum_alignment: None,
                    }),
                },
                // Event with static-length array
                EventClassDef {
                    id: 5,
                    name: "array_event".to_string(),
                    payload_field_class: Some(FieldClass::Structure {
                        member_classes: Some(vec![metadata::MemberClass {
                            name: "data".to_string(),
                            field_class: FieldClass::StaticLengthArray {
                                length: 4,
                                element_field_class: Box::new(make_uint_fc(32, bo)),
                                minimum_alignment: None,
                            },
                        }]),
                        minimum_alignment: None,
                    }),
                },
            ],
        }],
    };

    let mut trace = TraceWriter::create(dir, config).unwrap();
    let mut stream = trace.create_stream(0).unwrap();
    let mut ts = 0u64;

    // uint_sizes
    stream
        .write_event(0, ts, |enc| {
            enc.write_unsigned(255, 8);
            enc.write_unsigned(65535, 16);
            enc.write_unsigned(0xFFFFFFFF, 32);
            enc.write_unsigned(u64::MAX, 64);
        })
        .unwrap();
    ts += 1_000_000;

    // signed_ints
    stream
        .write_event(1, ts, |enc| {
            enc.write_signed(-1, 8);
            enc.write_signed(-42, 32);
            enc.write_signed(42, 32);
            enc.write_signed(i64::MIN, 64);
        })
        .unwrap();
    ts += 1_000_000;

    // floats
    stream
        .write_event(2, ts, |enc| {
            enc.write_f32(1.5);
            enc.write_f64(-273.15);
        })
        .unwrap();
    ts += 1_000_000;

    // booleans
    stream
        .write_event(3, ts, |enc| {
            enc.write_unsigned(1, 8);
            enc.write_unsigned(0, 8);
        })
        .unwrap();
    ts += 1_000_000;

    // nested_struct
    stream
        .write_event(4, ts, |enc| {
            enc.write_f32(1.0);
            enc.write_f32(2.0);
            enc.write_f32(3.0);
            enc.write_null_terminated_string("origin");
        })
        .unwrap();
    ts += 1_000_000;

    // array_event
    stream
        .write_event(5, ts, |enc| {
            enc.write_unsigned(10, 32);
            enc.write_unsigned(20, 32);
            enc.write_unsigned(30, 32);
            enc.write_unsigned(40, 32);
        })
        .unwrap();

    stream.close().unwrap();

    let (ok, stdout) = babeltrace2_read(dir);
    assert!(ok, "babeltrace2 failed to read field-types trace");
    assert_eq!(stdout.lines().count(), 6, "expected 6 events");

    // Check unsigned integers
    assert!(stdout.contains("val_u8 = 255"), "u8 max");
    assert!(stdout.contains("val_u16 = 65535"), "u16 max");
    assert!(stdout.contains("val_u32 = 4294967295"), "u32 max");
    assert!(stdout.contains("val_u64 = 18446744073709551615"), "u64 max");

    // Check signed integers
    assert!(stdout.contains("neg_i8 = -1"), "i8 -1");
    assert!(stdout.contains("neg_i32 = -42"), "i32 -42");
    assert!(stdout.contains("pos_i32 = 42"), "i32 +42");
    assert!(
        stdout.contains("neg_i64 = -9223372036854775808"),
        "i64 min"
    );

    // Check floats (babeltrace2 prints limited precision)
    assert!(stdout.contains("f32_val = 1.5"), "f32 value");
    assert!(stdout.contains("f64_val = -273.15"), "f64 neg");

    // Check booleans
    assert!(stdout.contains("flag_true = 1") || stdout.contains("flag_true = true"));
    assert!(stdout.contains("flag_false = 0") || stdout.contains("flag_false = false"));

    // Check nested struct
    assert!(stdout.contains("origin"), "nested struct string");

    // Check array
    assert!(stdout.contains("[0] = 10"), "array elem 0");
    assert!(stdout.contains("[3] = 40"), "array elem 3");
}

// ---------- Test 5: Multiple streams ----------

#[test]
fn multiple_streams() {
    let dir = Path::new("/tmp/ctf2-test-multistream");
    clean_dir(dir);

    let clock = Clock::new("monotonic", 1_000_000_000).with_unix_epoch_offset();

    let config = TraceConfig {
        byte_order: ByteOrder::LittleEndian,
        packet_size_bytes: 4096,
        clocks: vec![clock],
        stream_classes: vec![
            StreamClassDef {
                id: 0,
                name: Some("physics".to_string()),
                clock_name: Some("monotonic".to_string()),
                event_classes: vec![EventClassDef {
                    id: 0,
                    name: "tick".to_string(),
                    payload_field_class: Some(FieldClass::Structure {
                        member_classes: Some(vec![metadata::MemberClass {
                            name: "dt_ns".to_string(),
                            field_class: make_uint_fc(64, "little-endian"),
                        }]),
                        minimum_alignment: None,
                    }),
                }],
            },
            StreamClassDef {
                id: 1,
                name: Some("render".to_string()),
                clock_name: Some("monotonic".to_string()),
                event_classes: vec![EventClassDef {
                    id: 0,
                    name: "frame".to_string(),
                    payload_field_class: Some(FieldClass::Structure {
                        member_classes: Some(vec![metadata::MemberClass {
                            name: "frame_num".to_string(),
                            field_class: make_uint_fc(32, "little-endian"),
                        }]),
                        minimum_alignment: None,
                    }),
                }],
            },
        ],
    };

    let mut trace = TraceWriter::create(dir, config).unwrap();
    let mut stream_physics = trace.create_stream(0).unwrap();
    let mut stream_render = trace.create_stream(1).unwrap();

    // Interleave events across streams
    for i in 0u64..20 {
        stream_physics
            .write_event(0, i * 500_000, |enc| {
                enc.write_unsigned(16_666_667, 64); // ~60fps dt
            })
            .unwrap();

        if i % 2 == 0 {
            stream_render
                .write_event(0, i * 500_000, |enc| {
                    enc.write_unsigned(i / 2, 32);
                })
                .unwrap();
        }
    }

    stream_physics.close().unwrap();
    stream_render.close().unwrap();

    assert!(dir.join("stream_0").exists());
    assert!(dir.join("stream_1").exists());

    let (ok, stdout) = babeltrace2_read(dir);
    assert!(ok, "babeltrace2 failed to read multi-stream trace");

    let tick_count = stdout.lines().filter(|l| l.contains("tick")).count();
    let frame_count = stdout.lines().filter(|l| l.contains("frame")).count();
    assert_eq!(tick_count, 20, "expected 20 tick events");
    assert_eq!(frame_count, 10, "expected 10 frame events");
}

// ---------- Test 6: Verbose mode (check for warnings) ----------

#[test]
fn no_warnings_in_verbose_mode() {
    let dir = Path::new("/tmp/ctf2-test-verbose");
    clean_dir(dir);

    let clock = Clock::new("monotonic", 1_000_000_000).with_unix_epoch_offset();

    let config = TraceConfig {
        byte_order: ByteOrder::LittleEndian,
        packet_size_bytes: 4096,
        clocks: vec![clock],
        stream_classes: vec![StreamClassDef {
            id: 0,
            name: Some("default".to_string()),
            clock_name: Some("monotonic".to_string()),
            event_classes: vec![EventClassDef {
                id: 0,
                name: "ping".to_string(),
                payload_field_class: Some(FieldClass::Structure {
                    member_classes: Some(vec![metadata::MemberClass {
                        name: "seq".to_string(),
                        field_class: make_uint_fc(32, "little-endian"),
                    }]),
                    minimum_alignment: None,
                }),
            }],
        }],
    };

    let mut trace = TraceWriter::create(dir, config).unwrap();
    let mut stream = trace.create_stream(0).unwrap();

    for i in 0..5 {
        stream
            .write_event(0, i * 1_000_000, |enc| {
                enc.write_unsigned(i, 32);
            })
            .unwrap();
    }
    stream.close().unwrap();

    let (ok, stdout, stderr) = babeltrace2_read_verbose(dir);
    assert!(ok, "babeltrace2 failed");
    assert_eq!(stdout.lines().count(), 5);

    // Filter out the query-related warnings that happen during auto-discovery
    // (babeltrace2 tries multiple source plugins and some may warn)
    let real_warnings: Vec<&str> = stderr
        .lines()
        .filter(|l| l.contains(" W ") || l.contains(" E "))
        .filter(|l| !l.contains("support-info"))
        .filter(|l| !l.contains("query"))
        .collect();

    assert!(
        real_warnings.is_empty(),
        "unexpected warnings/errors:\n{}",
        real_warnings.join("\n")
    );
}

// ---------- Test 7: Timestamp correctness ----------

#[test]
fn timestamp_correctness() {
    let dir = Path::new("/tmp/ctf2-test-timestamps");
    clean_dir(dir);

    // Use a clock with known offset: exactly 1000 seconds after epoch
    let mut clock = Clock::new("monotonic", 1_000_000_000);
    clock.offset_seconds = 1000;
    clock.offset_cycles = 0;

    let config = TraceConfig {
        byte_order: ByteOrder::LittleEndian,
        packet_size_bytes: 4096,
        clocks: vec![clock],
        stream_classes: vec![StreamClassDef {
            id: 0,
            name: Some("default".to_string()),
            clock_name: Some("monotonic".to_string()),
            event_classes: vec![EventClassDef {
                id: 0,
                name: "ts_event".to_string(),
                payload_field_class: Some(FieldClass::Structure {
                    member_classes: Some(vec![metadata::MemberClass {
                        name: "seq".to_string(),
                        field_class: make_uint_fc(32, "little-endian"),
                    }]),
                    minimum_alignment: None,
                }),
            }],
        }],
    };

    let mut trace = TraceWriter::create(dir, config).unwrap();
    let mut stream = trace.create_stream(0).unwrap();

    // Write events at exactly 0, 1s, 2s, 3s in clock cycles
    for i in 0..4 {
        stream
            .write_event(0, i * 1_000_000_000, |enc| {
                enc.write_unsigned(i, 32);
            })
            .unwrap();
    }
    stream.close().unwrap();

    let (ok, stdout) = babeltrace2_read(dir);
    assert!(ok, "babeltrace2 failed");
    assert_eq!(stdout.lines().count(), 4);

    // With offset_seconds=1000, the first event (clock=0) should show
    // 1970-01-01 00:16:40.000000000 (1000 seconds after epoch)
    // Events should be 1 second apart
    let lines: Vec<&str> = stdout.lines().collect();

    // Verify events are 1 second apart by checking the delta field
    // babeltrace2 shows (+1.000000000) for 1-second deltas
    for line in &lines[1..] {
        assert!(
            line.contains("+1.000000000"),
            "events should be 1s apart: {}",
            line
        );
    }

    // Verify the timestamp includes :16:40 (1000 seconds = 16 min 40 sec)
    // Hour depends on local timezone, so just check minutes:seconds
    assert!(
        lines[0].contains(":16:40"),
        "first event should be at XX:16:40, got: {}",
        lines[0]
    );
}

// ---------- Test 8: Packet overflow with variable-length payloads ----------

#[test]
fn packet_overflow_with_strings() {
    let dir = Path::new("/tmp/ctf2-test-overflow-strings");
    clean_dir(dir);

    let clock = Clock::new("monotonic", 1_000_000_000).with_unix_epoch_offset();

    let config = TraceConfig {
        byte_order: ByteOrder::LittleEndian,
        packet_size_bytes: 256,
        clocks: vec![clock],
        stream_classes: vec![StreamClassDef {
            id: 0,
            name: Some("default".to_string()),
            clock_name: Some("monotonic".to_string()),
            event_classes: vec![EventClassDef {
                id: 0,
                name: "log".to_string(),
                payload_field_class: Some(FieldClass::Structure {
                    member_classes: Some(vec![metadata::MemberClass {
                        name: "message".to_string(),
                        field_class: FieldClass::NullTerminatedString { encoding: None },
                    }]),
                    minimum_alignment: None,
                }),
            }],
        }],
    };

    let mut trace = TraceWriter::create(dir, config).unwrap();
    let mut stream = trace.create_stream(0).unwrap();

    // Write strings of varying length — some will force packet boundaries
    let messages = [
        "short",
        "a medium length message for testing",
        "this is a longer message that takes up more space in the packet buffer to test boundary conditions",
        "x",
        "another fairly long message to push past the packet boundary and force a new packet allocation",
        "end",
    ];

    for (i, msg) in messages.iter().enumerate() {
        stream
            .write_event(0, i as u64 * 1_000_000, |enc| {
                enc.write_null_terminated_string(msg);
            })
            .unwrap();
    }
    stream.close().unwrap();

    let (ok, stdout) = babeltrace2_read(dir);
    assert!(ok, "babeltrace2 failed to read string-overflow trace");
    assert_eq!(
        stdout.lines().count(),
        messages.len(),
        "expected {} events",
        messages.len()
    );

    for msg in &messages {
        assert!(stdout.contains(msg), "missing message: {}", msg);
    }
}

// ---------- Test 9: Big-endian with packet overflow ----------

#[test]
fn big_endian_packet_overflow() {
    let dir = Path::new("/tmp/ctf2-test-be-overflow");
    clean_dir(dir);

    let clock = Clock::new("monotonic", 1_000_000_000).with_unix_epoch_offset();

    let config = TraceConfig {
        byte_order: ByteOrder::BigEndian,
        packet_size_bytes: 256,
        clocks: vec![clock],
        stream_classes: vec![StreamClassDef {
            id: 0,
            name: Some("default".to_string()),
            clock_name: Some("monotonic".to_string()),
            event_classes: vec![EventClassDef {
                id: 0,
                name: "be_counter".to_string(),
                payload_field_class: Some(FieldClass::Structure {
                    member_classes: Some(vec![metadata::MemberClass {
                        name: "value".to_string(),
                        field_class: make_uint_fc(32, "big-endian"),
                    }]),
                    minimum_alignment: None,
                }),
            }],
        }],
    };

    let mut trace = TraceWriter::create(dir, config).unwrap();
    let mut stream = trace.create_stream(0).unwrap();

    for i in 0u64..30 {
        stream
            .write_event(0, i * 1_000_000, |enc| {
                enc.write_unsigned(i * 100, 32);
            })
            .unwrap();
    }
    stream.close().unwrap();

    let (ok, stdout) = babeltrace2_read(dir);
    assert!(ok, "babeltrace2 failed to read BE multi-packet trace");
    assert_eq!(stdout.lines().count(), 30);

    let last_line = stdout.lines().last().unwrap();
    assert!(last_line.contains("value = 2900"), "last: {}", last_line);
}

// ---------- Test 10: Empty payload event ----------

#[test]
fn empty_payload_event() {
    let dir = Path::new("/tmp/ctf2-test-empty-payload");
    clean_dir(dir);

    let clock = Clock::new("monotonic", 1_000_000_000).with_unix_epoch_offset();

    let config = TraceConfig {
        byte_order: ByteOrder::LittleEndian,
        packet_size_bytes: 4096,
        clocks: vec![clock],
        stream_classes: vec![StreamClassDef {
            id: 0,
            name: Some("default".to_string()),
            clock_name: Some("monotonic".to_string()),
            event_classes: vec![EventClassDef {
                id: 0,
                name: "marker".to_string(),
                payload_field_class: None,
            }],
        }],
    };

    let mut trace = TraceWriter::create(dir, config).unwrap();
    let mut stream = trace.create_stream(0).unwrap();

    for i in 0..5 {
        stream
            .write_event(0, i * 1_000_000, |_enc| {
                // No payload
            })
            .unwrap();
    }
    stream.close().unwrap();

    let (ok, stdout) = babeltrace2_read(dir);
    assert!(ok, "babeltrace2 failed to read empty-payload trace");
    assert_eq!(stdout.lines().count(), 5);
    assert!(stdout.contains("marker"));
}
