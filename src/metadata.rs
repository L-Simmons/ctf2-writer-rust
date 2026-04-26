use serde::Serialize;
use std::collections::BTreeMap;
use std::io::Write;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Fragment {
    Preamble(Preamble),
    #[serde(rename = "trace-class")]
    TraceClass(TraceClass),
    #[serde(rename = "clock-class")]
    ClockClass(ClockClass),
    #[serde(rename = "data-stream-class")]
    DataStreamClass(DataStreamClass),
    #[serde(rename = "event-record-class")]
    EventRecordClass(EventRecordClass),
    #[serde(rename = "field-class-alias")]
    FieldClassAlias(FieldClassAlias),
}

#[derive(Debug, Clone, Serialize)]
pub struct Preamble {
    pub version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uuid: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct TraceClass {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packet_header_field_class: Option<FieldClass>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<BTreeMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClockClass {
    pub id: String,
    pub frequency: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "offset-from-origin")]
    pub offset_from_origin: Option<ClockOffset>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<ClockOrigin>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub precision: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClockOffset {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seconds: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cycles: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum ClockOrigin {
    UnixEpoch(String),
    Custom(ClockOriginCustom),
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClockOriginCustom {
    pub namespace: String,
    pub name: String,
    pub uid: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct DataStreamClass {
    pub id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_clock_class_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packet_context_field_class: Option<FieldClass>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_record_header_field_class: Option<FieldClass>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_record_common_context_field_class: Option<FieldClass>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct EventRecordClass {
    pub id: u64,
    pub data_stream_class_id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub specific_context_field_class: Option<FieldClass>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_field_class: Option<FieldClass>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct FieldClassAlias {
    pub name: String,
    pub field_class: FieldClass,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum FieldClass {
    #[serde(rename = "fixed-length-unsigned-integer")]
    FixedLengthUnsignedInteger {
        length: u32,
        #[serde(rename = "byte-order")]
        byte_order: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        alignment: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "preferred-display-base")]
        preferred_display_base: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        roles: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        mappings: Option<BTreeMap<String, Vec<[u64; 2]>>>,
    },
    #[serde(rename = "fixed-length-signed-integer")]
    FixedLengthSignedInteger {
        length: u32,
        #[serde(rename = "byte-order")]
        byte_order: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        alignment: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        roles: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        mappings: Option<BTreeMap<String, Vec<[i64; 2]>>>,
    },
    #[serde(rename = "fixed-length-floating-point-number")]
    FixedLengthFloatingPointNumber {
        length: u32,
        #[serde(rename = "byte-order")]
        byte_order: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        alignment: Option<u32>,
    },
    #[serde(rename = "fixed-length-boolean")]
    FixedLengthBoolean {
        length: u32,
        #[serde(rename = "byte-order")]
        byte_order: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        alignment: Option<u32>,
    },
    #[serde(rename = "null-terminated-string")]
    NullTerminatedString {
        #[serde(skip_serializing_if = "Option::is_none")]
        encoding: Option<String>,
    },
    #[serde(rename = "static-length-string")]
    StaticLengthString {
        length: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        encoding: Option<String>,
    },
    #[serde(rename = "dynamic-length-string")]
    DynamicLengthString {
        #[serde(rename = "length-field-location")]
        length_field_location: FieldLocation,
        #[serde(skip_serializing_if = "Option::is_none")]
        encoding: Option<String>,
    },
    #[serde(rename = "structure")]
    Structure {
        #[serde(rename = "member-classes")]
        #[serde(skip_serializing_if = "Option::is_none")]
        member_classes: Option<Vec<MemberClass>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "minimum-alignment")]
        minimum_alignment: Option<u32>,
    },
    #[serde(rename = "static-length-array")]
    StaticLengthArray {
        length: u64,
        #[serde(rename = "element-field-class")]
        element_field_class: Box<FieldClass>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "minimum-alignment")]
        minimum_alignment: Option<u32>,
    },
    #[serde(rename = "dynamic-length-array")]
    DynamicLengthArray {
        #[serde(rename = "element-field-class")]
        element_field_class: Box<FieldClass>,
        #[serde(rename = "length-field-location")]
        length_field_location: FieldLocation,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "minimum-alignment")]
        minimum_alignment: Option<u32>,
    },
    #[serde(rename = "static-length-blob")]
    StaticLengthBlob {
        length: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "media-type")]
        media_type: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        roles: Option<Vec<String>>,
    },
    #[serde(rename = "dynamic-length-blob")]
    DynamicLengthBlob {
        #[serde(rename = "length-field-location")]
        length_field_location: FieldLocation,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "media-type")]
        media_type: Option<String>,
    },
    #[serde(rename = "optional")]
    Optional {
        #[serde(rename = "field-class")]
        field_class: Box<FieldClass>,
        #[serde(rename = "selector-field-location")]
        selector_field_location: FieldLocation,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "selector-field-ranges")]
        selector_field_ranges: Option<Vec<[i64; 2]>>,
    },
    #[serde(rename = "variant")]
    Variant {
        options: Vec<VariantOption>,
        #[serde(rename = "selector-field-location")]
        selector_field_location: FieldLocation,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct MemberClass {
    pub name: String,
    pub field_class: FieldClass,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct FieldLocation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    pub path: Vec<Option<String>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct VariantOption {
    pub field_class: FieldClass,
    pub selector_field_ranges: Vec<[i64; 2]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

const RS: u8 = 0x1E;
const LF: u8 = 0x0A;

pub fn write_metadata<W: Write>(writer: &mut W, fragments: &[Fragment]) -> std::io::Result<()> {
    for fragment in fragments {
        writer.write_all(&[RS])?;
        serde_json::to_writer(&mut *writer, fragment)?;
        writer.write_all(&[LF])?;
    }
    Ok(())
}
