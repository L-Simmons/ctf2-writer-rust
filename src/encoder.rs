use crate::byte_order::ByteOrder;

pub struct BitEncoder {
    buf: Vec<u8>,
    bit_pos: usize,
    byte_order: ByteOrder,
}

impl BitEncoder {
    pub fn new(capacity: usize, byte_order: ByteOrder) -> Self {
        Self {
            buf: vec![0u8; capacity],
            bit_pos: 0,
            byte_order,
        }
    }

    pub fn bit_pos(&self) -> usize {
        self.bit_pos
    }

    pub fn set_bit_pos(&mut self, pos: usize) {
        self.bit_pos = pos;
    }

    pub fn align(&mut self, alignment: usize) {
        if alignment <= 1 {
            return;
        }
        let remainder = self.bit_pos % alignment;
        if remainder != 0 {
            self.bit_pos += alignment - remainder;
        }
    }

    pub fn write_unsigned(&mut self, value: u64, bit_width: usize) {
        self.write_unsigned_with_order(value, bit_width, self.byte_order);
    }

    pub fn write_unsigned_with_order(&mut self, value: u64, bit_width: usize, order: ByteOrder) {
        assert!(bit_width > 0 && bit_width <= 64);
        let mask = if bit_width == 64 {
            u64::MAX
        } else {
            (1u64 << bit_width) - 1
        };
        let value = value & mask;

        match order {
            ByteOrder::LittleEndian => self.write_bits_le(value, bit_width),
            ByteOrder::BigEndian => self.write_bits_be(value, bit_width),
        }
    }

    pub fn write_signed(&mut self, value: i64, bit_width: usize) {
        self.write_unsigned(value as u64, bit_width);
    }

    pub fn write_f32(&mut self, value: f32) {
        self.align(8);
        let bits = value.to_bits() as u64;
        self.write_unsigned(bits, 32);
    }

    pub fn write_f64(&mut self, value: f64) {
        self.align(8);
        let bits = value.to_bits();
        self.write_unsigned(bits, 64);
    }

    pub fn write_null_terminated_string(&mut self, s: &str) {
        self.align(8);
        for byte in s.as_bytes() {
            self.write_unsigned(*byte as u64, 8);
        }
        self.write_unsigned(0, 8);
    }

    pub fn write_bytes(&mut self, data: &[u8]) {
        self.align(8);
        for byte in data {
            self.write_unsigned(*byte as u64, 8);
        }
    }

    fn write_bits_le(&mut self, value: u64, bit_width: usize) {
        let mut remaining = bit_width;
        let mut val = value;
        while remaining > 0 {
            let byte_idx = self.bit_pos / 8;
            let bit_offset = self.bit_pos % 8;
            let bits_in_byte = (8 - bit_offset).min(remaining);

            if byte_idx >= self.buf.len() {
                self.buf.resize(byte_idx + 1, 0);
            }

            let mask = ((1u64 << bits_in_byte) - 1) as u8;
            let chunk = (val & mask as u64) as u8;
            self.buf[byte_idx] &= !(mask << bit_offset);
            self.buf[byte_idx] |= chunk << bit_offset;

            val >>= bits_in_byte;
            self.bit_pos += bits_in_byte;
            remaining -= bits_in_byte;
        }
    }

    fn write_bits_be(&mut self, value: u64, bit_width: usize) {
        let mut remaining = bit_width;
        while remaining > 0 {
            let byte_idx = self.bit_pos / 8;
            let bit_offset = self.bit_pos % 8;
            let bits_in_byte = (8 - bit_offset).min(remaining);

            if byte_idx >= self.buf.len() {
                self.buf.resize(byte_idx + 1, 0);
            }

            let shift = remaining - bits_in_byte;
            let chunk = ((value >> shift) & ((1u64 << bits_in_byte) - 1)) as u8;
            let dest_shift = 8 - bit_offset - bits_in_byte;
            let mask = if bits_in_byte == 8 { 0xFFu8 } else { (1u8 << bits_in_byte) - 1 };
            self.buf[byte_idx] &= !(mask << dest_shift);
            self.buf[byte_idx] |= chunk << dest_shift;

            self.bit_pos += bits_in_byte;
            remaining -= bits_in_byte;
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        let byte_len = (self.bit_pos + 7) / 8;
        &self.buf[..byte_len]
    }

    pub fn into_bytes(self) -> Vec<u8> {
        let byte_len = (self.bit_pos + 7) / 8;
        let mut buf = self.buf;
        buf.truncate(byte_len);
        buf
    }

    pub fn capacity_bits(&self) -> usize {
        self.buf.len() * 8
    }

    pub fn checkpoint(&self) -> usize {
        self.bit_pos
    }

    pub fn rollback(&mut self, checkpoint: usize) {
        let start_byte = checkpoint / 8;
        let end_byte = (self.bit_pos + 7) / 8;
        for i in start_byte..end_byte {
            if i < self.buf.len() {
                self.buf[i] = 0;
            }
        }
        self.bit_pos = checkpoint;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_u8_le() {
        let mut enc = BitEncoder::new(4, ByteOrder::LittleEndian);
        enc.write_unsigned(0xAB, 8);
        assert_eq!(enc.as_bytes(), &[0xAB]);
    }

    #[test]
    fn write_u32_le() {
        let mut enc = BitEncoder::new(4, ByteOrder::LittleEndian);
        enc.write_unsigned(0xDEADBEEF, 32);
        assert_eq!(enc.as_bytes(), &[0xEF, 0xBE, 0xAD, 0xDE]);
    }

    #[test]
    fn write_u32_be() {
        let mut enc = BitEncoder::new(4, ByteOrder::BigEndian);
        enc.write_unsigned(0xDEADBEEF, 32);
        assert_eq!(enc.as_bytes(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn write_4bit_fields_le() {
        let mut enc = BitEncoder::new(1, ByteOrder::LittleEndian);
        enc.write_unsigned(0x5, 4);
        enc.write_unsigned(0xA, 4);
        assert_eq!(enc.as_bytes(), &[0xA5]);
    }

    #[test]
    fn alignment() {
        let mut enc = BitEncoder::new(4, ByteOrder::LittleEndian);
        enc.write_unsigned(1, 1);
        enc.align(8);
        assert_eq!(enc.bit_pos(), 8);
        enc.write_unsigned(0xFF, 8);
        assert_eq!(enc.as_bytes(), &[0x01, 0xFF]);
    }

    #[test]
    fn write_string() {
        let mut enc = BitEncoder::new(16, ByteOrder::LittleEndian);
        enc.write_null_terminated_string("hi");
        assert_eq!(enc.as_bytes(), &[b'h', b'i', 0]);
    }

    #[test]
    fn magic_number_le() {
        let mut enc = BitEncoder::new(4, ByteOrder::LittleEndian);
        enc.write_unsigned(0xC1FC1FC1, 32);
        assert_eq!(enc.as_bytes(), &[0xC1, 0x1F, 0xFC, 0xC1]);
    }
}
