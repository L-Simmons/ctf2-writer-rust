use std::time::{SystemTime, UNIX_EPOCH};

pub struct Clock {
    pub name: String,
    pub frequency: u64,
    pub offset_seconds: i64,
    pub offset_cycles: u64,
    current_value: u64,
}

impl Clock {
    pub fn new(name: &str, frequency: u64) -> Self {
        Self {
            name: name.to_string(),
            frequency,
            offset_seconds: 0,
            offset_cycles: 0,
            current_value: 0,
        }
    }

    pub fn with_unix_epoch_offset(mut self) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch");
        self.offset_seconds = now.as_secs() as i64;
        self.offset_cycles = (now.subsec_nanos() as u64 * self.frequency) / 1_000_000_000;
        self
    }

    pub fn value(&self) -> u64 {
        self.current_value
    }

    pub fn set_value(&mut self, value: u64) {
        self.current_value = value;
    }

    pub fn tick(&mut self, cycles: u64) {
        self.current_value += cycles;
    }

    pub fn timestamp_from_nanos(&self, nanos: u64) -> u64 {
        (nanos as u128 * self.frequency as u128 / 1_000_000_000) as u64
    }
}
