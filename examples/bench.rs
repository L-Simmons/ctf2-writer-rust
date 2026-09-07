// Nanoseconds per record for the text tracer line against
// ctf2-writer's bit encoder driven through PacketWriter, both to a sink and
// to a file. Run with cargo run --release --example bench.

use ctf2_writer::byte_order::ByteOrder;
use ctf2_writer::packet::PacketWriter;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::Instant;

const UUID: [u8; 16] = [1; 16];
const N: u64 = 1_000_000;
const PACKET: usize = 4096;

fn text(out: Box<dyn Write + Send>, buffer: usize) -> (u128, u64) {
    let mut w = BufWriter::with_capacity(buffer, out);
    let names = ["Ping", "Pong", "Ball", "Stop"];
    let actors = ["sender", "echo", "supervisor", "messagehub"];
    let t = Instant::now();
    let mut bytes = 0u64;
    for i in 0..N {
        let s = format!(
            "{:>4} {:>9} {:>9}  {} -> {}  {}  delivered\n",
            i,
            i * 3,
            i * 3 + 1,
            actors[(i % 4) as usize],
            actors[((i + 1) % 4) as usize],
            names[(i % 4) as usize],
        );
        bytes += s.len() as u64;
        w.write_all(s.as_bytes()).unwrap();
    }
    w.flush().unwrap();
    (t.elapsed().as_nanos(), bytes)
}

fn text_writeln(out: Box<dyn Write + Send>, buffer: usize) -> u128 {
    let mut w = BufWriter::with_capacity(buffer, out);
    let names = ["Ping", "Pong", "Ball", "Stop"];
    let actors = ["sender", "echo", "supervisor", "messagehub"];
    let t = Instant::now();
    for i in 0..N {
        writeln!(
            w,
            "{:>4} {:>9} {:>9}  {} -> {}  {}  delivered",
            i,
            i * 3,
            i * 3 + 1,
            actors[(i % 4) as usize],
            actors[((i + 1) % 4) as usize],
            names[(i % 4) as usize],
        )
        .unwrap();
    }
    w.flush().unwrap();
    t.elapsed().as_nanos()
}

fn ctf2(mut out: Box<dyn Write + Send>) -> (u128, u64) {
    let mut seq = 0u64;
    let mut packet = PacketWriter::new(PACKET, ByteOrder::LittleEndian, &UUID, 0, 0, 0, 0);
    let mut bytes = 0u64;
    let t = Instant::now();
    for i in 0..N {
        let ts = i * 1000;
        if packet.bit_pos() + 19 * 8 > packet.packet_size_bits() {
            let done = std::mem::replace(
                &mut packet,
                PacketWriter::new(PACKET, ByteOrder::LittleEndian, &UUID, 0, 0, seq + 1, ts),
            );
            let b = done.finalize(ts);
            bytes += b.len() as u64;
            out.write_all(&b).unwrap();
            seq += 1;
        }
        let enc = packet.encoder_mut();
        enc.write_unsigned(i % 4, 16);
        enc.write_unsigned(ts, 64);
        enc.write_unsigned(i % 4, 16);
        enc.write_unsigned((i + 1) % 4, 16);
        enc.write_unsigned(0, 8);
        enc.write_unsigned(i % 1000, 32);
        packet.record_event();
    }
    let b = packet.finalize(N * 1000);
    bytes += b.len() as u64;
    out.write_all(&b).unwrap();
    out.flush().unwrap();
    (t.elapsed().as_nanos(), bytes)
}

fn main() {
    let dir = std::env::temp_dir();
    let f =
        |name: &str| -> Box<dyn Write + Send> { Box::new(File::create(dir.join(name)).unwrap()) };

    for round in 0..3 {
        let (t1, b1) = text(Box::new(std::io::sink()), 64 * 1024);
        let t1b = text_writeln(Box::new(std::io::sink()), 64 * 1024);
        let (t2, _) = text(f("hd-bench-text"), 64 * 1024);
        let (t3, b3) = ctf2(Box::new(std::io::sink()));
        let (t4, _) = ctf2(f("hd-bench-ctf2"));
        println!(
            "round {round}: text->sink {:>4} ns  writeln!->sink {:>4} ns  text->file {:>4} ns  ctf2->sink {:>4} ns  ctf2->file {:>4} ns   text {:.2} B/rec  ctf2 {:.2} B/rec",
            t1 / N as u128,
            t1b / N as u128,
            t2 / N as u128,
            t3 / N as u128,
            t4 / N as u128,
            b1 as f64 / N as f64,
            b3 as f64 / N as f64
        );
    }
}
