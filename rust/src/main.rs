// Kiffy v2 server — Rust rewrite. Standard library only, zero crates.
//
// Same wire protocol as kiffy_server.py (see its docstring): one port serves
// framed-TCP chat, HTTP static files and the /ws WebSocket endpoint; optional
// PSK encryption produces tokens compatible with Python's `cryptography`
// Fernet (AES-128-CBC + HMAC-SHA256, implemented here from scratch with
// published test vectors — run `--selftest`).
//
// Build:   cargo build --release          (or: ./build.sh)
// Run:     ./target/release/kiffy_server --port 8888 --psk secret
// Verify:  ./target/release/kiffy_server --selftest
// Tests:   cargo test

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{BufReader, Read, Shutdown, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_FRAME: usize = 64 * 1024;
const MAX_TEXT: usize = 16 * 1024;
const HISTORY_LIMIT: usize = 100;
const HISTORY_SEND: usize = 30;
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// rate limits, stored scaled to keep them lock-free atomics:
// RATE_CAP_X10 = burst (default 30.0), RATE_PER_SEC_X1000 = per second (default 0.5)
static RATE_CAP_X10: AtomicU64 = AtomicU64::new(300);
static RATE_PER_SEC_X1000: AtomicU64 = AtomicU64::new(500);

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn getrandom(buf: &mut [u8]) {
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(buf).is_ok() {
            return;
        }
    }
    let mut x = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
        | 1;
    for b in buf.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = (x & 0xff) as u8;
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn base_dir() -> PathBuf {
    std::env::var("KIFFY_BASE_DIR")
        .ok()
        .map(PathBuf::from)
        .or_else(|| option_env!("CARGO_MANIFEST_DIR").map(PathBuf::from))
        .unwrap_or_else(PathBuf::new)
}

// ============================= SHA-256 / SHA-1 / HMAC =============================

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let bitlen = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[4 * i], chunk[4 * i + 1], chunk[4 * i + 2], chunk[4 * i + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K256[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[4 * i..4 * i + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
    let bitlen = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[4 * i], chunk[4 * i + 1], chunk[4 * i + 2], chunk[4 * i + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a827999u32),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6),
            };
            let tmp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for i in 0..5 {
        out[4 * i..4 * i + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(64 + msg.len());
    for i in 0..64 {
        inner.push(k[i] ^ 0x36);
    }
    inner.extend_from_slice(msg);
    let ih = sha256(&inner);
    let mut outer = Vec::with_capacity(96);
    for i in 0..64 {
        outer.push(k[i] ^ 0x5c);
    }
    outer.extend_from_slice(&ih);
    sha256(&outer)
}

// ============================= AES-128 (FIPS-197) =============================

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

fn inv_sbox_byte(b: u8) -> u8 {
    for (i, &sb) in SBOX.iter().enumerate() {
        if sb == b {
            return i as u8;
        }
    }
    0
}

fn xtime(b: u8) -> u8 {
    (b << 1) ^ if b & 0x80 != 0 { 0x1b } else { 0 }
}

fn mul(a: u8, b: u8) -> u8 {
    let mut a = a;
    let mut b = b;
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    p
}

struct Aes128 {
    round_keys: [[u8; 16]; 11],
}

impl Aes128 {
    fn new(key: &[u8; 16]) -> Self {
        let mut rk = [[0u8; 16]; 11];
        rk[0].copy_from_slice(key);
        let mut rcon: u8 = 1;
        for round in 1..11 {
            let prev = rk[round - 1];
            let mut tmp = [prev[13], prev[14], prev[15], prev[12]];
            for t in tmp.iter_mut() {
                *t = SBOX[*t as usize];
            }
            tmp[0] ^= rcon;
            rcon = xtime(rcon);
            let mut cur = [0u8; 16];
            for i in 0..4 {
                cur[i] = prev[i] ^ tmp[i];
            }
            for wcol in 1..4 {
                for row in 0..4 {
                    let idx = wcol * 4 + row;
                    cur[idx] = prev[idx] ^ cur[idx - 4];
                }
            }
            rk[round] = cur;
        }
        Aes128 { round_keys: rk }
    }

    fn add_round_key(state: &mut [u8; 16], rk: &[u8; 16]) {
        for i in 0..16 {
            state[i] ^= rk[i];
        }
    }

    fn sub_bytes(state: &mut [u8; 16], inv: bool) {
        for b in state.iter_mut() {
            *b = if inv { inv_sbox_byte(*b) } else { SBOX[*b as usize] };
        }
    }

    fn shift_rows(state: &mut [u8; 16], inv: bool) {
        let src = *state;
        for r in 0..4 {
            for c in 0..4 {
                let dst = c * 4 + r;
                let sc = if inv { (c + 4 - r) % 4 } else { (c + r) % 4 };
                state[dst] = src[sc * 4 + r];
            }
        }
    }

    fn mix_columns(state: &mut [u8; 16], inv: bool) {
        for c in 0..4 {
            let col = [state[c * 4], state[c * 4 + 1], state[c * 4 + 2], state[c * 4 + 3]];
            for r in 0..4 {
                state[c * 4 + r] = if inv {
                    mul(col[r], 0x0e) ^ mul(col[(r + 1) % 4], 0x0b)
                        ^ mul(col[(r + 2) % 4], 0x0d) ^ mul(col[(r + 3) % 4], 0x09)
                } else {
                    mul(col[r], 2) ^ mul(col[(r + 1) % 4], 3)
                        ^ mul(col[(r + 2) % 4], 1) ^ mul(col[(r + 3) % 4], 1)
                };
            }
        }
    }

    fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut s = *block;
        Self::add_round_key(&mut s, &self.round_keys[0]);
        for round in 1..10 {
            Self::sub_bytes(&mut s, false);
            Self::shift_rows(&mut s, false);
            Self::mix_columns(&mut s, false);
            Self::add_round_key(&mut s, &self.round_keys[round]);
        }
        Self::sub_bytes(&mut s, false);
        Self::shift_rows(&mut s, false);
        Self::add_round_key(&mut s, &self.round_keys[10]);
        s
    }

    fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut s = *block;
        Self::add_round_key(&mut s, &self.round_keys[10]);
        for round in (1..10).rev() {
            Self::shift_rows(&mut s, true);
            Self::sub_bytes(&mut s, true);
            Self::add_round_key(&mut s, &self.round_keys[round]);
            Self::mix_columns(&mut s, true);
        }
        Self::shift_rows(&mut s, true);
        Self::sub_bytes(&mut s, true);
        Self::add_round_key(&mut s, &self.round_keys[0]);
        s
    }
}

fn cbc_encrypt(aes: &Aes128, iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let pad = 16 - plaintext.len() % 16;
    let mut data = plaintext.to_vec();
    data.resize(plaintext.len() + pad, pad as u8);
    let mut prev = *iv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut block = [0u8; 16];
        for i in 0..16 {
            block[i] = chunk[i] ^ prev[i];
        }
        let enc = aes.encrypt_block(&block);
        prev = enc;
        out.extend_from_slice(&enc);
    }
    out
}

fn cbc_decrypt(aes: &Aes128, iv: &[u8; 16], ciphertext: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return None;
    }
    let mut prev = *iv;
    let mut out = Vec::with_capacity(ciphertext.len());
    for chunk in ciphertext.chunks(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        let dec = aes.decrypt_block(&block);
        for i in 0..16 {
            out.push(dec[i] ^ prev[i]);
        }
        prev = block;
    }
    let pad = *out.last()? as usize;
    if pad == 0 || pad > 16 || out.len() < pad {
        return None;
    }
    if out[out.len() - pad..].iter().any(|&b| b as usize != pad) {
        return None;
    }
    out.truncate(out.len() - pad);
    Some(out)
}

// ============================= base64 =============================

fn b64_encode(data: &[u8], url: bool) -> String {
    let alpha: &[u8] = if url {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    };
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(alpha[(n >> 18) as usize & 63] as char);
        out.push(alpha[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { alpha[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { alpha[n as usize & 63] as char } else { '=' });
    }
    out
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let mut vals = Vec::with_capacity(s.len());
    for ch in s.bytes() {
        let v = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'a'..=b'z' => ch - b'a' + 26,
            b'0'..=b'9' => ch - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' | b'\n' | b'\r' => continue,
            _ => return None,
        };
        vals.push(v);
    }
    let mut out = Vec::with_capacity(vals.len() * 3 / 4);
    for chunk in vals.chunks(4) {
        if chunk.len() == 1 {
            return None;
        }
        let n = (chunk[0] as u32) << 18
            | ((chunk[1] as u32) << 12)
            | ((if chunk.len() > 2 { chunk[2] as u32 } else { 0 }) << 6)
            | (if chunk.len() > 3 { chunk[3] as u32 } else { 0 });
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

// ============================= Fernet (python-cryptography compatible) =============================

struct Fernet {
    aes: Aes128,
    sign_key: [u8; 16],
}

impl Fernet {
    fn new(key32: &[u8; 32]) -> Self {
        let mut sign_key = [0u8; 16];
        sign_key.copy_from_slice(&key32[..16]);
        let mut enc_key = [0u8; 16];
        enc_key.copy_from_slice(&key32[16..]);
        Fernet { aes: Aes128::new(&enc_key), sign_key }
    }

    /// Returns the urlsafe-base64 token bytes exactly as Python's
    /// Fernet.encrypt() puts them on the wire.
    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut iv = [0u8; 16];
        getrandom(&mut iv);
        let ct = cbc_encrypt(&self.aes, &iv, plaintext);
        let mut body = Vec::with_capacity(17 + ct.len());
        body.push(0x80);
        body.extend_from_slice(&iv);
        body.extend_from_slice(&ct);
        let mac = hmac_sha256(&self.sign_key, &body);
        body.extend_from_slice(&mac);
        b64_encode(&body, true).into_bytes()
    }

    fn decrypt(&self, token_b64: &[u8]) -> Option<Vec<u8>> {
        let tok = b64_decode(std::str::from_utf8(token_b64).ok()?)?;
        if tok.first()? != &0x80 || tok.len() < 17 + 16 + 32 {
            return None;
        }
        let mac_off = tok.len() - 32;
        let expected = hmac_sha256(&self.sign_key, &tok[..mac_off]);
        if !ct_eq(&expected, &tok[mac_off..]) {
            return None;
        }
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&tok[1..17]);
        cbc_decrypt(&self.aes, &iv, &tok[17..mac_off])
    }
}

// ============================= JSON =============================

#[derive(Clone, Debug, PartialEq)]
enum J {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl J {
    fn get(&self, key: &str) -> Option<&J> {
        if let J::Obj(pairs) = self {
            pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v)
        } else {
            None
        }
    }
    fn as_str(&self) -> Option<&str> {
        if let J::Str(s) = self {
            Some(s)
        } else {
            None
        }
    }
    fn as_bool(&self) -> Option<bool> {
        if let J::Bool(b) = self {
            Some(*b)
        } else {
            None
        }
    }
}

fn s(v: &str) -> J {
    J::Str(v.to_string())
}
fn n(v: i64) -> J {
    J::Num(v as f64)
}
fn obj(pairs: Vec<(&str, J)>) -> J {
    J::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    pos: usize,
    depth: usize,
}

fn j_parse(data: &[u8]) -> Option<J> {
    let mut p = JsonParser { bytes: data, pos: 0, depth: 0 };
    p.ws();
    let v = p.value()?;
    p.ws();
    if p.pos == p.bytes.len() {
        Some(v)
    } else {
        None
    }
}

impl<'a> JsonParser<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }
    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ') | Some(b'\t') | Some(b'\n') | Some(b'\r')) {
            self.pos += 1;
        }
    }
    fn expect(&mut self, b: u8) -> Option<()> {
        if self.peek() == Some(b) {
            self.pos += 1;
            Some(())
        } else {
            None
        }
    }
    fn value(&mut self) -> Option<J> {
        if self.depth > 64 {
            return None;
        }
        match self.peek()? {
            b'{' => self.object(),
            b'[' => self.array(),
            b'"' => self.string().map(J::Str),
            b't' => self.lit("true", J::Bool(true)),
            b'f' => self.lit("false", J::Bool(false)),
            b'n' => self.lit("null", J::Null),
            _ => self.number(),
        }
    }
    fn lit(&mut self, word: &str, v: J) -> Option<J> {
        if self.bytes[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Some(v)
        } else {
            None
        }
    }
    fn object(&mut self) -> Option<J> {
        self.expect(b'{')?;
        self.depth += 1;
        let mut pairs = Vec::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            self.depth -= 1;
            return Some(J::Obj(pairs));
        }
        loop {
            self.ws();
            let key = self.string()?;
            self.ws();
            self.expect(b':')?;
            self.ws();
            let val = self.value()?;
            pairs.push((key, val));
            self.ws();
            match self.peek()? {
                b',' => {
                    self.pos += 1;
                }
                b'}' => {
                    self.pos += 1;
                    self.depth -= 1;
                    return Some(J::Obj(pairs));
                }
                _ => return None,
            }
        }
    }
    fn array(&mut self) -> Option<J> {
        self.expect(b'[')?;
        self.depth += 1;
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            self.depth -= 1;
            return Some(J::Arr(items));
        }
        loop {
            self.ws();
            items.push(self.value()?);
            self.ws();
            match self.peek()? {
                b',' => {
                    self.pos += 1;
                }
                b']' => {
                    self.pos += 1;
                    self.depth -= 1;
                    return Some(J::Arr(items));
                }
                _ => return None,
            }
        }
    }
    fn string(&mut self) -> Option<String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let b = self.peek()?;
            self.pos += 1;
            match b {
                b'"' => return Some(out),
                b'\\' => {
                    let e = self.peek()?;
                    self.pos += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                if self.expect(b'\\').is_none() || self.expect(b'u').is_none() {
                                    return None;
                                }
                                let lo = self.hex4()?;
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else {
                                hi
                            };
                            out.push(char::from_u32(cp)?);
                        }
                        _ => return None,
                    }
                }
                _ => {
                    let start = self.pos - 1;
                    let len = utf8_len(b)?;
                    if start + len > self.bytes.len() {
                        return None;
                    }
                    let slice = &self.bytes[start..start + len];
                    out.push_str(std::str::from_utf8(slice).ok()?);
                    self.pos = start + len;
                }
            }
        }
    }
    fn hex4(&mut self) -> Option<u32> {
        if self.pos + 4 > self.bytes.len() {
            return None;
        }
        let txt = std::str::from_utf8(&self.bytes[self.pos..self.pos + 4]).ok()?;
        let v = u32::from_str_radix(txt, 16).ok()?;
        self.pos += 4;
        Some(v)
    }
    fn number(&mut self) -> Option<J> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while matches!(
            self.peek(),
            Some(b'0'..=b'9') | Some(b'.') | Some(b'e') | Some(b'E') | Some(b'+') | Some(b'-')
        ) {
            self.pos += 1;
        }
        let txt = std::str::from_utf8(&self.bytes[start..self.pos]).ok()?;
        txt.parse::<f64>().ok().map(J::Num)
    }
}

fn utf8_len(b: u8) -> Option<usize> {
    match b {
        0x00..=0x7f => Some(1),
        0xc0..=0xdf => Some(2),
        0xe0..=0xef => Some(3),
        0xf0..=0xf7 => Some(4),
        _ => None,
    }
}

fn j_escape(sv: &str, out: &mut String) {
    out.push('"');
    for c in sv.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn j_to_string(v: &J) -> String {
    let mut out = String::new();
    j_write(v, &mut out);
    out
}

fn j_write(v: &J, out: &mut String) {
    match v {
        J::Null => out.push_str("null"),
        J::Bool(true) => out.push_str("true"),
        J::Bool(false) => out.push_str("false"),
        J::Num(x) => {
            if x.fract() == 0.0 && x.abs() < 9.0e15 {
                out.push_str(&format!("{}", *x as i64));
            } else {
                out.push_str(&format!("{}", x));
            }
        }
        J::Str(sv) => j_escape(sv, out),
        J::Arr(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                j_write(item, out);
            }
            out.push(']');
        }
        J::Obj(pairs) => {
            out.push('{');
            for (i, (k, val)) in pairs.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                j_escape(k, out);
                out.push(':');
                j_write(val, out);
            }
            out.push('}');
        }
    }
}

// ============================= rate limiting =============================

struct Bucket {
    tokens: f64,
    ts: Instant,
}

impl Bucket {
    fn new() -> Self {
        Bucket { tokens: RATE_CAP_X10.load(Ordering::Relaxed) as f64 / 10.0, ts: Instant::now() }
    }
    fn allow(&mut self) -> bool {
        let cap = RATE_CAP_X10.load(Ordering::Relaxed) as f64 / 10.0;
        let per_sec = RATE_PER_SEC_X1000.load(Ordering::Relaxed) as f64 / 1000.0;
        let t = Instant::now();
        self.tokens = (self.tokens + t.duration_since(self.ts).as_secs_f64() * per_sec).min(cap);
        self.ts = t;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// ============================= hub =============================

#[derive(Clone, Copy, PartialEq)]
enum Transport {
    Tcp,
    Ws,
}

enum OutMsg {
    Frame(Vec<u8>),
}

struct Peer {
    tx: Sender<OutMsg>,
    #[allow(dead_code)]
    transport: Transport,
    #[allow(dead_code)]
    ip: String,
    admin: bool,
}

struct Ban {
    #[allow(dead_code)]
    ip: String,
    #[allow(dead_code)]
    reason: String,
}

struct Hub {
    clients: HashMap<String, Peer>,
    starred: HashSet<String>,
    admins: HashSet<String>,
    bans: HashMap<String, Ban>,
    typing: HashMap<String, Instant>,
    history: VecDeque<J>,
    admin_password: Option<String>,
    cipher: Option<Fernet>,
    psk_secret: Option<String>,
    nonce: String,
    buckets: HashMap<String, Bucket>,
    conn_buckets: HashMap<String, Bucket>,
    started: Instant,
}

impl Hub {
    fn new(admin_password: Option<String>, psk: Option<&str>) -> Hub {
        let mut nonce_bytes = [0u8; 16];
        getrandom(&mut nonce_bytes);
        let nonce = hex(&nonce_bytes);
        let cipher = psk.map(|psk| {
            let mut seed = Vec::new();
            seed.extend_from_slice(psk.as_bytes());
            seed.extend_from_slice(b"|");
            seed.extend_from_slice(nonce.as_bytes());
            let key = sha256(&seed);
            Fernet::new(&key)
        });
        Hub {
            clients: HashMap::new(),
            starred: HashSet::new(),
            admins: HashSet::new(),
            bans: HashMap::new(),
            typing: HashMap::new(),
            history: VecDeque::new(),
            admin_password,
            cipher,
            psk_secret: psk.map(|p| p.to_string()),
            nonce,
            buckets: HashMap::new(),
            conn_buckets: HashMap::new(),
            started: Instant::now(),
        }
    }

    fn allow_message(&mut self, name: &str, ip: &str) -> bool {
        let key = format!("{}|{}", name, ip);
        self.buckets.entry(key).or_insert_with(Bucket::new).allow()
    }

    fn allow_connect(&mut self, ip: &str) -> bool {
        self.conn_buckets.entry(ip.to_string()).or_insert_with(Bucket::new).allow()
    }

    fn is_banned(&self, name: &str, ip: &str) -> bool {
        if self.bans.contains_key(name) {
            return true;
        }
        self.bans.values().any(|b| b.ip == ip)
    }

    fn users_payload(&self) -> J {
        J::Arr(
            self.clients
                .iter()
                .map(|(name, _)| {
                    obj(vec![
                        ("n", s(name)),
                        ("s", J::Bool(self.starred.contains(name))),
                        ("a", J::Bool(self.admins.contains(name))),
                    ])
                })
                .collect(),
        )
    }

    fn record(&mut self, v: J) {
        if self.history.len() == HISTORY_LIMIT {
            self.history.pop_front();
        }
        self.history.push_back(v);
    }
}

fn frame_tcp(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn frame_ws(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + payload.len());
    out.push(0x81);
    let ln = payload.len();
    if ln < 126 {
        out.push(ln as u8);
    } else if ln < 65536 {
        out.push(126);
        out.extend_from_slice(&(ln as u16).to_be_bytes());
    } else {
        out.push(127);
        out.extend_from_slice(&(ln as u64).to_be_bytes());
    }
    out.extend_from_slice(payload);
    out
}

fn log(hub: &Hub, text: &str) {
    let secs = hub.started.elapsed().as_secs();
    println!(
        "[{:02}:{:02}:{:02}] {}",
        secs / 3600,
        secs / 60 % 60,
        secs % 60,
        text
    );
}

/// Build the wire payload for `msg` (encrypting once in PSK mode).
fn seal(hub: &Hub, msg: &J) -> Vec<u8> {
    let raw = j_to_string(msg).into_bytes();
    match &hub.cipher {
        Some(f) => f.encrypt(&raw),
        None => raw,
    }
}

/// Fan out `msg` to every client. Sends are channel pushes: they never block
/// on slow sockets (each client's writer thread does the actual I/O).
fn broadcast(hub: &Arc<Mutex<Hub>>, msg: &J, exclude: Option<&str>) {
    let dead = {
        let h = hub.lock().unwrap();
        let payload = seal(&h, msg);
        let tcp_frame = frame_tcp(&payload);
        let ws_frame = frame_ws(&payload);
        let mut dead = Vec::new();
        for (name, peer) in h.clients.iter() {
            if exclude == Some(name.as_str()) {
                continue;
            }
            let frame = if peer.transport == Transport::Tcp { tcp_frame.clone() } else { ws_frame.clone() };
            if peer.tx.send(OutMsg::Frame(frame)).is_err() {
                dead.push(name.clone());
            }
        }
        dead
    };
    if !dead.is_empty() {
        let mut h = hub.lock().unwrap();
        for d in dead {
            drop_user(&mut h, &d, true);
        }
    }
}

fn broadcast_users(hub: &mut Hub) {
    let msg = obj(vec![("t", s("users")), ("users", hub.users_payload())]);
    let payload = seal(hub, &msg);
    let tcp_frame = frame_tcp(&payload);
    let ws_frame = frame_ws(&payload);
    let dead: Vec<String> = hub
        .clients
        .iter()
        .filter(|(_, p)| {
            p.tx
                .send(OutMsg::Frame(if p.transport == Transport::Tcp {
                    tcp_frame.clone()
                } else {
                    ws_frame.clone()
                }))
                .is_err()
        })
        .map(|(nm, _)| nm.clone())
        .collect();
    for d in dead {
        drop_user(hub, &d, true);
    }
}

fn system(hub: &mut Hub, text: &str) {
    let msg = obj(vec![("t", s("sys")), ("text", s(text)), ("ts", n(now_unix() as i64))]);
    hub.record(msg.clone());
    let payload = seal(hub, &msg);
    let tcp_frame = frame_tcp(&payload);
    let ws_frame = frame_ws(&payload);
    let dead: Vec<String> = hub
        .clients
        .iter()
        .filter(|(_, p)| {
            p.tx
                .send(OutMsg::Frame(if p.transport == Transport::Tcp {
                    tcp_frame.clone()
                } else {
                    ws_frame.clone()
                }))
                .is_err()
        })
        .map(|(nm, _)| nm.clone())
        .collect();
    for d in dead {
        drop_user(hub, &d, true);
    }
}

fn drop_user(hub: &mut Hub, name: &str, quiet: bool) {
    if hub.clients.remove(name).is_none() {
        return;
    }
    hub.typing.remove(name);
    hub.starred.remove(name);
    hub.admins.remove(name);
    broadcast_users(hub);
    if !quiet {
        let text = format!("{} left ({} online)", name, hub.clients.len());
        log(hub, &text);
        system(hub, &text);
    }
}

// ============================= per-connection context =============================

struct Ctx {
    hub: Arc<Mutex<Hub>>,
    tx: Sender<OutMsg>,
    transport: Transport,
    ip: String,
    name: Option<String>,
    admin: bool,
    enc: bool,
    anchor: Option<String>,
}

impl Ctx {
    /// Serialize (+encrypt) and hand the frame to this client's writer thread.
    /// NEVER call while holding the hub lock — send() locks it.
    fn send(&self, msg: &J) {
        let payload = {
            let h = self.hub.lock().unwrap();
            if self.enc {
                match &h.cipher {
                    Some(f) => f.encrypt(j_to_string(msg).as_bytes()),
                    None => j_to_string(msg).into_bytes(),
                }
            } else {
                j_to_string(msg).into_bytes()
            }
        };
        let frame = match self.transport {
            Transport::Tcp => frame_tcp(&payload),
            Transport::Ws => frame_ws(&payload),
        };
        let _ = self.tx.send(OutMsg::Frame(frame));
    }

    fn safe_error(&self, text: &str) {
        self.send(&obj(vec![("t", s("error")), ("msg", s(text))]));
    }
}

fn valid_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (3..=20).contains(&bytes.len())
        && bytes.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'_')
}

// ============================= frame sources =============================

/// Pulls the next JSON payload off a connection, hiding TCP vs WS differences.
trait FrameSrc {
    fn read_frame(&mut self) -> Option<Vec<u8>>;
}

struct TcpSrc<'a> {
    reader: &'a mut BufReader<TcpStream>,
    first: Option<u8>, // demux byte that doubled as the first frame's header byte
}

impl<'a> FrameSrc for TcpSrc<'a> {
    fn read_frame(&mut self) -> Option<Vec<u8>> {
        let size: usize = match self.first.take() {
            Some(b0) => {
                let mut rest = [0u8; 3];
                self.reader.read_exact(&mut rest).ok()?;
                u32::from_be_bytes([b0, rest[0], rest[1], rest[2]]) as usize
            }
            None => {
                let mut hdr = [0u8; 4];
                self.reader.read_exact(&mut hdr).ok()?;
                u32::from_be_bytes(hdr) as usize
            }
        };
        if size == 0 || size > MAX_FRAME {
            return None;
        }
        let mut buf = vec![0u8; size];
        self.reader.read_exact(&mut buf).ok()?;
        Some(buf)
    }
}

struct WsSrc<'a> {
    reader: &'a mut BufReader<TcpStream>,
    tx: Sender<OutMsg>,
    buf: Vec<u8>,
}

impl<'a> FrameSrc for WsSrc<'a> {
    fn read_frame(&mut self) -> Option<Vec<u8>> {
        loop {
            let (fin, op, data) = ws_read_frame(self.reader)?;
            match op {
                0x8 => {
                    if data.len() < 126 {
                        let mut close = vec![0x88, data.len() as u8];
                        close.extend_from_slice(&data);
                        let _ = self.tx.send(OutMsg::Frame(close));
                    }
                    return None;
                }
                0x9 => {
                    if data.len() < 126 {
                        let mut pong = vec![0x8a, data.len() as u8];
                        pong.extend_from_slice(&data);
                        let _ = self.tx.send(OutMsg::Frame(pong));
                    }
                }
                0xA => {}
                0x1 | 0x2 | 0x0 => {
                    if op == 0x0 && self.buf.is_empty() {
                        return None; // stray continuation
                    }
                    self.buf.extend_from_slice(&data);
                    if fin {
                        return Some(std::mem::take(&mut self.buf));
                    }
                }
                _ => return None,
            }
        }
    }
}

fn ws_read_frame(reader: &mut BufReader<TcpStream>) -> Option<(bool, u8, Vec<u8>)> {
    let mut head = [0u8; 2];
    reader.read_exact(&mut head).ok()?;
    let fin = head[0] & 0x80 != 0;
    let op = head[0] & 0x0f;
    let masked = head[1] & 0x80 != 0;
    let mut size = (head[1] & 0x7f) as usize;
    if size == 126 {
        let mut ext = [0u8; 2];
        reader.read_exact(&mut ext).ok()?;
        size = u16::from_be_bytes(ext) as usize;
    } else if size == 127 {
        let mut ext = [0u8; 8];
        reader.read_exact(&mut ext).ok()?;
        size = u64::from_be_bytes(ext) as usize;
    }
    if size > MAX_FRAME {
        return None;
    }
    let mask = if masked {
        let mut m = [0u8; 4];
        reader.read_exact(&mut m).ok()?;
        Some(m)
    } else {
        None
    };
    let mut data = vec![0u8; size];
    if size > 0 {
        reader.read_exact(&mut data).ok()?;
    }
    if let Some(m) = mask {
        for (i, b) in data.iter_mut().enumerate() {
            *b ^= m[i % 4];
        }
    }
    Some((fin, op, data))
}

// ============================= chat session =============================

fn decrypt_payload(hub: &Arc<Mutex<Hub>>, payload: Vec<u8>, enc: bool) -> Option<Vec<u8>> {
    if enc {
        let h = hub.lock().unwrap();
        h.cipher.as_ref()?.decrypt(&payload)
    } else {
        Some(payload)
    }
}

fn pw_ok(pw: &str, expected: &str) -> bool {
    let a = hmac_sha256(b"kiffy", pw.as_bytes());
    let b = hmac_sha256(b"kiffy", expected.as_bytes());
    ct_eq(&a, &b)
}

fn chat_session(hub: Arc<Mutex<Hub>>, tx: Sender<OutMsg>, transport: Transport, ip: String, src: &mut dyn FrameSrc) {
    let mut ctx = Ctx {
        hub: hub.clone(),
        tx: tx.clone(),
        transport,
        ip: ip.clone(),
        name: None,
        admin: false,
        enc: false,
        anchor: None,
    };

    // Speak first so clients can detect plain/PSK mode (no lock held during send).
    let (has_cipher, nonce) = {
        let h = hub.lock().unwrap();
        (h.cipher.is_some(), h.nonce.clone())
    };
    if has_cipher {
        ctx.send(&obj(vec![("t", s("nonce")), ("nonce", s(&nonce))]));
    } else {
        ctx.send(&obj(vec![("t", s("hi")), ("psk", J::Bool(false))]));
    }

    // ---- handshake: hello ----
    let payload = match src.read_frame() {
        Some(p) => p,
        None => return,
    };
    let plain = match decrypt_payload(&hub, payload, false) {
        Some(p) => p,
        None => return,
    };
    let hello = match j_parse(&plain) {
        Some(v) => v,
        None => {
            ctx.safe_error("This is a Kiffy v2 server — update your client.");
            return;
        }
    };
    let is_v2 = matches!(hello.get("v"), Some(J::Num(x)) if *x == 2.0);
    if hello.get("t").and_then(J::as_str) != Some("hello") || !is_v2 {
        ctx.safe_error("This is a Kiffy v2 server — update your client.");
        return;
    }

    if has_cipher {
        let proof = hello.get("proof").and_then(J::as_str).unwrap_or("");
        let expected = {
            let h = hub.lock().unwrap();
            let psk = h.psk_secret.clone().unwrap_or_default();
            hex(&hmac_sha256(psk.as_bytes(), h.nonce.as_bytes()))
        };
        if !ct_eq(proof.as_bytes(), expected.as_bytes()) {
            ctx.safe_error("Wrong passphrase.");
            return;
        }
        ctx.enc = true;
    }

    let name = hello.get("user").and_then(J::as_str).unwrap_or("").trim().to_string();
    if !valid_name(&name) {
        ctx.safe_error("Invalid username: 3-20 chars, letters/digits/_");
        return;
    }

    // ---- admin password (checked before the taken-name check) ----
    let mut is_admin = false;
    if name == "admin" {
        let need_pw = hub.lock().unwrap().admin_password.is_some();
        if need_pw {
            let mut pw = hello.get("pw").and_then(J::as_str).unwrap_or("").to_string();
            if pw.is_empty() {
                ctx.send(&obj(vec![("t", s("pw"))]));
                let payload = match src.read_frame() {
                    Some(p) => p,
                    None => return,
                };
                let plain = match decrypt_payload(&hub, payload, ctx.enc) {
                    Some(p) => p,
                    None => return,
                };
                let auth = match j_parse(&plain) {
                    Some(v) => v,
                    None => return,
                };
                pw = auth.get("pw").and_then(J::as_str).unwrap_or("").to_string();
            }
            let expected = hub.lock().unwrap().admin_password.clone().unwrap_or_default();
            if !pw_ok(&pw, &expected) {
                ctx.safe_error("Wrong admin password.");
                return;
            }
            is_admin = true;
        }
    }

    // ---- register (checks and insert happen under one lock) ----
    let (welcome_frame, online) = {
        let mut h = hub.lock().unwrap();
        if h.is_banned(&name, &ip) {
            drop(h);
            ctx.safe_error("You are banned from this server.");
            return;
        }
        if h.clients.contains_key(&name) {
            drop(h);
            ctx.safe_error("Username already taken.");
            return;
        }
        if is_admin {
            h.admins.insert(name.clone());
        }
        h.clients.insert(
            name.clone(),
            Peer { tx: tx.clone(), transport, ip: ip.clone(), admin: is_admin },
        );
        ctx.name = Some(name.clone());
        ctx.admin = is_admin;

        let welcome = obj(vec![
            ("t", s("welcome")),
            ("user", s(&name)),
            ("admin", J::Bool(is_admin)),
            ("users", h.users_payload()),
            ("history", J::Arr(h.history.iter().rev().take(HISTORY_SEND).rev().cloned().collect())),
            ("psk", J::Bool(h.cipher.is_some())),
        ]);
        let payload = if ctx.enc {
            match &h.cipher {
                Some(f) => f.encrypt(j_to_string(&welcome).as_bytes()),
                None => j_to_string(&welcome).into_bytes(),
            }
        } else {
            j_to_string(&welcome).into_bytes()
        };
        let frame = match transport {
            Transport::Tcp => frame_tcp(&payload),
            Transport::Ws => frame_ws(&payload),
        };
        (frame, h.clients.len())
    };
    let _ = tx.send(OutMsg::Frame(welcome_frame));
    {
        let h = hub.lock().unwrap();
        log(&h, &format!("{} joined ({} online) from {}", name, online, ip));
    }
    let joined = format!("{} joined ({} online)", name, online);
    {
        let mut h = hub.lock().unwrap();
        h.record(obj(vec![("t", s("sys")), ("text", s(&joined)), ("ts", n(now_unix() as i64))]));
    }
    broadcast(&hub, &obj(vec![("t", s("sys")), ("text", s(&joined)), ("ts", n(now_unix() as i64))]), Some(&name));
    {
        let mut h = hub.lock().unwrap();
        broadcast_users(&mut h);
    }

    // ---- message loop ----
    while let Some(payload) = src.read_frame() {
        let plain = match decrypt_payload(&hub, payload, ctx.enc) {
            Some(p) => p,
            None => break,
        };
        let msg = match j_parse(&plain) {
            Some(v) => v,
            None => break,
        };
        if !handle_message(&hub, &mut ctx, &msg) {
            break;
        }
    }

    let mut h = hub.lock().unwrap();
    drop_user(&mut h, &name, true);
}

/// Returns false when the session should end (/exit).
fn handle_message(hub: &Arc<Mutex<Hub>>, ctx: &mut Ctx, msg: &J) -> bool {
    let t = msg.get("t").and_then(J::as_str).unwrap_or("").to_string();
    match t.as_str() {
        "ping" => {
            let ts = msg.get("ts").cloned().unwrap_or(J::Null);
            ctx.send(&obj(vec![("t", s("pong")), ("ts", ts)]));
        }
        "exit" => return false,
        "typing" => {
            let name = match &ctx.name {
                Some(nm) => nm.clone(),
                None => return true,
            };
            let on = msg.get("on").and_then(J::as_bool).unwrap_or(false);
            let (now_on, now_off) = {
                let mut h = hub.lock().unwrap();
                if on {
                    h.typing.insert(name.clone(), Instant::now() + Duration::from_secs(5));
                    (true, false)
                } else {
                    (false, h.typing.remove(&name).is_some())
                }
            };
            if now_on {
                broadcast(hub, &obj(vec![("t", s("typing")), ("user", s(&name)), ("on", J::Bool(true))]), Some(&name));
            } else if now_off {
                broadcast(hub, &obj(vec![("t", s("typing")), ("user", s(&name)), ("on", J::Bool(false))]), Some(&name));
            }
        }
        "users" => {
            let payload = {
                let h = hub.lock().unwrap();
                seal(&h, &obj(vec![("t", s("users")), ("users", h.users_payload())]))
            };
            let frame = match ctx.transport {
                Transport::Tcp => frame_tcp(&payload),
                Transport::Ws => frame_ws(&payload),
            };
            let _ = ctx.tx.send(OutMsg::Frame(frame));
        }
        "unanchor" => {
            ctx.anchor = None;
            ctx.send(&obj(vec![("t", s("sys")), ("text", s("Anchor removed.")), ("ts", n(now_unix() as i64))]));
        }
        "anchor" => {
            let to = msg.get("to").and_then(J::as_str).unwrap_or("").to_string();
            let known = hub.lock().unwrap().clients.contains_key(&to);
            let me = ctx.name.clone().unwrap_or_default();
            if known && to != me {
                ctx.anchor = Some(to.clone());
                ctx.send(&obj(vec![
                    ("t", s("sys")),
                    ("text", s(&format!("Anchored to {}. All messages go to them.", to))),
                    ("ts", n(now_unix() as i64)),
                ]));
            } else {
                ctx.safe_error(&format!("User {} not found.", to));
            }
        }
        "msg" => {
            let name = match &ctx.name {
                Some(nm) => nm.clone(),
                None => return true,
            };
            if !hub.lock().unwrap().allow_message(&name, &ctx.ip) {
                ctx.safe_error("Rate limit: max 30 messages per minute.");
                return true;
            }
            let text = msg.get("text").and_then(J::as_str).unwrap_or("").to_string();
            if text.starts_with('/') {
                return handle_command(hub, ctx, &text);
            }
            public_message(hub, ctx, &name, &text);
        }
        "pm" => {
            let name = match &ctx.name {
                Some(nm) => nm.clone(),
                None => return true,
            };
            if !hub.lock().unwrap().allow_message(&name, &ctx.ip) {
                ctx.safe_error("Rate limit: max 30 messages per minute.");
                return true;
            }
            let to = msg.get("to").and_then(J::as_str).unwrap_or("").to_string();
            let text = msg.get("text").and_then(J::as_str).unwrap_or("").to_string();
            private_message(hub, ctx, &name, &to, &text);
        }
        _ => {}
    }
    true
}

fn public_message(hub: &Arc<Mutex<Hub>>, ctx: &mut Ctx, name: &str, raw: &str) {
    let text: String = raw.trim().chars().take(MAX_TEXT).collect();
    if text.is_empty() {
        return;
    }
    let stopped_typing = {
        let mut h = hub.lock().unwrap();
        h.typing.remove(name).is_some()
    };
    if stopped_typing {
        broadcast(hub, &obj(vec![("t", s("typing")), ("user", s(name)), ("on", J::Bool(false))]), Some(name));
    }
    let msg = obj(vec![
        ("t", s("msg")),
        ("from", s(name)),
        ("text", s(&text)),
        ("ts", n(now_unix() as i64)),
        ("star", J::Bool(hub.lock().unwrap().starred.contains(name))),
    ]);
    {
        let mut h = hub.lock().unwrap();
        h.record(msg.clone());
    }
    broadcast(hub, &msg, Some(name));
}

fn private_message(hub: &Arc<Mutex<Hub>>, ctx: &mut Ctx, from: &str, to: &str, raw: &str) {
    let text: String = raw.trim().chars().take(MAX_TEXT).collect();
    if text.is_empty() {
        return;
    }
    let mut target = to.to_string();
    if target.is_empty() {
        if let Some(a) = &ctx.anchor {
            target = a.clone();
        }
    }

    let outcome: Result<(), String> = {
        let h = hub.lock().unwrap();
        match h.clients.get(&target) {
            None => Err(format!("User {} is not online.", target)),
            Some(peer) => {
                let pm = obj(vec![
                    ("t", s("pm")),
                    ("from", s(from)),
                    ("text", s(&text)),
                    ("ts", n(now_unix() as i64)),
                ]);
                let payload = seal(&h, &pm);
                let frame = match peer.transport {
                    Transport::Tcp => frame_tcp(&payload),
                    Transport::Ws => frame_ws(&payload),
                };
                match peer.tx.send(OutMsg::Frame(frame)) {
                    Ok(()) => Ok(()),
                    Err(_) => Err(format!("User {} is not reachable.", target)),
                }
            }
        }
    };
    match outcome {
        Ok(()) => ctx.send(&obj(vec![("t", s("pm_sent")), ("to", s(&target))])),
        Err(msg) => ctx.safe_error(&msg),
    }
}

/// Returns false on /exit.
fn handle_command(hub: &Arc<Mutex<Hub>>, ctx: &mut Ctx, text: &str) -> bool {
    let mut parts = text.splitn(2, ' ');
    let cmd = parts.next().unwrap_or("").to_lowercase();
    let rest = parts.next().unwrap_or("").trim().to_string();
    let name = match &ctx.name {
        Some(nm) => nm.clone(),
        None => return true,
    };

    if cmd == "/exit" {
        return false;
    }
    match cmd.as_str() {
        "/help" => {
            let mut lines = vec!["Commands: /users /s [user] [msg] /anchor [user] /unanchor /exit".to_string()];
            if ctx.admin {
                lines.push("Admin: /star /unstar /global /setemoji /makeadmin /removeadmin /ban /unban /banlist".to_string());
            }
            ctx.send(&obj(vec![("t", s("sys")), ("text", s(&lines.join("\n"))), ("ts", n(now_unix() as i64))]));
        }
        "/users" => {
            let names = {
                let h = hub.lock().unwrap();
                h.clients.keys().cloned().collect::<Vec<_>>().join(", ")
            };
            ctx.send(&obj(vec![("t", s("sys")), ("text", s(&format!("Online: {}", names))), ("ts", n(now_unix() as i64))]));
        }
        "/s" => {
            let mut it = rest.splitn(2, ' ');
            let target = it.next().unwrap_or("").trim().to_string();
            let body = it.next().unwrap_or("").to_string();
            private_message(hub, ctx, &name, &target, &body);
        }
        "/anchor" => {
            let known = hub.lock().unwrap().clients.contains_key(&rest);
            if known && rest != name {
                ctx.anchor = Some(rest.clone());
                ctx.send(&obj(vec![("t", s("sys")), ("text", s(&format!("Anchored to {}.", rest))), ("ts", n(now_unix() as i64))]));
            } else {
                ctx.safe_error(&format!("User {} not found.", rest));
            }
        }
        "/unanchor" => {
            ctx.anchor = None;
            ctx.send(&obj(vec![("t", s("sys")), ("text", s("Anchor removed.")), ("ts", n(now_unix() as i64))]));
        }
        "/star" if ctx.admin => {
            let found = {
                let mut h = hub.lock().unwrap();
                let found = h.clients.contains_key(&rest);
                if found {
                    h.starred.insert(rest.clone());
                }
                found
            };
            if found {
                ctx.send(&obj(vec![("t", s("sys")), ("text", s(&format!("Star given to {}.", rest))), ("ts", n(now_unix() as i64))]));
                let text = format!("⭐ {} received the Kiffy Star", rest);
                {
                    let mut h = hub.lock().unwrap();
                    h.record(obj(vec![("t", s("sys")), ("text", s(&text)), ("ts", n(now_unix() as i64))]));
                }
                broadcast(hub, &obj(vec![("t", s("sys")), ("text", s(&text)), ("ts", n(now_unix() as i64))]), None);
            } else {
                ctx.safe_error(&format!("User {} not found.", rest));
            }
        }
        "/unstar" if ctx.admin => {
            hub.lock().unwrap().starred.remove(&rest);
            ctx.send(&obj(vec![("t", s("sys")), ("text", s(&format!("Star removed from {}.", rest))), ("ts", n(now_unix() as i64))]));
        }
        "/global" if ctx.admin => {
            if !rest.is_empty() {
                let text: String = rest.chars().take(MAX_TEXT).collect();
                let msg = obj(vec![
                    ("t", s("global")),
                    ("from", s(&name)),
                    ("text", s(&text)),
                    ("ts", n(now_unix() as i64)),
                ]);
                {
                    let mut h = hub.lock().unwrap();
                    h.record(msg.clone());
                }
                broadcast(hub, &msg, None);
            }
        }
        "/setemoji" if ctx.admin => {
            // accepted for protocol parity; the web client renders its own badge
        }
        "/makeadmin" if ctx.admin => {
            let found = {
                let mut h = hub.lock().unwrap();
                let found = h.clients.contains_key(&rest);
                if found {
                    if let Some(peer) = h.clients.get_mut(&rest) {
                        peer.admin = true;
                    }
                    h.admins.insert(rest.clone());
                }
                found
            };
            if found {
                let text = format!("{} is now an admin", rest);
                {
                    let mut h = hub.lock().unwrap();
                    h.record(obj(vec![("t", s("sys")), ("text", s(&text)), ("ts", n(now_unix() as i64))]));
                }
                broadcast(hub, &obj(vec![("t", s("sys")), ("text", s(&text)), ("ts", n(now_unix() as i64))]), None);
                let mut h = hub.lock().unwrap();
                broadcast_users(&mut h);
            } else {
                ctx.safe_error(&format!("User {} not found.", rest));
            }
        }
        "/removeadmin" if ctx.admin => {
            if rest == "admin" {
                ctx.safe_error("Cannot remove the main admin.");
            } else {
                let mut h = hub.lock().unwrap();
                if let Some(peer) = h.clients.get_mut(&rest) {
                    peer.admin = false;
                }
                h.admins.remove(&rest);
            }
        }
        "/ban" if ctx.admin => {
            let mut it = rest.splitn(2, ' ');
            let target = it.next().unwrap_or("").to_string();
            let reason = it.next().unwrap_or("").trim().to_string();
            let reason = if reason.is_empty() { "No reason".to_string() } else { reason };
            if target == "admin" {
                ctx.safe_error("Cannot ban the main admin.");
            } else {
                let banned: Option<String> = {
                    let mut h = hub.lock().unwrap();
                    match h.clients.get(&target) {
                        Some(peer) => {
                            let ip = peer.ip.clone();
                            // deliver the ban notice before dropping the peer
                            let payload = seal(&h, &obj(vec![
                                ("t", s("sys")),
                                ("text", s(&format!("You are banned. Reason: {}", reason))),
                                ("ts", n(now_unix() as i64)),
                            ]));
                            let frame = match peer.transport {
                                Transport::Tcp => frame_tcp(&payload),
                                Transport::Ws => frame_ws(&payload),
                            };
                            let _ = peer.tx.send(OutMsg::Frame(frame));
                            h.bans.insert(target.clone(), Ban { ip, reason: reason.clone() });
                            Some(target.clone())
                        }
                        None => None,
                    }
                };
                if let Some(target) = banned {
                    let mut h = hub.lock().unwrap();
                    drop_user(&mut h, &target, true);
                    let text = format!("{} was banned (reason: {})", target, reason);
                    h.record(obj(vec![("t", s("sys")), ("text", s(&text)), ("ts", n(now_unix() as i64))]));
                    drop(h);
                    broadcast(hub, &obj(vec![("t", s("sys")), ("text", s(&text)), ("ts", n(now_unix() as i64))]), None);
                } else {
                    ctx.safe_error(&format!("User {} not found.", target));
                }
            }
        }
        "/unban" if ctx.admin => {
            let removed = hub.lock().unwrap().bans.remove(&rest).is_some();
            if removed {
                ctx.send(&obj(vec![("t", s("sys")), ("text", s(&format!("{} unbanned.", rest))), ("ts", n(now_unix() as i64))]));
            } else {
                ctx.safe_error(&format!("{} is not banned.", rest));
            }
        }
        "/banlist" if ctx.admin => {
            let list = {
                let h = hub.lock().unwrap();
                if h.bans.is_empty() {
                    "no banned users".to_string()
                } else {
                    let mut names: Vec<String> = h.bans.keys().cloned().collect();
                    names.sort();
                    names.join(", ")
                }
            };
            ctx.send(&obj(vec![("t", s("sys")), ("text", s(&format!("Banned: {}", list))), ("ts", n(now_unix() as i64))]));
        }
        _ => {
            ctx.safe_error("Unknown command. Try /help");
        }
    }
    true
}

// ============================= connection demux =============================

fn handle_conn(stream: TcpStream, hub: Arc<Mutex<Hub>>) {
    let ip = stream
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "?".to_string());
    let write_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let (tx, rx): (Sender<OutMsg>, Receiver<OutMsg>) = channel();
    thread::spawn(move || writer_loop(write_stream, rx));

    let read_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut reader = BufReader::new(read_stream);
    let mut first = [0u8; 1];
    if reader.read_exact(&mut first).is_err() {
        return;
    }

    if first[0] == 0x00 {
        let rejected = {
            let mut h = hub.lock().unwrap();
            if h.is_banned("", &ip) {
                let payload = seal(&h, &obj(vec![("t", s("error")), ("msg", s("You are banned from this server."))]));
                let _ = tx.send(OutMsg::Frame(frame_tcp(&payload)));
                true
            } else if !h.allow_connect(&ip) {
                true
            } else {
                false
            }
        };
        if !rejected {
            let mut src = TcpSrc { reader: &mut reader, first: Some(first[0]) };
            chat_session(hub, tx, Transport::Tcp, ip, &mut src);
        }
    } else {
        http_loop(&mut reader, stream, first[0], &hub, tx, ip);
    }
}

fn writer_loop(mut stream: TcpStream, rx: Receiver<OutMsg>) {
    for msg in rx {
        if let OutMsg::Frame(bytes) = msg {
            if stream.write_all(&bytes).is_err() {
                break;
            }
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
}

fn http_loop(
    reader: &mut BufReader<TcpStream>,
    mut stream: TcpStream,
    first_byte: u8,
    hub: &Arc<Mutex<Hub>>,
    tx: Sender<OutMsg>,
    ip: String,
) {
    let mut first = Some(first_byte);
    loop {
        // ---- read one request head ----
        let mut head: Vec<u8> = match first.take() {
            Some(b) => vec![b],
            None => vec![],
        };
        loop {
            let mut b = [0u8; 1];
            match reader.read(&mut b) {
                Ok(0) => return,
                Ok(_) => head.push(b[0]),
                Err(_) => return,
            }
            if head.ends_with(b"\r\n\r\n") || head.ends_with(b"\n\n") || head.len() > 32 * 1024 {
                break;
            }
        }
        let head_str = String::from_utf8_lossy(&head).to_string();
        let mut lines = head_str.split("\r\n").flat_map(|l| l.split('\n'));
        let request_line = lines.next().unwrap_or("").trim().to_string();
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() != 3 || !parts[2].starts_with("HTTP/") {
            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            return;
        }
        let method = parts[0].to_uppercase();
        let path_full = parts[1].to_string();
        let path = path_full.split('?').next().unwrap_or("/").to_string();
        let version = parts[2].to_string();

        let mut connection_close = version == "HTTP/1.0";
        for line in lines {
            let lower = line.to_lowercase();
            if lower.starts_with("connection:") && lower.contains("close") {
                connection_close = true;
            }
        }

        // ---- websocket upgrade ----
        if path == "/ws" {
            let mut key: Option<String> = None;
            let mut upgrade = false;
            for line in head_str.split("\r\n").skip(1) {
                let lower = line.to_lowercase();
                if lower.starts_with("sec-websocket-key:") {
                    key = line.splitn(2, ':').nth(1).map(|sv| sv.trim().to_string());
                }
                if lower.starts_with("upgrade:") && lower.contains("websocket") {
                    upgrade = true;
                }
            }
            if upgrade && key.is_some() {
                ws_upgrade(reader, stream, &key.unwrap(), hub.clone(), tx, ip);
                return; // connection now speaks the chat protocol
            }
            let body = b"WebSocket endpoint: use ws://host/ws";
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            );
            let _ = stream.write_all(body);
            return;
        }

        // ---- static files ----
        if method != "GET" && method != "HEAD" {
            let body = b"405 - GET only";
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 405 Method Not Allowed\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            );
            let _ = stream.write_all(body);
            return;
        }

        let (fname, ctype) = match path.as_str() {
            "/" | "/index.html" => ("index.html", "text/html; charset=utf-8"),
            "/app.html" => ("app.html", "text/html; charset=utf-8"),
            "/android.html" => ("android.html", "text/html; charset=utf-8"),
            "/kiffy_server.py" => ("kiffy_server.py", "text/plain; charset=utf-8"),
            "/kiffy_client.py" => ("kiffy_client.py", "text/plain; charset=utf-8"),
            "/LICENSE" => ("LICENSE", "text/plain; charset=utf-8"),
            "/windows.zip" => ("windows.zip", "application/zip"),
            _ => {
                let body = "404 - not found. Try / (landing) or /app.html (web app).";
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                );
                let _ = stream.write_all(body.as_bytes());
                return;
            }
        };

        let fpath = base_dir().join(fname);
        match std::fs::read(&fpath) {
            Ok(body) => {
                let cache = if ctype.starts_with("text/html") { "no-cache" } else { "max-age=3600" };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: {}\r\nConnection: {}\r\n\r\n",
                    ctype,
                    body.len(),
                    cache,
                    if connection_close { "close" } else { "keep-alive" }
                );
                let _ = stream.write_all(resp.as_bytes());
                if method == "GET" {
                    let _ = stream.write_all(&body);
                }
            }
            Err(_) => {
                let body = format!("500 - server file missing: {}", fname);
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                );
                let _ = stream.write_all(body.as_bytes());
            }
        }
        if connection_close {
            return;
        }
    }
}

fn ws_upgrade(
    reader: &mut BufReader<TcpStream>,
    stream: TcpStream,
    key: &str,
    hub: Arc<Mutex<Hub>>,
    tx: Sender<OutMsg>,
    ip: String,
) {
    let mut accept_input = key.trim().to_string();
    accept_input.push_str(WS_GUID);
    let accept = b64_encode(&sha1(accept_input.as_bytes()), false);
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        accept
    );
    // the 101 must go out before any channel frames, so write it directly:
    let mut write_half = match stream.try_clone() {
        Ok(sv) => sv,
        Err(_) => return,
    };
    if write_half.write_all(resp.as_bytes()).is_err() {
        return;
    }
    drop(write_half);

    let mut src = WsSrc { reader, tx: tx.clone(), buf: Vec::new() };
    chat_session(hub, tx, Transport::Ws, ip, &mut src);
}

// ============================= selftest =============================

fn selftest() -> bool {
    let mut ok = true;
    {
        let mut check = |name: &str, cond: bool| {
            println!("  {} {}", if cond { "OK" } else { "FAIL" }, name);
            if !cond {
                ok = false;
            }
        };

        let h = hex(&sha256(b""));
        check("sha256(\"\")", h == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        let h = hex(&sha256(b"abc"));
        check("sha256(\"abc\")", h == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        let h = hex(&sha1(b""));
        check("sha1(\"\")", h == "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        let h = hex(&sha1(b"abc"));
        check("sha1(\"abc\")", h == "a9993e364706816aba3e25717850c26c9cd0d89d");
        let h = hex(&hmac_sha256(b"key", b"The quick brown fox jumps over the lazy dog"));
        check("hmac-sha256 rfc vector", h == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");

        let aes = Aes128::new(&[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ]);
        let pt: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        let ct = aes.encrypt_block(&pt);
        check("aes-128 fips197 encrypt", hex(&ct) == "69c4e0d86a7b0430d8cdb78070b4c55a");
        check("aes-128 fips197 decrypt", aes.decrypt_block(&ct) == pt);

        let f = Fernet::new(&[7u8; 32]);
        let token = f.encrypt(b"hello kiffy");
        check("fernet roundtrip", f.decrypt(&token).as_deref() == Some(&b"hello kiffy"[..]));
        check("fernet tamper rejected", {
            let mut t2 = token.clone();
            let ln = t2.len();
            t2[ln - 1] ^= 1;
            f.decrypt(&t2).is_none()
        });

        let v = j_parse(b"{\"a\":[1,2.5,\"x\\u00e9\"],\"b\":true,\"c\":null}");
        check("json parse", v.is_some());
        if let Some(v) = v {
            let back = j_to_string(&v);
            check("json roundtrip", j_parse(back.as_bytes()) == Some(v));
        }
    }
    ok
}

// ============================= main =============================

fn main() {
    let mut host = "0.0.0.0".to_string();
    let mut port: u16 = std::env::var("PORT")
        .or_else(|_| std::env::var("KIFFY_PORT"))
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8888);
    let mut psk = std::env::var("KIFFY_PSK").ok();
    let mut admin_password = std::env::var("KIFFY_ADMIN_PASSWORD").ok();
    let mut args = std::env::args().skip(1).peekable();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--selftest" => {
                std::process::exit(if selftest() { 0 } else { 1 });
            }
            "--port" => {
                port = args.next().and_then(|v| v.parse().ok()).unwrap_or(port);
            }
            "--host" => {
                host = args.next().unwrap_or(host);
            }
            "--psk" => {
                psk = args.next();
            }
            "--admin-password" => {
                admin_password = args.next();
            }
            _ => {}
        }
    }
    if let Ok(cap) = std::env::var("KIFFY_RATE_CAP") {
        if let Ok(cap) = cap.parse::<f64>() {
            RATE_CAP_X10.store((cap * 10.0) as u64, Ordering::Relaxed);
        }
    }
    if let Ok(rps) = std::env::var("KIFFY_RATE_PER_SEC") {
        if let Ok(rps) = rps.parse::<f64>() {
            RATE_PER_SEC_X1000.store((rps * 1000.0) as u64, Ordering::Relaxed);
        }
    }

    let hub = Arc::new(Mutex::new(Hub::new(admin_password, psk.as_deref())));

    // typing sweeper: expires typing flags after 5s
    {
        let hub = hub.clone();
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(2));
            let now = Instant::now();
            let expired: Vec<String> = {
                let h = hub.lock().unwrap();
                h.typing
                    .iter()
                    .filter(|(_, exp)| **exp < now)
                    .map(|(nm, _)| nm.clone())
                    .collect()
            };
            for name in expired {
                {
                    let mut h = hub.lock().unwrap();
                    h.typing.remove(&name);
                }
                broadcast(&hub, &obj(vec![("t", s("typing")), ("user", s(&name)), ("on", J::Bool(false))]), Some(&name));
            }
        });
    }

    let listener = match TcpListener::bind((host.as_str(), port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: cannot bind {}:{} — {}", host, port, e);
            std::process::exit(1);
        }
    };

    println!("\n  ⚡ KIFFY v2 SERVER (rust)");
    println!("  ==============================================");
    println!("    Web app   http://127.0.1:{}/app.html", port);
    println!("    Landing   http://127.0.1:{}/", port);
    println!("    Port      {}  (chat + web + websocket)", port);
    println!(
        "    Encrypt   {}",
        if psk.is_some() { "PSK (passphrase required)" } else { "plain — start with --psk to encrypt" }
    );
    println!(
        "    Admin     {}",
        if hub.lock().unwrap().admin_password.is_some() { "password set via env/arg" } else { "login as username admin" }
    );
    println!("  ==============================================\n");

    for stream in listener.incoming() {
        match stream {
            Ok(sv) => {
                let hub = hub.clone();
                thread::spawn(move || handle_conn(sv, hub));
            }
            Err(_) => continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_vectors() {
        assert_eq!(hex(&sha256(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(hex(&sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        let m55 = vec![b'a'; 55];
        let m56 = vec![b'a'; 56];
        let m64 = vec![b'a'; 64];
        assert_ne!(sha256(&m55), sha256(&m56));
        assert_ne!(sha256(&m56), sha256(&m64));
    }

    #[test]
    fn sha1_vectors() {
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(hex(&sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn hmac_vector() {
        assert_eq!(
            hex(&hmac_sha256(b"key", b"The quick brown fox jumps over the lazy dog")),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn aes_fips197() {
        let aes = Aes128::new(&[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ]);
        let pt: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        assert_eq!(hex(&aes.encrypt_block(&pt)), "69c4e0d86a7b0430d8cdb78070b4c55a");
        assert_eq!(aes.decrypt_block(&aes.encrypt_block(&pt)), pt);
    }

    #[test]
    fn fernet_roundtrip() {
        let f = Fernet::new(&[9u8; 32]);
        for size in [0usize, 1, 15, 16, 17, 100, 1000] {
            let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let token = f.encrypt(&data);
            assert_eq!(f.decrypt(&token).unwrap(), data, "size {}", size);
        }
    }

    #[test]
    fn b64_vectors() {
        assert_eq!(b64_encode(b"", false), "");
        assert_eq!(b64_encode(b"f", false), "Zg==");
        assert_eq!(b64_encode(b"fo", false), "Zm8=");
        assert_eq!(b64_encode(b"foo", false), "Zm9v");
        assert_eq!(b64_decode("Zm9v").unwrap(), b"foo");
        assert_eq!(b64_decode("Zm8=").unwrap(), b"fo");
    }

    #[test]
    fn json_roundtrip() {
        let src = br#"{"t":"msg","from":"кирилл","text":"привет 😀","ts":123,"arr":[1,2.5,null,true]}"#;
        let v = j_parse(src).expect("parse");
        let back = j_to_string(&v);
        let v2 = j_parse(back.as_bytes()).expect("reparse");
        assert_eq!(v, v2);
        assert_eq!(v.get("from").and_then(J::as_str), Some("кирилл"));
    }

    #[test]
    fn name_validation() {
        assert!(valid_name("kirill_1"));
        assert!(!valid_name("ab"));
        assert!(!valid_name("плохое имя"));
        assert!(!valid_name("way-too-long-username-here"));
    }
}
