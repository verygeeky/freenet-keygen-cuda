// SPDX-License-Identifier: GPL-3.0-or-later
//! website-vanity - CPU vanity search for a Freenet *website contract* key.
//!
//! This is the portable CPU reference for the CUDA search driven by
//! `fn-vanity` / `fn-words`. It is far slower, but needs no GPU.
//!
//! DERIVATION (confirmed against live published contracts, and matches
//! `build_contract_key` in fdev's `website.rs`):
//!
//!     contract_id = blake3( container_code_hash ‖ ed25519_verifying_key )
//!                    32 bytes        ‖        32 bytes      -> 32 bytes -> base58
//!
//! The website container contract is the same for every site, so its code hash
//! is a CONSTANT 32-byte prefix; only the verifying key varies. That makes the
//! inner loop one Ed25519 seed->pubkey plus one blake3 of 64 bytes.
//!
//! WHY THE SEARCH IS ~17x WORSE THAN 58^n LOOKS:
//! base58 of a 32-byte value is 43 or 44 characters, so a given n-char prefix
//! only covers part of the encoding space. `frost` is p = 1/11.3e9, not
//! 1/58^5 = 1/656e6. We therefore match on NUMERIC RANGES over the raw 32
//! bytes rather than by encoding each candidate to base58: same result, and
//! it skips an expensive encode per attempt. A prefix yields up to two ranges
//! (one per encoded length); they are kept separate because the gap between
//! them holds ids that do NOT start with the prefix.
//!
//! NOTE ON WHY WE CANNOT USE THE INCREMENTAL POINT-ADDITION TRICK:
//! classic vanity generators walk P += B, turning a scalar multiplication into
//! a cheap point addition. That produces a raw SCALAR, but an Ed25519 signing
//! key is a SEED: the scalar is SHA512(seed) with clamping, which is not
//! invertible. fdev stores a seed, so every candidate needs a full derivation.
//! This is exactly why the GPU port matters for long prefixes.

use ed25519_dalek::SigningKey;
use num_bigint::BigUint;
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

const B58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// The website container contract's code hash. Constant across all sites.
const CONTAINER_CODE_B58: &str = "7EBvjNgTAteeJBKE3TRHq9vSiDPi8Ex7aKWZfhwtf13r";

type Range = ([u8; 32], [u8; 32]);

/// The 32-byte ranges (big-endian, inclusive) whose base58 encoding starts
/// with `prefix`: one per encoded length (43 or 44 chars) that can hold it.
/// Returns None if the prefix can never occur (bad char, or out of range).
fn prefix_ranges(prefix: &str) -> Option<Vec<Range>> {
    // A leading '1' in base58 encodes a leading zero BYTE, not digit 0, so the
    // numeric-range model does not apply. Such prefixes are not supported.
    if prefix.is_empty() || prefix.starts_with('1') {
        return None;
    }
    let mut n = BigUint::from(0u32);
    for ch in prefix.bytes() {
        let idx = B58.iter().position(|&c| c == ch)?;
        n = n * 58u32 + BigUint::from(idx as u32);
    }
    let max = (BigUint::from(1u32) << 256) - BigUint::from(1u32);
    // Values below 2^248 have a leading zero byte, which base58 renders as an
    // extra leading '1'; none of them can start with a non-'1' prefix.
    let floor = BigUint::from(1u32) << 248;
    let mut out = Vec::new();
    for total in [43usize, 44usize] {
        if total < prefix.len() {
            continue;
        }
        let pad = total - prefix.len();
        let mul = BigUint::from(58u32).pow(pad as u32);
        let l = &n * &mul;
        let h = (&n + BigUint::from(1u32)) * &mul - BigUint::from(1u32);
        if l > max {
            continue;
        }
        let h = if h > max { max.clone() } else { h };
        let l = if l < floor { floor.clone() } else { l };
        if l > h {
            continue;
        }
        out.push((to_32(&l), to_32(&h)));
    }
    out.sort();
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Number of 32-byte values covered by `ranges`.
fn covered(ranges: &[Range]) -> BigUint {
    ranges
        .iter()
        .map(|(l, h)| BigUint::from_bytes_be(h) - BigUint::from_bytes_be(l) + BigUint::from(1u32))
        .sum()
}

fn main() {
    let mut args = std::env::args().skip(1);
    let prefix = args.next().unwrap_or_else(|| {
        eprintln!("usage: website-vanity <base58-prefix>");
        std::process::exit(2);
    });

    let code = bs58::decode(CONTAINER_CODE_B58)
        .into_vec()
        .expect("container code hash must be base58");
    assert_eq!(code.len(), 32, "container code hash must be 32 bytes");

    let ranges = match prefix_ranges(&prefix) {
        Some(r) => r,
        None => {
            eprintln!(
                "prefix {prefix:?} is not searchable: it uses a character outside the \
                 base58 alphabet (no 0, O, I or l), starts with '1' (which base58 uses \
                 for a leading zero byte), or falls outside the range a 32-byte value \
                 can encode to."
            );
            std::process::exit(1);
        }
    };

    let space = (BigUint::from(1u32) << 256) / covered(&ranges);
    println!("prefix        : {prefix:?}");
    println!("container code: {CONTAINER_CODE_B58}");
    println!("expected tries: ~{space}");
    println!("threads       : {}", rayon::current_num_threads());

    // Fixed-width big-endian bounds, so the hot loop compares raw bytes and
    // never allocates or encodes base58 per candidate.

    let found = Arc::new(AtomicBool::new(false));
    let tried = Arc::new(AtomicU64::new(0));
    let t0 = Instant::now();

    // Progress reporter.
    {
        let tried = tried.clone();
        let found = found.clone();
        std::thread::spawn(move || {
            let mut last = 0u64;
            while !found.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_secs(5));
                let n = tried.load(Ordering::Relaxed);
                let dt = t0.elapsed().as_secs_f64();
                eprint!(
                    "\r  {:.2} Mkey/s   tried {:.3e}   {:.0}s      ",
                    (n - last) as f64 / 5.0 / 1e6,
                    n as f64,
                    dt
                );
                use std::io::Write;
                let _ = std::io::stderr().flush();
                last = n;
            }
        });
    }

    let hit = (0..rayon::current_num_threads())
        .into_par_iter()
        .find_map_any(|_| {
            let mut local = 0u64;
            loop {
                if found.load(Ordering::Relaxed) {
                    return None;
                }
                // Generate the SEED directly. ed25519-dalek 2.x wants a
                // rand_core CryptoRngCore for ::generate, and going through the
                // seed is what fdev stores anyway.
                let mut seed = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
                let sk = SigningKey::from_bytes(&seed);
                let vk = sk.verifying_key();

                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&code);
                buf[32..].copy_from_slice(vk.as_bytes());
                let id: [u8; 32] = *blake3::hash(&buf).as_bytes();

                local += 1;
                if local % 4096 == 0 {
                    tried.fetch_add(4096, Ordering::Relaxed);
                }

                if ranges.iter().any(|(lo, hi)| id >= *lo && id <= *hi) {
                    found.store(true, Ordering::Relaxed);
                    return Some((seed, *vk.as_bytes(), id));
                }
            }
        });

    match hit {
        Some((seed, vk, id)) => {
            let enc = bs58::encode(id).into_string();
            println!("\n\nFOUND in {:.1}s", t0.elapsed().as_secs_f64());
            println!("contract key : {enc}");
            assert!(
                enc.starts_with(&prefix),
                "range match disagreed with base58 encoding: bug in prefix_ranges"
            );
            println!("\n--- write to ~/.config/freenet/website-keys/<name>.toml ---");
            println!("[keys]");
            println!("signing_key = \"{}\"", hex(&seed));
            println!("verifying_key = \"{}\"", hex(&vk));
        }
        None => println!("\nno match"),
    }
}

fn to_32(n: &BigUint) -> [u8; 32] {
    let b = n.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(&b);
    out
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every value in a range must encode to a string starting with the
    /// prefix, and the values just outside must not.
    #[test]
    fn ranges_match_base58() {
        for prefix in [
            "2", "3", "4", "5", "Frost", "frost", "H", "J", "z", "abc", "9zz",
        ] {
            let ranges = prefix_ranges(prefix).expect(prefix);
            for (lo, hi) in &ranges {
                for v in [lo, hi] {
                    let enc = bs58::encode(v).into_string();
                    assert!(enc.starts_with(prefix), "{prefix}: {enc}");
                }
                let below = BigUint::from_bytes_be(lo);
                if below > BigUint::from(0u32) {
                    let enc = bs58::encode(to_32(&(below - 1u32))).into_string();
                    assert!(!enc.starts_with(prefix), "{prefix}: below {enc}");
                }
            }
        }
    }

    /// Random ids: "inside some range" must agree exactly with "base58
    /// encoding starts with the prefix", in both directions.
    #[test]
    fn ranges_agree_with_encoding_on_random_ids() {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        for prefix in ["2", "4", "5", "A", "H", "J", "a", "z", "Fr"] {
            let ranges = prefix_ranges(prefix).unwrap();
            for _ in 0..50_000 {
                let mut id = [0u8; 32];
                rng.fill_bytes(&mut id);
                // Bias half the samples toward small values, where the
                // leading-zero-byte edge case lives.
                if id[31] & 1 == 0 {
                    id[0] = 0;
                    id[1] &= 0x3f;
                }
                let inside = ranges.iter().any(|(lo, hi)| id >= *lo && id <= *hi);
                let enc = bs58::encode(id).into_string();
                assert_eq!(inside, enc.starts_with(prefix), "{prefix}: {enc}");
            }
        }
    }

    /// A prefix starting with a low base58 digit has one 43-char range and
    /// one 44-char range; they must not be merged into one span.
    #[test]
    fn low_first_char_gives_two_disjoint_ranges() {
        let r = prefix_ranges("Frost").unwrap();
        assert_eq!(r.len(), 2);
        assert!(r[0].1 < r[1].0);
    }

    #[test]
    fn unreachable_prefixes() {
        assert!(prefix_ranges("0abc").is_none()); // '0' not in base58
        assert!(prefix_ranges("island").is_none()); // 'l' not in base58
        assert!(prefix_ranges("1abc").is_none()); // leading '1' = zero byte
    }

    /// Contract id for the RFC 8032 TEST 1 public key under the current
    /// website container code hash (same vector as cuda/test_blake3.cpp).
    #[test]
    fn contract_id_vector() {
        let code = bs58::decode(CONTAINER_CODE_B58).into_vec().unwrap();
        let sk = SigningKey::from_bytes(&[
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ]);
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&code);
        buf[32..].copy_from_slice(sk.verifying_key().as_bytes());
        let id = blake3::hash(&buf);
        assert_eq!(
            bs58::encode(id.as_bytes()).into_string(),
            "AuYwQj7QWUf8nrxEA1DBxZLnCYcCqUD9fzE7zaQFTjuz"
        );
    }
}
