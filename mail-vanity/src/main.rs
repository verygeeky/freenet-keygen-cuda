// SPDX-License-Identifier: GPL-3.0-or-later
//! mail-vanity - grind a Freenet Mail identity whose inbox address starts with
//! a chosen word.
//!
//! The address a Freenet Mail user publishes as their contact token is an inbox
//! `ContractInstanceId`. From `freenet/mail` (`ui/src/app/address_book.rs` ->
//! `ui/src/inbox.rs::inbox_key_for`) and freenet-stdlib 0.3.5
//! (`contract_interface/key.rs::ContractKey::from_params`):
//!
//!     address = bs58( blake3( inbox_code_hash[32] || serde_json(InboxParams) ) )
//!     InboxParams = { "pub_key": <ML-DSA-65 verifying key, 1952 bytes> }
//!
//! serde_json renders `Vec<u8>` as an array of decimal integers, so the hashed
//! parameter blob is ~6974 bytes rather than 1952. Each candidate therefore
//! costs one full ML-DSA-65 keygen plus a ~7 KB blake3 — about two orders of
//! magnitude more work per try than the Ed25519 website-key search in
//! `fn-words`, and there is no GPU kernel for it.
//!
//! IMPORTANT: the address is keyed on `inbox_code_hash`, the blake3 of the
//! inbox contract WASM. That hash rotates whenever the inbox contract is
//! rebuilt (`docs/qa/manual-test-inventory.md` — "Per-identity inbox migration
//! on contract id rotation (#213)"), and a rotation changes the address of an
//! already-existing identity. A ground-out vanity address is only valid for the
//! code hash it was ground against.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use ml_dsa::signature::Keypair;
use ml_dsa::{KeyGen, MlDsa65};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

const B58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// ── identity export format ───────────────────────────────────────────────────
// Mirrors `IdentityBackup` / `StoredIdentityKeys` in freenet/mail
// `ui/src/app/login.rs`. Field order here is the order the app emits.

#[derive(Serialize, Deserialize)]
struct IdentityBackup {
    version: u32,
    alias: String,
    description: String,
    keys: StoredIdentityKeys,
}

#[derive(Serialize, Deserialize)]
struct StoredIdentityKeys {
    ml_dsa_seed: Vec<u8>,
    ml_kem_seed: Vec<u8>,
}

/// `IDENTITY_BACKUP_VERSION` in `ui/src/app/login.rs`.
const IDENTITY_BACKUP_VERSION: u32 = 2;

/// The exact struct the inbox contract serialises into `Parameters`
/// (`contracts/inbox/src/lib.rs`). Used only to prove the hand-rolled encoder
/// below is byte-identical to serde_json's output.
#[derive(Serialize)]
struct InboxParams {
    pub_key: Vec<u8>,
}

// ── params encoding ──────────────────────────────────────────────────────────

/// Decimal rendering of every u8, so the hot loop never formats.
struct DecTable {
    buf: [[u8; 3]; 256],
    len: [u8; 256],
}

impl DecTable {
    fn new() -> Self {
        let mut t = DecTable {
            buf: [[0u8; 3]; 256],
            len: [0u8; 256],
        };
        for i in 0..256usize {
            let s = i.to_string();
            t.len[i] = s.len() as u8;
            t.buf[i][..s.len()].copy_from_slice(s.as_bytes());
        }
        t
    }
}

/// Write `{"pub_key":[a,b,c,...]}` into `out`, matching `serde_json::to_vec`.
fn encode_params(vk: &[u8], tbl: &DecTable, out: &mut Vec<u8>) {
    out.clear();
    out.extend_from_slice(b"{\"pub_key\":[");
    for (i, &b) in vk.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        let n = tbl.len[b as usize] as usize;
        out.extend_from_slice(&tbl.buf[b as usize][..n]);
    }
    out.extend_from_slice(b"]}");
}

/// address = blake3(code_hash || params)
fn derive_id(code_hash: &[u8; 32], params: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(code_hash);
    h.update(params);
    *h.finalize().as_bytes()
}

fn vk_bytes_from_seed(seed: &[u8; 32]) -> Vec<u8> {
    let s = ml_dsa::Seed::try_from(&seed[..]).expect("32-byte seed");
    let kp = MlDsa65::from_seed(&s);
    kp.verifying_key().encode().to_vec()
}

// ── base58 prefix ranges ─────────────────────────────────────────────────────
// Same construction as fn-words: a 32-byte value base58-encodes to 43 or 44
// characters, and a given prefix sits at a different magnitude in each, so a
// word yields up to two numeric ranges over the raw 32-byte integer. Comparing
// the digest against a range beats base58-encoding every candidate.

type Range = ([u8; 32], [u8; 32]);

fn b58_index(c: u8) -> Option<u32> {
    B58.iter().position(|&x| x == c).map(|p| p as u32)
}

/// Big-endian 256-bit arithmetic, just enough for range construction.
fn mul_small(v: &mut [u8; 32], m: u32) -> bool {
    let mut carry: u64 = 0;
    for i in (0..32).rev() {
        let cur = v[i] as u64 * m as u64 + carry;
        v[i] = (cur & 0xff) as u8;
        carry = cur >> 8;
    }
    carry != 0 // overflow past 2^256
}

fn add_small(v: &mut [u8; 32], a: u32) -> bool {
    let mut carry = a as u64;
    for i in (0..32).rev() {
        if carry == 0 {
            return false;
        }
        let cur = v[i] as u64 + carry;
        v[i] = (cur & 0xff) as u8;
        carry = cur >> 8;
    }
    carry != 0
}

fn sub_one(v: &mut [u8; 32]) {
    for i in (0..32).rev() {
        if v[i] == 0 {
            v[i] = 0xff;
        } else {
            v[i] -= 1;
            return;
        }
    }
}

/// Ranges of 32-byte values whose base58 encoding starts with `word`.
fn word_ranges(word: &str) -> Result<Vec<Range>, String> {
    let bytes = word.as_bytes();
    // A leading '1' in base58 encodes a leading zero BYTE rather than digit 0,
    // so the numeric-range model below does not cover it.
    if bytes.is_empty() || bytes[0] == b'1' {
        return Err(format!(
            "'{word}': prefixes starting with '1' (base58 for a zero byte) are not supported"
        ));
    }
    for &c in bytes {
        if b58_index(c).is_none() {
            return Err(format!(
                "'{}' is not in the base58 alphabet — an address can never start with '{}'",
                c as char, word
            ));
        }
    }
    let mut out = Vec::new();
    for total in [43usize, 44usize] {
        if total < bytes.len() {
            continue;
        }
        let pad = total - bytes.len();

        // lo = value(word) * 58^pad, hi = (value(word)+1) * 58^pad - 1
        let mut lo = [0u8; 32];
        let mut lo_over = false;
        for &c in bytes {
            lo_over |= mul_small(&mut lo, 58);
            lo_over |= add_small(&mut lo, b58_index(c).unwrap());
        }
        let mut hi = lo;
        let mut hi_over = lo_over | add_small(&mut hi, 1);
        for _ in 0..pad {
            lo_over |= mul_small(&mut lo, 58);
            if !hi_over {
                hi_over |= mul_small(&mut hi, 58);
            }
        }
        if lo_over {
            // The whole range sits above 2^256: unreachable at this length.
            continue;
        }
        if hi_over {
            // Only the top of the range is past 2^256: clamp to 2^256 - 1.
            hi = [0xff; 32];
        } else {
            sub_one(&mut hi);
        }
        // Values below 2^248 have a leading zero byte, which base58 renders as
        // an extra leading '1', so none of them can start with `word`.
        if hi[0] == 0 {
            continue;
        }
        if lo[0] == 0 {
            lo = [0u8; 32];
            lo[0] = 1;
        }
        out.push((lo, hi));
    }
    if out.is_empty() {
        return Err(format!("no reachable 32-byte value starts with '{word}'"));
    }
    Ok(out)
}

fn merge(mut spans: Vec<Range>) -> Vec<Range> {
    spans.sort_by(|a, b| a.0.cmp(&b.0));
    let mut merged: Vec<Range> = Vec::new();
    for (lo, hi) in spans {
        match merged.last_mut() {
            // Overlapping ranges must be merged: a short word's range encloses
            // every longer word sharing that prefix, and a binary search over
            // unmerged ranges can miss the enclosing one and report a false
            // miss on a real hit.
            Some(last) if lo <= last.1 => {
                if hi > last.1 {
                    last.1 = hi;
                }
            }
            _ => merged.push((lo, hi)),
        }
    }
    merged
}

fn in_ranges(id: &[u8; 32], ranges: &[Range]) -> bool {
    match ranges.binary_search_by(|r| r.0.cmp(id)) {
        Ok(_) => true,
        Err(0) => false,
        Err(i) => *id <= ranges[i - 1].1,
    }
}

/// Fraction of the 2^256 space covered, as f64 — for the ETA.
fn coverage(ranges: &[Range]) -> f64 {
    let top = |v: &[u8; 32]| {
        // Leading 8 bytes are plenty of precision for an estimate.
        let mut x = 0f64;
        for &b in v.iter().take(10) {
            x = x * 256.0 + b as f64;
        }
        x
    };
    let space = 256f64.powi(10);
    ranges
        .iter()
        .map(|(lo, hi)| top(hi) - top(lo) + 1.0)
        .sum::<f64>()
        / space
}

fn decode_code_hash(s: &str) -> Result<[u8; 32], String> {
    let mut out = [0u8; 32];
    bs58::decode(s.trim())
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .onto(&mut out)
        .map_err(|e| format!("bad code hash '{s}': {e}"))?;
    Ok(out)
}

fn encode_id(id: &[u8; 32]) -> String {
    bs58::encode(id)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_string()
}

// ── cli ──────────────────────────────────────────────────────────────────────

const USAGE: &str = "\
mail-vanity — grind a Freenet Mail identity with a chosen inbox-address prefix

  addr    --identity <file.json> --code-hash <bs58>
          Derive the inbox address for an existing identity export. Use this to
          confirm a code hash reproduces an address you already know.

  scan    --identity <file.json> --target <bs58 address> --hashes <file>
          Try every candidate code hash (one bs58 hash per line) against a known
          identity + address pair. Recovers which inbox build an address is on.

  extract --identity <file.json> --target <bs58 address> --file <binary>
          Pull every base58-looking 32-byte constant out of a binary (the mail
          webapp wasm carries INBOX_CODE_HASH as an `include_str!` constant) and
          report the one that reproduces the address. This is how you recover
          the real code hash: it is NOT reproducible from source, because the
          inbox wasm embeds the release builder's absolute paths.

  grind   --code-hash <bs58> [--prefix <word> | --words <file> [--min-len N]]
          [--threads N] [--alias NAME] [--description TEXT] [--out FILE]
          Search for a new identity whose address starts with the prefix (or any
          word from the list). Writes an importable identity JSON on success.
";

struct Args {
    cmd: String,
    map: std::collections::HashMap<String, String>,
}

impl Args {
    fn parse() -> Result<Args, String> {
        let mut it = std::env::args().skip(1);
        let cmd = it.next().ok_or_else(|| USAGE.to_string())?;
        let mut map = std::collections::HashMap::new();
        while let Some(k) = it.next() {
            let key = k.trim_start_matches("--").to_string();
            let val = it.next().unwrap_or_else(|| "true".into());
            map.insert(key, val);
        }
        Ok(Args { cmd, map })
    }
    fn get(&self, k: &str) -> Result<&str, String> {
        self.map
            .get(k)
            .map(|s| s.as_str())
            .ok_or_else(|| format!("missing --{k}\n\n{USAGE}"))
    }
    fn opt(&self, k: &str) -> Option<&str> {
        self.map.get(k).map(|s| s.as_str())
    }
}

fn load_identity(path: &str) -> Result<IdentityBackup, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    serde_json::from_str(&raw).map_err(|e| format!("parse {path}: {e}"))
}

fn seed32(v: &[u8]) -> Result<[u8; 32], String> {
    if v.len() != 32 {
        return Err(format!("ml_dsa_seed must be 32 bytes, got {}", v.len()));
    }
    let mut s = [0u8; 32];
    s.copy_from_slice(v);
    Ok(s)
}

/// Assert the hand-rolled encoder matches serde_json byte for byte. Cheap, and
/// it is the one assumption the whole search rests on.
fn selftest(tbl: &DecTable) -> Result<(), String> {
    let vk = vk_bytes_from_seed(&[7u8; 32]);
    let mut fast = Vec::new();
    encode_params(&vk, tbl, &mut fast);
    let slow = serde_json::to_vec(&InboxParams {
        pub_key: vk.clone(),
    })
    .map_err(|e| e.to_string())?;
    if fast != slow {
        return Err("params encoder disagrees with serde_json".into());
    }
    if vk.len() != 1952 {
        return Err(format!("expected 1952-byte ML-DSA-65 vk, got {}", vk.len()));
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse()?;
    let tbl = DecTable::new();
    selftest(&tbl)?;

    match args.cmd.as_str() {
        "addr" => {
            let id = load_identity(args.get("identity")?)?;
            let ch = decode_code_hash(args.get("code-hash")?)?;
            let vk = vk_bytes_from_seed(&seed32(&id.keys.ml_dsa_seed)?);
            let mut params = Vec::new();
            encode_params(&vk, &tbl, &mut params);
            println!("alias        : {}", id.alias);
            println!("vk bytes     : {}", vk.len());
            println!("params bytes : {}", params.len());
            println!("address      : {}", encode_id(&derive_id(&ch, &params)));
            Ok(())
        }

        "scan" => {
            let id = load_identity(args.get("identity")?)?;
            let target = args.get("target")?.trim().to_string();
            let list = fs::read_to_string(args.get("hashes")?).map_err(|e| e.to_string())?;
            let vk = vk_bytes_from_seed(&seed32(&id.keys.ml_dsa_seed)?);
            let mut params = Vec::new();
            encode_params(&vk, &tbl, &mut params);

            let mut tried = 0usize;
            for line in list.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let Ok(ch) = decode_code_hash(line) else {
                    eprintln!("skip (not bs58-32): {line}");
                    continue;
                };
                tried += 1;
                let got = encode_id(&derive_id(&ch, &params));
                let hit = got == target;
                println!(
                    "{} {} -> {}",
                    if hit { "MATCH" } else { "     " },
                    line,
                    got
                );
                if hit {
                    println!("\ninbox code hash for {target} is {line}");
                    return Ok(());
                }
            }
            Err(format!("no match among {tried} candidate code hashes"))
        }

        "extract" => {
            let id = load_identity(args.get("identity")?)?;
            let target = args.get("target")?.trim().to_string();
            let path = args.get("file")?;
            let blob = fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
            let vk = vk_bytes_from_seed(&seed32(&id.keys.ml_dsa_seed)?);
            let mut params = Vec::new();
            encode_params(&vk, &tbl, &mut params);

            // Maximal runs of base58 characters; any 43/44-char window inside a
            // run is a candidate encoding of a 32-byte hash.
            let mut cands: Vec<String> = Vec::new();
            let mut run_start = 0usize;
            for i in 0..=blob.len() {
                let is_b58 = i < blob.len() && b58_index(blob[i]).is_some();
                if !is_b58 {
                    let run = &blob[run_start..i];
                    if run.len() >= 43 {
                        for len in [43usize, 44] {
                            for w in run.windows(len) {
                                if let Ok(s) = std::str::from_utf8(w) {
                                    cands.push(s.to_string());
                                }
                            }
                        }
                    }
                    run_start = i + 1;
                }
            }
            cands.sort();
            cands.dedup();
            eprintln!("{} base58 candidate(s) in {path}", cands.len());

            for c in &cands {
                let Ok(ch) = decode_code_hash(c) else {
                    continue;
                };
                if encode_id(&derive_id(&ch, &params)) == target {
                    println!("inbox code hash: {c}");
                    println!("reproduces     : {target}");
                    return Ok(());
                }
            }
            Err(format!(
                "no candidate in {path} reproduces {target}\n\
                 (either the wrong binary, or the address predates the current inbox build)"
            ))
        }

        "grind" => grind(&args, &tbl),

        other => Err(format!("unknown command '{other}'\n\n{USAGE}")),
    }
}

fn grind(args: &Args, tbl: &DecTable) -> Result<(), String> {
    let code_hash = decode_code_hash(args.get("code-hash")?)?;
    if let Some(p) = args.opt("out") {
        if std::path::Path::new(p).exists() {
            return Err(format!(
                "{p} already exists; refusing to overwrite a key file"
            ));
        }
    }

    // Target set: one prefix, or any word from a list (vastly cheaper).
    let (ranges, words) = if let Some(p) = args.opt("prefix") {
        (merge(word_ranges(p)?), vec![p.to_string()])
    } else if let Some(f) = args.opt("words") {
        let min_len: usize = args.opt("min-len").unwrap_or("7").parse().unwrap_or(7);
        let raw = fs::read_to_string(f).map_err(|e| format!("read {f}: {e}"))?;
        let words: Vec<String> = raw
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|w| {
                w.len() >= min_len
                    && !w.starts_with('1')
                    && w.bytes().all(|c| b58_index(c).is_some())
            })
            .collect();
        if words.is_empty() {
            return Err("no usable words after filtering".into());
        }
        let mut spans = Vec::new();
        for w in &words {
            spans.extend(word_ranges(w)?);
        }
        (merge(spans), words)
    } else {
        return Err(format!("need --prefix or --words\n\n{USAGE}"));
    };

    let cov = coverage(&ranges);
    let expected = 1.0 / cov;
    let threads: usize = args
        .opt("threads")
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(rayon::current_num_threads);

    eprintln!("code hash     : {}", encode_id(&code_hash));
    eprintln!(
        "targets       : {} word(s), {} merged range(s)",
        words.len(),
        ranges.len()
    );
    eprintln!("expected tries: ~{:.3e}", expected);
    eprintln!("threads       : {threads}");
    eprintln!("searching...  (Ctrl-C to stop)");

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .map_err(|e| e.to_string())?;

    let found = Arc::new(AtomicBool::new(false));
    let tries = Arc::new(AtomicU64::new(0));
    let result: Arc<std::sync::Mutex<Option<([u8; 32], [u8; 32])>>> =
        Arc::new(std::sync::Mutex::new(None));
    let start = Instant::now();

    // Progress reporter.
    {
        let found = found.clone();
        let tries = tries.clone();
        std::thread::spawn(move || {
            let mut last = 0u64;
            while !found.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_secs(2));
                let n = tries.load(Ordering::Relaxed);
                let el = start.elapsed().as_secs_f64();
                eprint!(
                    "\r  {:.0} key/s   tried {:.3e}   {:.0}s          ",
                    (n - last) as f64 / 2.0,
                    n as f64,
                    el
                );
                last = n;
            }
        });
    }

    pool.install(|| {
        (0..threads).into_par_iter().for_each(|t| {
            let mut rng = ChaCha12Rng::from_os_rng();
            let mut seed = [0u8; 32];
            let mut params = Vec::with_capacity(8192);
            let mut local = 0u64;
            loop {
                if found.load(Ordering::Relaxed) {
                    return;
                }
                rng.fill_bytes(&mut seed);
                let vk = vk_bytes_from_seed(&seed);
                encode_params(&vk, tbl, &mut params);
                let id = derive_id(&code_hash, &params);

                local += 1;
                if local % 256 == 0 {
                    tries.fetch_add(256, Ordering::Relaxed);
                }

                if in_ranges(&id, &ranges) {
                    if !found.swap(true, Ordering::SeqCst) {
                        *result.lock().unwrap() = Some((seed, id));
                    }
                    let _ = t;
                    return;
                }
            }
        });
    });

    let (seed, id) = result
        .lock()
        .unwrap()
        .take()
        .ok_or_else(|| "search ended without a hit".to_string())?;
    let addr = encode_id(&id);
    let elapsed = start.elapsed().as_secs_f64();

    // Never trust the range check alone — re-derive from the seed and confirm
    // the address really does start with a word we asked for.
    let vk = vk_bytes_from_seed(&seed);
    let mut params = Vec::new();
    encode_params(&vk, tbl, &mut params);
    let recheck = encode_id(&derive_id(&code_hash, &params));
    if recheck != addr {
        return Err("BUG: re-derivation disagreed with the search result".into());
    }
    let mut hits: Vec<&String> = words
        .iter()
        .filter(|w| addr.starts_with(w.as_str()))
        .collect();
    hits.sort_by_key(|w| std::cmp::Reverse(w.len()));
    let matched = hits
        .first()
        .ok_or_else(|| format!("BUG: {addr} matched no word in the target list"))?;

    // ML-KEM seed is independent of the address — the inbox id is derived from
    // the ML-DSA verifying key alone — so fresh randomness is all it needs.
    let mut kem_seed = vec![0u8; 64];
    ChaCha12Rng::from_os_rng().fill_bytes(&mut kem_seed);

    let backup = IdentityBackup {
        version: IDENTITY_BACKUP_VERSION,
        alias: args.opt("alias").unwrap_or("vanity").to_string(),
        description: args.opt("description").unwrap_or("").to_string(),
        keys: StoredIdentityKeys {
            ml_dsa_seed: seed.to_vec(),
            ml_kem_seed: kem_seed,
        },
    };
    let json = serde_json::to_string_pretty(&backup).map_err(|e| e.to_string())?;

    eprintln!("\nFOUND in {elapsed:.1}s");
    println!();
    println!("address      : {addr}");
    println!("matched word : {matched}");
    println!("ml_dsa_seed  : {}", hex(&seed));
    println!("code hash    : {}", encode_id(&code_hash));

    match args.opt("out") {
        Some(p) => {
            let path = PathBuf::from(p);
            write_private(&path, (json + "\n").as_bytes())
                .map_err(|e| format!("write {p}: {e}"))?;
            println!("\nwrote {}", path.display());
        }
        None => {
            println!();
            println!("{json}");
        }
    }
    Ok(())
}

/// Write a file that holds secret key material: refuse to overwrite, and on
/// Unix create it readable by the owner only.
fn write_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(data)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn params_encoder_matches_serde_json() {
        selftest(&DecTable::new()).unwrap();
    }

    /// Random ids: membership in the merged ranges must agree exactly with
    /// "base58 encoding starts with one of the words".
    #[test]
    fn ranges_agree_with_encoding() {
        let words = ["2", "4", "5", "A", "H", "J", "a", "v", "z", "Fr", "vi"];
        let mut spans = Vec::new();
        for w in words {
            spans.extend(word_ranges(w).unwrap());
        }
        let ranges = merge(spans);
        let mut rng = rand::rng();
        for i in 0..200_000u32 {
            let mut id: [u8; 32] = rng.random();
            if i % 2 == 0 {
                // Exercise the leading-zero-byte edge case.
                id[0] = 0;
                id[1] &= 0x3f;
            }
            let enc = encode_id(&id);
            let want = words.iter().any(|w| enc.starts_with(w));
            assert_eq!(in_ranges(&id, &ranges), want, "{enc}");
        }
    }

    #[test]
    fn rejects_unsearchable_words() {
        assert!(word_ranges("island").is_err()); // 'l' not in base58
        assert!(word_ranges("1abc").is_err()); // leading '1' = zero byte
    }

    /// ML-DSA-65 seed of 32 zero bytes, code hash of 32 zero bytes. The
    /// expected address was computed independently with dilithium-py 1.4.0
    /// (ML_DSA_65.key_derive), Python's json module and the blake3 package.
    #[test]
    fn address_vector() {
        let tbl = DecTable::new();
        let vk = vk_bytes_from_seed(&[0u8; 32]);
        let mut params = Vec::new();
        encode_params(&vk, &tbl, &mut params);
        let addr = encode_id(&derive_id(&[0u8; 32], &params));
        assert_eq!(addr, ADDRESS_VECTOR);
    }

    const ADDRESS_VECTOR: &str = "3qVDeZ3WdN8Pb5cnJ5irACnfjtndNFvn5ehMQCLTRxFQ";
}
