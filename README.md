# freenet-keygen-cuda

Vanity key grinders for [Freenet](https://freenet.org/). They search for keys
whose public address starts with a word you choose:

- website contract keys (Ed25519), on an NVIDIA GPU with CUDA or on the CPU;
- Freenet Mail inbox addresses (ML-DSA-65), on the CPU.

Everything runs locally. Keys are generated on your machine and nothing is sent
over the network.

## Contents

| Path | What it is |
|---|---|
| `fn-vanity` | Python wrapper: GPU search for a website key starting with one prefix |
| `fn-words` | Python wrapper: GPU search for a website key starting with any word from a list |
| `cuda/website-vanity.cu` | The CUDA search binary the wrappers call |
| `cuda/ed25519_fast.cuh`, `cuda/blake3_64.cuh` | Ed25519 key derivation and single-block BLAKE3 for the GPU |
| `cuda/test_blake3.cpp` | Host-side known-answer test for the BLAKE3 code |
| `src/main.rs` (`website-vanity`) | CPU version of the website key search, no GPU needed |
| `mail-vanity/` | Freenet Mail identity grinder; see [mail-vanity/README.md](mail-vanity/README.md) |
| `words-b58.txt` | 7,664 common English words that are valid base58 (built from SCOWL) |
| `tools/make-wordlist.sh` | Rebuilds `words-b58.txt` from the SCOWL release |

## Background

### Freenet

The Freenet these tools target is the Rust platform developed at
[freenet/freenet-core](https://github.com/freenet/freenet-core). It began in
2019 as a ground-up redesign by Ian Clarke, internally named "Locutus". In
March 2023 Locutus took over the Freenet name, and the original Java Freenet,
whose development started in 1999, continued as
[Hyphanet](https://www.hyphanet.org/). See the
[Freenet FAQ](https://freenet.org/about/faq/) and
[history page](https://freenet.org/about/history/). The keys generated here are
for the new Freenet, not for Hyphanet.

On Freenet, a contract is identified by its **contract key**. The key is a hash
of the contract's WebAssembly code plus its parameters, and it is shown as a
base58 string of 43 or 44 characters. When the parameters are just a public
key, as they are for websites and Freenet Mail inboxes, the contract key works
as the key owner's address.

### What a vanity address is

A normal address is random-looking, for example
`AuYwQj7QWUf8nrxEA1DBxZLnCYcCqUD9fzE7zaQFTjuz`. A vanity address starts with
something readable, like `frost…`. There is no shortcut to finding one: you
generate key pairs, compute each address, and keep going until one matches.
Each extra character multiplies the work by about 58.

## How the addresses are derived

### Website contract keys

A website published with `fdev website publish` lives in a container contract
that is the same for every site. The site's Ed25519 verifying key is the
contract parameter:

```
contract_key = base58( blake3( container_code_hash[32] || ed25519_verifying_key[32] ) )
```

`container_code_hash` is the BLAKE3 hash of `website_contract.wasm`, the
container that fdev embeds (`crates/fdev/resources/website_contract.wasm` in
freenet-core). For the version current at the time of writing it is:

```
7EBvjNgTAteeJBKE3TRHq9vSiDPi8Ex7aKWZfhwtf13r
```

This constant is hard-coded in `fn-vanity`, `fn-words` and `src/main.rs`. It
was checked two ways: against live published sites, and by hashing the wasm
file in freenet-core directly. The derivation matches `build_contract_key` in
fdev's `website.rs`. The signing key is stored in
`~/.config/freenet/website-keys/<name>.toml` as

```toml
[keys]
signing_key = "<64 hex chars: the 32-byte Ed25519 seed>"
verifying_key = "<64 hex chars>"
```

and the tools print a block in exactly this format.

Since the address only depends on 64 bytes of input, each candidate costs one
Ed25519 key derivation (SHA-512 plus a fixed-base scalar multiplication) and a
single BLAKE3 compression. That is what makes a GPU search fast.

### Freenet Mail addresses

A [Freenet Mail](https://github.com/freenet/mail) contact address is the
contract key of the user's inbox contract. The parameter is the identity's
ML-DSA-65 verifying key (FIPS 204), serialized as JSON:

```
address = base58( blake3( inbox_code_hash[32] || serde_json({"pub_key": [ML-DSA-65 vk, 1952 bytes]}) ) )
```

Each candidate costs a full ML-DSA-65 key generation plus a BLAKE3 over about
7 KB of JSON. That is roughly 2000 times more work than a website key, and
there's no GPU kernel for it. Details are in
[mail-vanity/README.md](mail-vanity/README.md).

### Base58 quirks that affect the search

- The alphabet has no `0`, `O`, `I` or `l`, so words containing those letters
  can never appear.
- A 32-byte value encodes to 43 or 44 characters, and a 44-character encoding
  can only start with `1` to `J`. A prefix starting with a later character
  (every lowercase letter, for example) only occurs in 43-character addresses.
  That makes it about 17 times harder than 58^n suggests: a 5-letter lowercase
  prefix takes about 1.1e10 tries, not 6.6e8.
- A leading `1` stands for a leading zero byte, so prefixes starting with `1`
  aren't supported.

The tools never base58-encode candidates. They turn the prefix into one or two
numeric ranges over the raw 32-byte hash and compare against those, then check
the base58 prefix of any hit on the host before reporting it.

## The code hash caveat

**A vanity address is only valid for the contract code it was ground against.**
Both address types start with a code hash, and if that code changes, the same
key gets a different address.

- Website keys: the container code hash changes whenever fdev ships a
  different `website_contract.wasm`. If that happens, update `CONTAINER` in
  `fn-vanity` and `fn-words` and `CONTAINER_CODE_B58` in `src/main.rs`. Before
  publishing with a ground key, always check the address with
  `fdev website list` (see [Verify before you use a key](#verify-before-you-use-a-key)).
- Freenet Mail: the inbox contract hash rotates between Freenet Mail
  releases, and a rotation changes the address of every existing identity
  (the app migrates identities to the new inbox; see freenet/mail issues
  [#199](https://github.com/freenet/mail/issues/199) and
  [#213](https://github.com/freenet/mail/issues/213)). The hash also can't be
  reproduced by building from source, because the inbox wasm embeds absolute paths
  from the release build machine, so your own build gets a different hash.
  `mail-vanity extract` recovers the real hash from the shipped webapp wasm. A
  vanity mail address lasts until the next inbox contract change and then it's
  gone.

## Requirements

- Linux (tested on x86_64). The CUDA part needs an NVIDIA GPU and the CUDA
  Toolkit with `nvcc`. The default build targets `sm_120` (RTX 50 series),
  which needs CUDA 12.8 or newer. Other GPUs work with a different `ARCH`.
- A C++ compiler (`g++`) for the host-side test.
- Rust (stable, 2021 edition) and cargo for `website-vanity` and `mail-vanity`.
- Python 3 with the `base58` package for `fn-vanity` and `fn-words`.

Tested with CUDA 13.4, rustc/cargo 1.97, Python 3.14 and g++ on CachyOS.

## Building

```sh
git clone https://github.com/verygeeky/freenet-keygen-cuda
cd freenet-keygen-cuda

# CUDA searcher -> cuda/website-vanity-gpu
make                     # RTX 50 series (sm_120)
make ARCH=sm_89          # RTX 40 series; sm_86 for RTX 30

# Host-side BLAKE3 test (no GPU needed)
make test

# Python environment for fn-vanity / fn-words (they run .venv/bin/python)
make venv                # python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# Rust tools
make rust                # target/release/website-vanity, mail-vanity/target/release/mail-vanity
make rust-test           # unit tests for both crates
```

Without make:

```sh
nvcc -O3 -arch=sm_120 cuda/website-vanity.cu -o cuda/website-vanity-gpu
g++ -O2 -x c++ cuda/test_blake3.cpp -o cuda/test_blake3 && cuda/test_blake3
cargo build --release
(cd mail-vanity && cargo build --release)
```

The GPU binary runs two self-tests on the device every time it starts. They
check the Ed25519 code against known public keys and the BLAKE3 code against a
reference digest. If either fails, it exits before searching.

## Usage

### Website key, one prefix (GPU)

```sh
./fn-vanity frost
```

It prints the expected number of tries, shows progress, and on a hit prints
the contract key and a `[keys]` block to save as
`~/.config/freenet/website-keys/<name>.toml`.

### Website key, any word from a list (GPU)

```sh
./fn-words --min-len 7                  # any word of 7+ letters from words-b58.txt
./fn-words --min-len 6 --max-len 8
./fn-words --words my-words.txt --min-len 5
```

Allowing any of a few thousand words is thousands of times cheaper than one
fixed word, and you still get a readable address.

### Website key without a GPU

```sh
cargo run --release -- frost            # or target/release/website-vanity frost
```

### Freenet Mail identity

```sh
cd mail-vanity
cargo run --release -- grind --code-hash <inbox code hash> --prefix fros --out my-identity.json
cargo run --release -- grind --code-hash <inbox code hash> --words ../words-b58.txt --min-len 5 --out my-identity.json
```

Then import `my-identity.json` in the Freenet Mail app. See
[mail-vanity/README.md](mail-vanity/README.md) for how to get the current inbox
code hash, and for the `addr`, `scan` and `extract` subcommands.

### Tuning the GPU grid

`cuda/website-vanity-gpu` reads three optional environment variables:
`VANITY_THREADS` (threads per block, default 256), `VANITY_BLOCKS` (default 16
× the number of SMs) and `VANITY_WORK` (keys per thread per launch, default
48).

## Performance

Measured on one machine for this README: an NVIDIA GeForce RTX 5090 (170 SMs)
and an Intel Core Ultra 9 285K (24 threads).

| Tool | Rate |
|---|---|
| `fn-vanity` / `fn-words` (RTX 5090, default grid) | ~190 million keys/s |
| `website-vanity` (CPU, 24 threads) | ~1.6 million keys/s |
| `mail-vanity grind` (CPU, 24 threads) | ~90,000 keys/s |

Expected time for a website key on the RTX 5090, for a prefix that starts with
a lowercase letter:

| prefix length | example | expected tries | time at 190 Mkey/s |
|---|---|---|---|
| 4 | `fros` | 2.0e8 | ~1 s |
| 5 | `frost` | 1.1e10 | ~1 min |
| 6 | `frosty` | 6.6e11 | ~1 hour |
| 7 | `frosted` | 3.8e13 | ~2.3 days |

With `fn-words` and the bundled list:

| `--min-len` | words | expected tries | time at 190 Mkey/s |
|---|---|---|---|
| 6 | 5,628 | 5.4e8 | ~3 s |
| 7 | 4,434 | 3.1e10 | ~3 min |
| 8 | 3,203 | 2.0e12 | ~3 hours |

A prefix starting with an uppercase letter or digit from `2` to `J` is about 17
times cheaper, because it can also appear in 44-character addresses. The tools
print the exact expected count before they start. Real runs vary a lot around
the average.

## Security

These tools make private keys. Whoever holds the key controls the address.

- Keys never leave your machine. Nothing here uses the network. The GPU
  search takes a 32-byte random base from `/dev/urandom` and derives each
  candidate seed as `SHA-512(base || counter)[:32]`. The CPU tools use the
  operating system's RNG (`OsRng`, or ChaCha12 seeded from it).
- The output contains the secret. `fn-vanity` and `fn-words` print the
  seed (`signing_key`) to the terminal. `mail-vanity grind` prints it and also
  writes it into the identity JSON. Don't run these where terminal output is
  logged or shared (CI, screen sharing, a shared tmux, a pasted bug report). If
  you tee the output to a file, that file holds the key: keep it private and
  delete it after importing. This repository's `.gitignore` excludes `*.log`
  and `*identity*.json` so logs don't end up in a commit by accident.
- Never share the seed or the identity file. Anyone who has the website
  `signing_key` can publish updates to your site. Anyone who has the Freenet
  Mail identity JSON can read your mail and send as you.
- Back the key up. Freenet's docs say a lost website signing key leaves the site
  permanently read-only, with no recovery. Store the key file, or the identity
  export, in a password manager or on encrypted storage.
- `mail-vanity --out` creates the file with mode 0600 and won't overwrite
  an existing file. For website keys, create the `.toml` yourself with
  `umask 077`.
- Use a fresh key. Don't reuse a key that has been printed somewhere you
  don't control.

### Verify before you use a key

Every tool checks its own hit on the host before reporting it. You should still
check the address with the software that will use it:

- Website: save the `[keys]` block as
  `~/.config/freenet/website-keys/<name>.toml` and run `fdev website list`. It
  prints each key's contract key as computed by your installed fdev. If that
  doesn't match the vanity address, your fdev uses a different container
  contract and the key has to be ground again.
- Freenet Mail: import the identity JSON into the app and check the address
  it shows. You can also run
  `mail-vanity addr --identity my-identity.json --code-hash <hash>`.

## Limitations

- Vanity addresses tie you to a code hash (see
  [the code hash caveat](#the-code-hash-caveat)). This matters most for Freenet
  Mail, whose inbox hash rotates between releases.
- There is no GPU kernel for ML-DSA, so mail addresses longer than about five
  characters take days to years.
- The CUDA code has only been built and run on an RTX 5090 (`sm_120`). Other
  architectures should work with `ARCH=...` but have not been tested.
- Prefixes starting with `1` are not supported.
- Matching is case-sensitive and prefix-only. There is no substring or suffix
  search.
- `words-b58.txt` is a general English dictionary list. It hasn't been
  filtered for offensive words, so look at the address before you use it.
- The tools follow Freenet and Freenet Mail formats as of September 2026. Both
  projects are under active development and the formats may change.

## Related work and credits

### Freenet and Freenet Mail

- Freenet: https://freenet.org/ and https://github.com/freenet/freenet-core.
  History and the Locutus rename: https://freenet.org/about/history/.
- Freenet Mail: https://github.com/freenet/mail. Identity format, inbox
  contract parameters and the rotation issues
  ([#199](https://github.com/freenet/mail/issues/199),
  [#213](https://github.com/freenet/mail/issues/213)).
- freenet-stdlib (`ContractKey::from_params`): https://github.com/freenet/freenet-stdlib
- Publishing a website with fdev: https://freenet.org/build/manual/publish-a-website/
- Hyphanet, the original Freenet: https://www.hyphanet.org/

### Algorithms and reference implementations

- BLAKE3, by Jack O'Connor, Jean-Philippe Aumasson, Samuel Neves and Zooko
  Wilcox-O'Hearn: https://github.com/BLAKE3-team/BLAKE3 and the
  [specification](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf).
- Ed25519 (RFC 8032): https://www.rfc-editor.org/rfc/rfc8032 and
  https://ed25519.cr.yp.to/ (ref10, public domain).
- TweetNaCl: https://tweetnacl.cr.yp.to/
- curve25519-donna, by Adam Langley: https://github.com/agl/curve25519-donna
- Hisil, Wong, Carter and Dawson, "Twisted Edwards Curves Revisited" (2008),
  for the extended-coordinate point addition: https://eprint.iacr.org/2008/522
- ML-DSA (FIPS 204): https://csrc.nist.gov/pubs/fips/204/final. `mail-vanity`
  uses the RustCrypto implementation:
  https://github.com/RustCrypto/signatures/tree/master/ml-dsa
- ed25519-dalek / curve25519-dalek:
  https://github.com/dalek-cryptography/curve25519-dalek

### Other vanity generators

I didn't find a browser-based vanity generator for new-Freenet contract keys or
Freenet Mail addresses. The closest tools are:

- [freenet-vanity-id](https://github.com/TDiffff/freenet-vanity-id): a Rust CPU
  tool that grinds vanity Freenet contract ids. It works differently: instead
  of grinding keys, it appends a nonce to the contract parameters, so it
  applies to contracts whose parameters can carry one.
- [Freenet vanity key generator](https://gist.github.com/bertm/3a50d0c32520dfb4b34b):
  a C program for the old DSA-based keys of the original Freenet (now
  Hyphanet).
- [MeshCore web keygen](https://agessaman.github.io/meshcore-web-keygen/)
  ([source](https://github.com/agessaman/meshcore-web-keygen)) and
  [MeshCore Private Key Generator](https://valentinvieriu.github.io/MeshCore-Private-Key-Generator/)
  ([source](https://github.com/valentinvieriu/MeshCore-Private-Key-Generator)):
  in-browser Ed25519 vanity generators for MeshCore node keys. The CUDA code
  here started as a project inspired by them, with the goal of running the
  same hex-prefix search on a local GPU, and was then adapted to Freenet's
  hash-then-base58 addresses.
- [horse25519](https://github.com/Yawning/horse25519): a CPU Ed25519 vanity
  key generator (Base32 prefixes).
- In-browser vanity generators for other systems:
  [Vanity-ETH](https://vanity-eth.tk/) (Ethereum) and
  [Vanity BTC](https://joshua-zou.github.io/vanity-btc/) (Bitcoin).

### Word list

`words-b58.txt` comes from SCOWL by Kevin Atkinson (http://wordlist.aspell.net/).
See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## License

Copyright (C) 2026 the freenet-keygen-cuda contributors

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version. See [LICENSE](LICENSE).

Third-party code, algorithms and data are credited in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
