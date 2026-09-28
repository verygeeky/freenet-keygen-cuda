# Third-party notices

freenet-keygen-cuda is licensed under GPL-3.0-or-later (see `LICENSE`). This
file lists the outside work it builds on, with the upstream notices that must
travel with it.

## Code and algorithms in this repository

### curve25519-donna (field arithmetic formulas)

`cuda/ed25519_fast.cuh` implements the radix-2^51 field multiply and square in
the style of `curve25519-donna-c64.c`. The file header of that source reads
"Code released into the public domain", and its repository ships the BSD
3-Clause license below. The notice is reproduced here to satisfy either.

Source: https://github.com/agl/curve25519-donna

```
Copyright 2008, Google Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

    * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
    * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

### Ed25519 ref10 / TweetNaCl (public domain)

The field inversion addition chain in `cuda/ed25519_fast.cuh` follows the
Ed25519 "ref10" implementation from SUPERCOP by Daniel J. Bernstein, Niels
Duif, Tanja Lange, Peter Schwabe and Bo-Yin Yang, which is public domain. The
earlier MeshCore CUDA key generator this code grew out of started from a port
of TweetNaCl (Bernstein, van Gastel, Janssen, Lange, Schwabe, Smetsers), also
public domain.

- https://ed25519.cr.yp.to/
- https://tweetnacl.cr.yp.to/

### BLAKE3

`cuda/blake3_64.cuh` implements the BLAKE3 compression function for a single
64-byte block, following the BLAKE3 specification by Jack O'Connor,
Jean-Philippe Aumasson, Samuel Neves and Zooko Wilcox-O'Hearn. The reference
implementation is available under CC0-1.0, Apache-2.0, or Apache-2.0 WITH
LLVM-exception.

- https://github.com/BLAKE3-team/BLAKE3
- https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf

### SHA-512 constants

The SHA-512 round constants and initial hash values in `cuda/ed25519_fast.cuh`
come from FIPS 180-4, a US government standard.

## Data

### words-b58.txt: SCOWL

`words-b58.txt` is built by `tools/make-wordlist.sh` from SCOWL 2020.12.07
(Spell Checker Oriented Word Lists), size levels 10 and 20 of the English and
American lists. The script keeps lowercase words that are valid base58 strings.
SCOWL's full copyright file is in `wordlists/SCOWL-Copyright`. The main notice:

```
Copyright 2000-2018 by Kevin Atkinson

Permission to use, copy, modify, distribute and sell these word
lists, the associated scripts, the output created from the scripts,
and its documentation for any purpose is hereby granted without fee,
provided that the above copyright notice appears in all copies and
that both that copyright notice and this permission notice appear in
supporting documentation. Kevin Atkinson makes no representations
about the suitability of this array for any purpose. It is provided
"as is" without express or implied warranty.
```

According to that file, levels 10 and 20 come from the Moby Words II package
and Brian Kelk's "UK English Wordlist with Frequency Classification", both
public domain. The American list uses Kevin Atkinson's VarCon, under a
permission notice of the same form.

- http://wordlist.aspell.net/
- https://github.com/en-wl/wordlist

## Dependencies (not vendored)

These are fetched by the package manager at build time. No copies live in this
repository, but the Rust binaries link them statically. Every license below is
compatible with GPL-3.0-or-later.

| Component | Used by | License |
|---|---|---|
| ed25519-dalek 2.2, curve25519-dalek 4.1, subtle | `website-vanity` | BSD-3-Clause |
| blake3 1.8 | both Rust crates | CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception |
| ml-dsa 0.1.0-rc.8, module-lattice (RustCrypto) | `mail-vanity` | Apache-2.0 OR MIT |
| bs58, rand, rand_chacha, rayon, num-bigint, serde, serde_json, sha2, sha3 and other transitive crates | both Rust crates | MIT OR Apache-2.0 (a few also offer Zlib, BSD-2-Clause, Unlicense, CC0 or MIT-0 as alternatives) |
| arrayref | blake3 | BSD-2-Clause |
| unicode-ident | serde_derive (build only) | (MIT OR Apache-2.0) AND Unicode-3.0 |
| r-efi | getrandom on UEFI targets only | MIT OR Apache-2.0 OR LGPL-2.1-or-later |
| base58 (Python) 2.1 | `fn-vanity`, `fn-words` | MIT |
| CUDA Toolkit | `cuda/` | NVIDIA EULA; a system library, not distributed here |

To regenerate the Rust part of this table from the lockfiles, run
`cargo metadata --format-version 1` in each crate and read the `license` field
of each package.
