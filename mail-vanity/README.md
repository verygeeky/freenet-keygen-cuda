# mail-vanity

Grinds a Freenet Mail identity whose inbox address starts with a word you pick,
and writes an identity JSON that the Freenet Mail app can import.

This tool is separate from the website-key tools in the parent directory
(`fn-vanity`, `fn-words`, `website-vanity`). Those search Ed25519 website keys;
this one searches ML-DSA-65 mail identities. A hit from one is useless to the
other.

## What the address is

The contact address a Freenet Mail user hands out is the id of their inbox
contract. Following the code in [freenet/mail](https://github.com/freenet/mail)
(`ui/src/app/address_book.rs::identity_inbox_address` →
`ui/src/inbox.rs::inbox_key_for`) into freenet-stdlib 0.3.5
(`contract_interface/key.rs::ContractKey::from_params`):

```
address     = base58( blake3( inbox_code_hash[32] || serde_json(InboxParams) ) )
InboxParams = { "pub_key": <ML-DSA-65 verifying key, 1952 bytes> }
```

serde_json writes `Vec<u8>` as an array of decimal integers, so the hashed
parameter blob is about 7 KB, not 1952 bytes. Only the ML-DSA key feeds the
address. The identity's ML-KEM seed is independent, so the tool fills it with
fresh randomness.

The `addr` subcommand reproduces a known identity/address pair from the real
app exactly. The unit test `address_vector` pins one address that was computed
separately in Python (dilithium-py, `json`, `blake3`).

## Why this is slow

1. Cost per try. Every candidate needs a full ML-DSA-65 key generation plus
   a BLAKE3 over ~7 KB. On a 24-thread Intel Core Ultra 9 285K, `grind` runs at
   about 90,000 keys/s. The CUDA website search does about 190 million keys/s,
   roughly 2000 times faster. There is no GPU kernel for ML-DSA here.

2. Base58 length. A 32-byte value encodes to 43 or 44 base58 characters.
   Since 2^256 / 58^43 ≈ 17.6, a 44-character address can only start with the
   first 18 characters of the alphabet (`1` to `J`). A prefix starting with any
   later character, such as any lowercase letter, can only occur in a
   43-character address, which covers about 5.8% of the space. That costs
   another factor of ~17 on top of 58 per character.

   Base58 has no `0`, `O`, `I` or lowercase `l`, so a word like `island` can
   never be a prefix. Prefixes starting with `1` are rejected too: base58 uses a
   leading `1` for a leading zero byte, which the range search doesn't model.

3. The address depends on the inbox code hash, and that hash rotates. A new
   build of the inbox contract changes `INBOX_CODE_HASH`. That changes the
   address of every existing identity. Freenet Mail handles this with a
   per-identity migration (see
   [issue #199](https://github.com/freenet/mail/issues/199),
   [issue #213](https://github.com/freenet/mail/issues/213), and the "Per-identity
   inbox migration on contract id rotation (#213)" entry in the app's
   `docs/qa/manual-test-inventory.md`). A vanity address only holds for the code
   hash it was ground against. When the inbox contract changes, the prefix is
   gone.

## Getting the code hash

You can't compute `INBOX_CODE_HASH` from source. The inbox wasm embeds the
absolute paths of the machine that built it, so a local rebuild gives a
different hash from the official release. Local builds of tags v0.2.1 to v0.2.5
and `main` all produced the same hash as each other, which shows the lockfile
isolation from issue #199 works. But that hash belongs to the local build, not
to the shipped one.

To get the real hash, pull it out of the shipped webapp wasm, which carries it
as a string constant. You need an identity export and the address the app shows
for it:

```
mail-vanity extract --identity <your-identity-export.json> \
                    --target <the address the app shows for it> \
                    --file <path/to/mail-webapp.wasm>
```

`extract` collects every base58 string in the binary that decodes to 32 bytes,
tries each one as the code hash, and reports the one that reproduces your
address. `scan` does the same for a text file of candidate hashes.

## Cost

Expected tries come from `grind`'s header. Times assume 90,000 keys/s. The
figures hold for any prefix that starts with a lowercase letter.

| prefix length | example | expected tries | time at 90k keys/s |
|---|---|---|---|
| 3 | `fro` | 3.4e6 | ~40 s |
| 4 | `fros` | 2.0e8 | ~36 min |
| 5 | `frost` | 1.1e10 | ~35 h |
| 6 | `frosty` | 6.6e11 | ~84 days |
| 7 | `frosted` | 3.8e13 | ~13 years |

Accepting any word from `../words-b58.txt` is much cheaper, and you still get
a real English word:

| mode | words | expected tries | time at 90k keys/s |
|---|---|---|---|
| `--min-len 5` | 6661 | 1.1e7 | ~2 min |
| `--min-len 6` | 5628 | 5.4e8 | ~1.7 h |
| `--min-len 7` | 4434 | 3.1e10 | ~4 days |

These are averages. A search can take several times longer.

## Usage

```
mail-vanity addr    --identity <file.json> --code-hash <bs58>
mail-vanity scan    --identity <file.json> --target <bs58 addr> --hashes <file>
mail-vanity extract --identity <file.json> --target <bs58 addr> --file <binary>
mail-vanity grind   --code-hash <bs58> [--prefix <word> | --words <file> [--min-len N]]
                    [--threads N] [--alias NAME] [--description TEXT] [--out FILE]
```

`grind` writes a `version: 2` identity JSON with the same schema as the app's
own export. Before it reports a hit, it derives the address again from the
found seed, so a bug in the range check can't produce a false hit. With
`--out`, the file is created with mode 0600 and the tool refuses to overwrite an
existing file. Without `--out`, the identity JSON, including the secret seed,
goes to stdout.

The identity JSON contains your private keys. Treat it like a password
manager export. See the security section in the top-level README.
