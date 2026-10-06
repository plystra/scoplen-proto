# Shared test vectors

Vector files are UTF-8 JSON documents with the `scoplen-test-vectors` format name and version `1`.
Each vector has a stable `id`, a contract-specific `kind`, and opaque `input` and `expected` strings.
The loader in `scoplen-test-vectors` validates the envelope and identifiers; the contract crate that
owns a kind validates its encoding and interprets the values.

The baseline document includes K-1 vectors for shortest-form maps, NFC text, the complete CBOR
negative-integer range, and an executable object merge. `model.cbor` vectors use hexadecimal CBOR
for both `input` and `expected`. `model.merge` vectors use two hexadecimal object envelopes joined
by `|` in `input`, with the expected merged envelope in `expected`. Contract-specific vector kinds
and additional canonical encodings are added with the corresponding contract gate and are
consumed by both client and server workstreams.

`crypto.json` contains K-2 known answers. All private keys and plaintexts in this document are
synthetic, public test material and must never be used for real data. Every binary field is
lowercase hexadecimal; fields in `input` are separated by `|`. Decimal integer fields and the
recovery display and safety-number outputs are written as text.

| Kind | Input fields, in order | Expected |
| --- | --- | --- |
| `crypto.hkdf-sha256` | IKM, salt, info, output length | Derived bytes (RFC 5869 case 1) |
| `crypto.xchacha20poly1305` | key, nonce, plaintext, AAD | ciphertext and tag |
| `crypto.p256-signature` | private scalar, message | uncompressed public key, fixed-width signature |
| `crypto.ed25519-signature` | private seed, message | public key, signature |
| `crypto.hpke-account-open`, `crypto.hpke-device-open` | recipient private key, encapsulated key, info, AAD, ciphertext | plaintext |
| `crypto.device-key-wrap-open` | device private key, encapsulated key, info, AAD, ciphertext | 32-byte unwrapped key |
| `crypto.device-certificate` | account signing seed, device UUID, account UUID, device signing scalar, device KEM private key, UTF-8 name, UTF-8 platform, Unix milliseconds | signed deterministic CBOR |
| `crypto.device-revocation` | account signing seed, device UUID, Unix milliseconds, UTF-8 reason | signed deterministic CBOR |
| `crypto.object-envelope` | vault UUID, epoch, K-1 object CBOR, vault key, signer UUID, P-256 signing scalar, nonce | signed encrypted envelope |
| `crypto.recovery-display` | raw recovery key | `SPL1-` display with checksum |
| `crypto.recovery-blob` | raw recovery key, account UUID, ARK, nonce | encoded wrapped ARK |
| `crypto.shamir-split` | secret, threshold, share count, coefficient bytes | serialized shares, separated by `|` |
| `crypto.safety-number` | two Ed25519 public keys | twelve decimal digits |
| `crypto.local-db-key` | UTF-8 passphrase, database key, Argon2 memory KiB, time cost, parallelism, salt, nonce | encoded Argon2id wrapper |
| `crypto.escrow-account-open`, `crypto.escrow-device-open` | recipient private key, encapsulated key, ciphertext | serialized authenticated Shamir share |
| `crypto.qr-pairing` | pairing UUIDv7, P-256 KEM public key, P-256 signing public key | canonical `splpair1:` QR text |

The HPKE seal operations use fresh randomness, so their published known answers exercise opening
fixed ciphertexts. The test suite separately exercises sealing and tamper rejection. The local
database wrapper vector uses 8 MiB and one pass to keep CI practical; production defaults remain
256 MiB, three passes, and four lanes.

`api-problem.json` contains an `api.problem.cbor` vector. Its `input` is the JSON form of an RFC
9457 problem with all eight required Scoplen fields; `expected` is the deterministic CBOR body in
lowercase hexadecimal. The `scoplen-api` tests exercise the public JSON and CBOR contract, including
unknown error-code preservation and malformed-body rejection.

`sync-session.json` contains `sync.session.request` and `sync.session.response` vectors. Each
`input` is a JSON description of the typed K-4 session value; `expected` is deterministic CBOR in
lowercase hexadecimal. UUIDs are written as canonical text in the vector input and encoded as
16-byte CBOR byte strings. The public codec tests consume both vectors and reject missing fields,
invalid limits, duplicate vaults, and malformed nested values.
