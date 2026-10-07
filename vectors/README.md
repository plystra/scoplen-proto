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

`sync-changes.json` contains K-4 change-feed vectors. Query inputs are JSON objects with `after`
and `limit`; expected values are the canonical query string. Response inputs are JSON objects with
`changes`, `next_cursor`, and `more`; payloads are lowercase hexadecimal and a missing signer is
represented by JSON `null`. Response expected values are deterministic CBOR. Each response change
entry uses integer map keys 1 through 5, as defined by `07-sync-protocol.md` §4.

`sync-messages.json` contains the remaining K-4 wire vectors. Write requests are JSON arrays with
`object_id`, nullable `base_seq`, lowercase hexadecimal `payload`, and `tombstone`; their
expected value is a direct deterministic CBOR array of integer-keyed maps 1 through 4. Write
responses are JSON arrays of `object_id` and `seq` assignments and encode as a direct array of
integer-keyed maps 1 and 2. Acknowledgement requests and responses use a JSON object with
`cursor` and encode as a text-keyed CBOR map. Snapshot responses use `objects`, `next_cursor`,
and `more`, with the same integer-keyed entries and page rules as the change feed. Version
responses use `versions`, contain one object id in ascending sequence order, and include at most
the current entry plus 20 retained entries. All expected values are deterministic CBOR in lowercase
hexadecimal.

`sync-notifications.json` contains the content-free K-4 notification events sent over the WebSocket.
Vault advancement uses `{seq, vault}`, rotation pending uses `{rotation_pending, vault}`, and
device revocation uses the boolean marker `{device_revoked: true}` until the specification defines
an event payload. UUIDs are encoded as 16-byte UUIDv7 strings, and all expected values are
deterministic CBOR in lowercase hexadecimal.

`sync-keys.json` contains the K-4 account key-bundle vectors from `07-sync-protocol.md` §8.1 and
D-50. The GET response uses opaque non-empty artifact hex strings and lexicographically sorted
certificate and revocation arrays. The PUT request uses one sorted device wrap per device, a
synthetic fixed-width 64-byte signature, and the same deterministic map encoding for the exact
replay vector. The signature-input vector covers the `spl-sync-keys-v1` domain prefix and unsigned
map bytes. The successful PUT response is `{revision}`. These vectors exercise transport encoding
only; key authenticity is owned by `scoplen-crypto`.

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
| `crypto.safety-number` | account UUID, Ed25519 public key, and X25519 KEM public key for each account | sixty decimal digits, both 32-byte fingerprints, and canonical `splsafety2:` QR text |
| `crypto.local-db-key` | UTF-8 passphrase, database key, Argon2 memory KiB, time cost, parallelism, salt, nonce | encoded Argon2id wrapper |
| `crypto.escrow-account-open` | account UUID, administrator UUID, recipient private key, encapsulated key, ciphertext | serialized authenticated Shamir share |
| `crypto.escrow-device-open` | account UUID, request UUID, device signing public key, recipient private key, encapsulated key, ciphertext | serialized authenticated Shamir share |
| `crypto.escrow-verification` | account UUID, administrator UUID, request UUID, device signing and KEM public keys | grouped 80-bit verification code and account/device contexts |
| `crypto.qr-pairing` | pairing UUIDv7, P-256 KEM public key, P-256 signing public key | canonical `splpair1:` QR text |
| `crypto.cpace-pairing` | pairing UUIDv7, initiator and responder UUIDv7, code, initiator and responder RNG bytes, nonce, plaintext | initiator share, responder share, 64-byte CPace session id, both confirmations, and nonce-prefixed XChaCha frame |

The `crypto.cpace-pairing` expected fields are lowercase hexadecimal and are
separated by `|` in this order: initiator share, responder share, session id,
initiator confirmation, responder confirmation, and the frame (`nonce ||
ciphertext || tag`).  Its fixed context and role ordering are the K-3
typed-code contract from `06-identity-and-authentication.md` §2; the RNG fields
make the published shares reproducible without exposing production secrets.

The HPKE seal operations use fresh randomness, so their published known answers exercise opening
fixed ciphertexts. The test suite separately exercises sealing and tamper rejection. The local
database wrapper vector uses 8 MiB and one pass to keep CI practical; production defaults remain
256 MiB, three passes, and four lanes.

`api-problem.json` contains an `api.problem.cbor` vector. Its `input` is the JSON form of an RFC
9457 problem with all eight required Scoplen fields; `expected` is the deterministic CBOR body in
lowercase hexadecimal. The `scoplen-api` tests exercise the public JSON and CBOR contract, including
unknown error-code preservation and malformed-body rejection.

`api-auth.json` contains the K-3 JSON vectors. Challenge responses use a 32-byte lowercase
hexadecimal nonce and an RFC 3339 UTC timestamp. Device requests use a canonical UUIDv7, the
canonical challenge nonce, and a fixed-width P-256 `r || s` signature as lowercase hexadecimal.
Token responses use literal `DPoP`; `AuthTokenResponse::new` writes the default 600-second and
30-day lifetimes, while readers and validators accept any positive integer lifetime. The expected
values are canonical field order; readers ignore unknown response fields while device requests
reject unknown fields.

`sync-session.json` contains `sync.session.request` and `sync.session.response` vectors. Each
`input` is a JSON description of the typed K-4 session value; `expected` is deterministic CBOR in
lowercase hexadecimal. UUIDs are written as canonical text in the vector input and encoded as
16-byte CBOR byte strings. The public codec tests consume both vectors and reject missing fields,
invalid limits, duplicate vaults, and malformed nested values.
