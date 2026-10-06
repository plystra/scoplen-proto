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
