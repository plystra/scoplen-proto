// SPDX-License-Identifier: Apache-2.0
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let _ = scoplen_ssh::AgentMessage::decode_frame(bytes);
});
