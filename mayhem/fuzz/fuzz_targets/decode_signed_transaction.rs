// Additive in-process libFuzzer harness for nearcore's transaction wire decoder.
//
// nearcore gossips and stores transactions as borsh-encoded `SignedTransaction`.
// The decode path is a genuine byte-in parser: `borsh::from_slice` drives the
// hand-written `impl BorshDeserialize for Transaction` in core/primitives, which
// peeks the first two bytes to discriminate the V0 (legacy, no tag) and V1
// (0x01-tagged) transaction layouts, plus all the nested Action / AccessKey /
// AccountId borsh readers. That version-sniffing + length-prefixed decoding is
// exactly the kind of attacker-reachable code worth fuzzing.
//
// We feed the fuzzer raw bytes straight into the decoder (no file I/O, no relative
// paths — SPEC §3). On a SUCCESSFUL decode we assert borsh's canonical round-trip
// invariant: re-serializing the decoded value must reproduce the input byte-for-byte.
// `borsh::from_slice` already rejects trailing bytes, so any input it accepts must
// re-encode identically; an input that decodes but does NOT round-trip is a real
// asymmetry bug in the decoder (the product), so we do NOT guard it.
//
// NOTE: `SignedTransaction` carries `#[borsh(init=init)]` + two `#[borsh(skip)]`
// fields (hash/size) that are recomputed on decode, not read from the wire — so the
// round-trip compares only the on-wire bytes (transaction + signature), which is
// what `borsh::to_vec` emits.
#![no_main]

use libfuzzer_sys::fuzz_target;
use near_primitives::transaction::SignedTransaction;

fuzz_target!(|data: &[u8]| {
    if let Ok(tx) = borsh::from_slice::<SignedTransaction>(data) {
        let reencoded = borsh::to_vec(&tx).expect("re-serialization of a decoded tx must succeed");
        assert_eq!(
            data, reencoded.as_slice(),
            "borsh decode/encode of SignedTransaction is not a canonical round-trip"
        );
    }
});
