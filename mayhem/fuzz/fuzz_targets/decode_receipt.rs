// Additive in-process libFuzzer harness for nearcore's receipt wire decoder.
//
// This targets `ReceiptOrStateStoredReceipt`, which is the most interesting
// hand-written decoder in core/primitives/src/receipt.rs. It is NOT a derive-macro
// borsh impl: `deserialize_reader` reads the first two bytes, chains them back onto
// the reader, and uses them to discriminate between two entirely different layouts:
//
//     let u1 = u8::deserialize_reader(reader)?;
//     let u2 = u8::deserialize_reader(reader)?;
//     let mut reader = prefix.chain(reader);
//     if u1 == STATE_STORED_RECEIPT_TAG && u2 == STATE_STORED_RECEIPT_TAG { .. }
//
// The discrimination rests on an ENCODING INVARIANT rather than an explicit tag:
// `Receipt::V0`'s first field is an `AccountId` whose borsh length prefix is a
// little-endian u32, so for any legitimately-encoded receipt the second byte must be
// 0 (account ids are at most 64 bytes). `StateStoredReceipt` is marked by 0xFF 0xFF.
// Upstream's own comment calls this "hackery" kept for backwards compatibility.
//
// That is exactly the shape worth fuzzing: a parser that decides which of two types
// it is looking at from two leading bytes, on attacker-influenced input. Receipts
// cross the network and are read back out of state, so the bytes are not trusted.
//
// Feeding raw fuzz bytes here also covers everything underneath — Receipt, ReceiptV0,
// the ReceiptEnum variants (Action/Data/PromiseYield/PromiseResume/
// GlobalContractDistribution/ActionV2/PromiseYieldV2), StateStoredReceiptV0/V1 and
// their metadata — since all of them are reached through this one entry point.
//
// Oracle: on a SUCCESSFUL decode we assert borsh's canonical round-trip, the same
// invariant mayhem/fuzz/fuzz_targets/decode_signed_transaction.rs asserts.
// `borsh::from_slice` rejects trailing bytes, so anything it accepts must re-encode
// to the identical byte string. A value that decodes but does NOT round-trip is a
// real asymmetry in the decoder — and for THIS type it is the precise signature of
// the confusion bug the two-byte discriminator can admit: bytes parsed as one
// variant that re-encode as the other. So the assert is deliberately unguarded.
//
// No file I/O and no relative paths (SPEC §3) — bytes go straight into the decoder.
#![no_main]

use libfuzzer_sys::fuzz_target;
use near_primitives::receipt::ReceiptOrStateStoredReceipt;

fuzz_target!(|data: &[u8]| {
    if let Ok(receipt) = borsh::from_slice::<ReceiptOrStateStoredReceipt<'static>>(data) {
        let reencoded =
            borsh::to_vec(&receipt).expect("re-serialization of a decoded receipt must succeed");
        assert_eq!(
            data,
            reencoded.as_slice(),
            "borsh decode/encode of ReceiptOrStateStoredReceipt is not a canonical round-trip"
        );
    }
});
