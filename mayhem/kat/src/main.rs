// KAT probe for the nearcore Mayhem oracle (see mayhem/kat/Cargo.toml).
//
// Builds a known `SignedTransaction` (signer=alice.near, receiver=bob.near,
// nonce=42, no actions), borsh-encodes it, then decodes it back through
// near_primitives and prints the decoded fields. mayhem/test.sh asserts the exact
// printed values. `kat dump <path>` writes the canonical encoding for use as a
// fuzzing seed.
//
// This drives the real decoder (`borsh::from_slice::<SignedTransaction>` ->
// `impl BorshDeserialize for Transaction`), so if near_primitives is neutered the
// asserted values change / disappear and the oracle fails.

use borsh;
use near_crypto::{KeyType, PublicKey, Signature};
use near_primitives::hash::CryptoHash;
use near_primitives::transaction::{
    Action, SignedTransaction, Transaction, TransactionNonce, TransactionV0, TransactionV1,
    TransferAction,
};
use near_primitives::types::{Balance, Gas};
use near_primitives::receipt::{
    DataReceipt, Receipt, ReceiptEnum, ReceiptOrStateStoredReceipt, ReceiptV0, StateStoredReceipt,
    StateStoredReceiptMetadata, StateStoredReceiptV0,
};
use std::borrow::Cow;

fn build_known_tx() -> SignedTransaction {
    let tx = Transaction::V0(TransactionV0 {
        signer_id: "alice.near".parse().expect("valid account id"),
        public_key: PublicKey::empty(KeyType::ED25519),
        nonce: 42,
        receiver_id: "bob.near".parse().expect("valid account id"),
        block_hash: CryptoHash::default(),
        actions: vec![],
    });
    SignedTransaction::new(Signature::empty(KeyType::ED25519), tx)
}

fn build_v0_transfer() -> SignedTransaction {
    let tx = Transaction::V0(TransactionV0 {
        signer_id: "alice.near".parse().unwrap(),
        public_key: PublicKey::empty(KeyType::ED25519),
        nonce: 7,
        receiver_id: "bob.near".parse().unwrap(),
        block_hash: CryptoHash::default(),
        actions: vec![Action::Transfer(TransferAction {
            deposit: Balance::from_yoctonear(1_000_000),
        })],
    });
    SignedTransaction::new(Signature::empty(KeyType::ED25519), tx)
}

fn build_v1_empty() -> SignedTransaction {
    let tx = Transaction::V1(TransactionV1 {
        signer_id: "alice.near".parse().unwrap(),
        public_key: PublicKey::empty(KeyType::ED25519),
        nonce: TransactionNonce::from_nonce(9),
        receiver_id: "bob.near".parse().unwrap(),
        block_hash: CryptoHash::default(),
        actions: vec![],
        nonce_mode: Default::default(),
    });
    SignedTransaction::new(Signature::empty(KeyType::ED25519), tx)
}


// ---- receipt seeds (mayhem/fuzz/fuzz_targets/decode_receipt.rs) -------------------
//
// ReceiptOrStateStoredReceipt discriminates on the first TWO bytes: 0xFF 0xFF means
// StateStoredReceipt, anything else is parsed as a legacy Receipt (whose second byte
// is 0, because an AccountId's borsh length prefix is a little-endian u32 and account
// ids are short). Seed BOTH sides of that branch so the fuzzer starts with a valid
// example of each layout rather than having to discover the tag by chance.

fn build_receipt_data_empty() -> Receipt {
    Receipt::V0(ReceiptV0 {
        predecessor_id: "alice.near".parse().expect("valid account id"),
        receiver_id: "bob.near".parse().expect("valid account id"),
        receipt_id: CryptoHash::default(),
        receipt: ReceiptEnum::Data(DataReceipt { data_id: CryptoHash::default(), data: None }),
    })
}

fn build_receipt_data_payload() -> Receipt {
    Receipt::V0(ReceiptV0 {
        predecessor_id: "alice.near".parse().expect("valid account id"),
        receiver_id: "carol.near".parse().expect("valid account id"),
        receipt_id: CryptoHash::default(),
        receipt: ReceiptEnum::Data(DataReceipt {
            data_id: CryptoHash::default(),
            data: Some(vec![0u8, 1, 2, 3, 0xff]),
        }),
    })
}

fn receipt_seeds() -> Vec<(&'static str, Vec<u8>)> {
    let legacy_empty = ReceiptOrStateStoredReceipt::Receipt(Cow::Owned(build_receipt_data_empty()));
    let legacy_payload =
        ReceiptOrStateStoredReceipt::Receipt(Cow::Owned(build_receipt_data_payload()));
    // The 0xFF 0xFF-tagged side of the discriminator.
    let state_stored = ReceiptOrStateStoredReceipt::StateStoredReceipt(StateStoredReceipt::V0(
        StateStoredReceiptV0 {
            receipt: Cow::Owned(build_receipt_data_empty()),
            metadata: StateStoredReceiptMetadata {
                congestion_gas: Gas::from_gas(1_000),
                congestion_size: 128,
            },
        },
    ));
    vec![
        ("receipt_v0_data_empty.bin", borsh::to_vec(&legacy_empty).expect("serialize seed")),
        ("receipt_v0_data_payload.bin", borsh::to_vec(&legacy_payload).expect("serialize seed")),
        ("receipt_state_stored_v0.bin", borsh::to_vec(&state_stored).expect("serialize seed")),
    ]
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let signed = build_known_tx();
    let bytes = borsh::to_vec(&signed).expect("serialize known tx");

    if args.len() >= 3 && args[1] == "dump" {
        std::fs::write(&args[2], &bytes).expect("write seed file");
        eprintln!("wrote {} bytes to {}", bytes.len(), args[2]);
        return;
    }

    // `kat dumpall <dir>` writes a few diverse VALID seeds for the fuzzer.
    if args.len() >= 3 && args[1] == "dumpall" {
        let dir = &args[2];
        std::fs::create_dir_all(dir).expect("mkdir seed dir");
        for (name, tx) in [
            ("tx_v0_empty.bin", build_known_tx()),
            ("tx_v0_transfer.bin", build_v0_transfer()),
            ("tx_v1_empty.bin", build_v1_empty()),
        ] {
            let b = borsh::to_vec(&tx).expect("serialize seed");
            let path = format!("{}/{}", dir, name);
            std::fs::write(&path, &b).expect("write seed");
            eprintln!("wrote {} bytes to {}", b.len(), path);
        }
        return;
    }

    // `kat dumpreceipts <dir>` writes VALID seeds for the decode_receipt target,
    // covering both sides of the ReceiptOrStateStoredReceipt two-byte discriminator.
    if args.len() >= 3 && args[1] == "dumpreceipts" {
        let dir = &args[2];
        std::fs::create_dir_all(dir).expect("mkdir seed dir");
        for (name, b) in receipt_seeds() {
            let path = format!("{}/{}", dir, name);
            std::fs::write(&path, &b).expect("write seed");
            eprintln!("wrote {} bytes to {}", b.len(), path);
        }
        return;
    }

    // Decode the canonical bytes back through the real near_primitives decoder.
    let decoded: SignedTransaction =
        borsh::from_slice(&bytes).expect("decode known tx must succeed");

    let signer = decoded.transaction.signer_id().to_string();
    let receiver = decoded.transaction.receiver_id().to_string();
    let nonce = decoded.transaction.nonce().nonce();
    let n_actions = decoded.transaction.actions().len();
    let reencoded = borsh::to_vec(&decoded).expect("re-serialize");
    let roundtrip = reencoded == bytes;

    // Panic if the decoder ever returns wrong values (defence in depth); the
    // grep in test.sh is the sabotage-proof half of the oracle.
    assert_eq!(signer, "alice.near", "decoded signer_id mismatch");
    assert_eq!(receiver, "bob.near", "decoded receiver_id mismatch");
    assert_eq!(nonce, 42, "decoded nonce mismatch");
    assert_eq!(n_actions, 0, "decoded action count mismatch");
    assert!(roundtrip, "decode/encode is not a canonical round-trip");

    println!(
        "KAT signer={} receiver={} nonce={} actions={} bytes_len={} roundtrip={}",
        signer,
        receiver,
        nonce,
        n_actions,
        bytes.len(),
        if roundtrip { "OK" } else { "BAD" }
    );
}
