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
use near_primitives::types::Balance;

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
