//! (frankenredis-rc-raptorq-gate-d-contract-71zfo) The §18 G6 durability drill
//! in miniature: generate, damage, scrub, recover — with every §9 output
//! asserted (generation manifest, scrub status, decode proof).

use fr_fec::{
    ScrubOutcome, decode_artifact, deserialize_symbol, encode_artifact, envelope_from_json,
    envelope_to_json, scrub, serialize_symbol,
};

const NOW: u64 = 1_788_600_000_000;

fn fixture_bytes() -> Vec<u8> {
    // Deterministic stand-in for a persisted artifact (e.g. a benchmark
    // baseline JSON): larger than one symbol so k > 1.
    let mut data = Vec::new();
    for i in 0..400_u32 {
        data.extend_from_slice(format!("{{\"entry\":{i},\"value\":\"{i:016x}\"}}\n").as_bytes());
    }
    data
}

fn corrupt(serialized: &[u8]) -> Vec<u8> {
    let mut bytes = serialized.to_vec();
    let at = bytes.len() / 2;
    bytes[at] ^= 0xFF;
    bytes
}

#[test]
fn generation_scrub_and_recovery_drill_round_trips() {
    let data = fixture_bytes();

    // GENERATION (§9 output 1): k source symbols + a repair budget.
    let encoded = encode_artifact("bench/set", "benchmark", &data, 4, 256, NOW).expect("encode");
    let k = encoded.envelope.raptorq.k as usize;
    assert!(k > 1, "fixture must span multiple symbols, k={k}");
    assert_eq!(encoded.symbols.len(), k + 4);
    assert_eq!(encoded.envelope.raptorq.symbol_hashes.len(), k + 4);

    // Round-trip through the serialized symbol form (the persisted form).
    let serialized: Vec<Vec<u8>> = encoded.symbols.iter().map(serialize_symbol).collect();
    let mut symbols: Vec<_> = serialized
        .iter()
        .map(|b| deserialize_symbol(b).unwrap())
        .collect();

    // SCRUB on an intact artifact (§9 output 2): Clean, nothing to repair.
    assert!(matches!(
        scrub(&encoded.envelope, &symbols, NOW),
        ScrubOutcome::Clean
    ));

    // Damage: lose the first source symbol and corrupt one repair symbol.
    symbols.remove(0);
    *symbols.last_mut().unwrap() =
        deserialize_symbol(&corrupt(&serialized[serialized.len() - 1])).unwrap();

    // SCRUB now reports damage; recovery from the remaining symbols works.
    match scrub(&encoded.envelope, &symbols, NOW + 1_000) {
        ScrubOutcome::Recovered { source, proof } => {
            assert_eq!(source, data, "recovered source must equal the original");
            assert_eq!(proof.recovered_blocks as usize, k);
            assert!(proof.reason.contains("hash-damaged"));
        }
        other => panic!("expected Recovered, got {other:?}"),
    }

    // DECODE PROOF (§9 output 3): explicit decode from the surviving set,
    // including the envelope round-trip through canonical JSON.
    let envelope_json = envelope_to_json(&encoded.envelope);
    let envelope = envelope_from_json(&envelope_json).expect("envelope reparse");
    let (source, proof) =
        decode_artifact(&envelope, &symbols, "forced-recovery drill", NOW + 2_000).expect("decode");
    assert_eq!(source, data);
    use sha2::{Digest, Sha256};
    assert_eq!(
        proof.proof_hash,
        format!("sha256:{}", hex::encode(Sha256::digest(&source)))
    );
    assert_eq!(envelope.decode_proofs.len(), 0);

    // Undecodable: below k intact symbols the artifact is honestly failed.
    let too_few: Vec<_> = symbols.iter().take(k - 1).cloned().collect();
    assert!(
        decode_artifact(&envelope, &too_few, "lost", NOW).is_err(),
        "fewer than k intact symbols must not decode"
    );
}
