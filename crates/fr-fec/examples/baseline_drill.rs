//! (frankenredis-rc-raptorq-gate-d-contract-71zfo) End-to-end durability drill
//! against a REAL repo artifact: encode a checked-in benchmark baseline into a
//! §19 envelope, drop + corrupt symbols, scrub-recover, decode, verify, and
//! emit the envelope JSON for the session record.
//!
//! Run: `cargo run -p fr-fec --example baseline_drill -- <path> [out.json]`

use fr_fec::{
    decode_artifact, deserialize_symbol, encode_artifact, envelope_to_json, scrub, serialize_symbol,
};

fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .unwrap_or_else(|| "baselines/frankenredis_v0.1.0_set.json".to_string());
    let out = args
        .next()
        .unwrap_or_else(|| "artifacts/fec/baseline_drill.envelope.json".to_string());

    let data = std::fs::read(&path).map_err(|err| format!("read {path}: {err}"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let encoded = encode_artifact(&path, "benchmark", &data, 8, 512, now)?;
    let k = encoded.envelope.raptorq.k;
    println!(
        "artifact: {path} ({} bytes) -> k={k} + 8 repair symbols of {} bytes",
        data.len(),
        encoded.envelope.symbol_size
    );

    let mut symbols: Vec<_> = encoded
        .symbols
        .iter()
        .map(|p| deserialize_symbol(&serialize_symbol(p)).unwrap())
        .collect();

    // Loss + corruption: the exact damage the drill exists to survive.
    symbols.remove(0);
    symbols.remove(1);
    let last = symbols.len() - 1;
    {
        let serialized = serialize_symbol(&symbols[last]);
        let mut bytes = serialized;
        let at = bytes.len() / 2;
        bytes[at] ^= 0xFF;
        let rebuilt = deserialize_symbol(&bytes).unwrap();
        symbols[last] = rebuilt;
    }

    match scrub(&encoded.envelope, &symbols, now + 1_000) {
        fr_fec::ScrubOutcome::Recovered { source, proof } => {
            println!(
                "scrub: RECOVERED ({}), source {} bytes re-verified",
                proof.reason,
                source.len()
            );
            let mut envelope = encoded.envelope.clone();
            envelope.decode_proofs.push(proof);
            envelope.scrub.status = "recovered".to_string();
            let json = envelope_to_json(&envelope);
            if let Some(parent) = std::path::Path::new(&out).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            std::fs::write(&out, json).map_err(|err| format!("write {out}: {err}"))?;
            println!("envelope: {out}");
        }
        fr_fec::ScrubOutcome::Clean => {
            return Err("expected damage, scrub reported Clean".into());
        }
        fr_fec::ScrubOutcome::Failed { reason } => return Err(reason),
    }

    // Final integrity statement: decode and hash-verify.
    let (source, proof) =
        decode_artifact(&encoded.envelope, &symbols, "drill decode", now + 2_000)?;
    assert_eq!(
        source, data,
        "decoded source must equal the original artifact"
    );
    println!(
        "decode: {} bytes verified against {}",
        source.len(),
        encoded.envelope.source_hash
    );
    println!("decode proof: {}", proof.proof_hash);
    Ok(())
}
