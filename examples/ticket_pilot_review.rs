//! Unsigned P0 review; no key loading, signing, RPC or submission.
#[path = "support/ticket_pilot.rs"]
mod pilot;
use pilot::*;
use serde::Deserialize;
use std::io::{self, Read};
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct RoleKeys {
    funding_key: String,
    ticket_key: String,
    return_key: String,
}
fn addresses(raw: &[u8]) -> Result<serde_json::Value> {
    let keys: RoleKeys = serde_json::from_slice(raw).map_err(|_| "Invalid role keys")?;
    if canonical(&keys)? != raw {
        return Err("Canonical closed role keys required".into());
    }
    let values = [&keys.funding_key, &keys.ticket_key, &keys.return_key];
    if values[0] == values[1] || values[0] == values[2] || values[1] == values[2] {
        return Err("Distinct native roles required".into());
    }
    for key in values {
        if LAB_KEYS.contains(&key.as_str()) || key == COLD_FIXTURE_KEY {
            return Err("Known public fixture key rejected".into());
        }
    }
    Ok(serde_json::json!({
        "mode": "TN10_P0_PUBLIC_ADDRESSES_NO_SOURCE_OR_AUTHORIZATION",
        "network": "testnet-10",
        "roles": {
            "funding": address(&keys.funding_key)?.to_string(),
            "ticket": address(&keys.ticket_key)?.to_string(),
            "return": address(&keys.return_key)?.to_string()
        }
    }))
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if !args.is_empty() && args != ["addresses"] {
        return Err("Usage: ticket_pilot_review [addresses] < canonical-public-input.json".into());
    }
    let mut raw = Vec::new();
    io::stdin()
        .take(16385)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    if raw.len() > 16384 || !raw.is_ascii() {
        return Err("Bounded ASCII input required".into());
    }
    let result = if args.is_empty() {
        review(&Plan::parse(&raw)?)?
    } else {
        addresses(&raw)?
    };
    println!(
        "{}",
        serde_json::to_string(&result).map_err(|e| e.to_string())?
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::tx::Transaction;
    use kaspa_rpc_core::RpcTransaction;
    use kaspa_txscript::standard::pay_to_address_script;
    use silverscript_abi::{decode_hex, encode_hex};
    fn fixture() -> Plan {
        Plan {
            namespace: "icp-ticket-pilot-review-p0".into(),
            network: "testnet-10".into(),
            purpose: "public-fixture-never-fund".into(),
            run_nonce: "44".repeat(32),
            evidence_digest: "77".repeat(32),
            funding_key: LAB_KEYS[0].into(),
            ticket_key: LAB_KEYS[1].into(),
            return_key: LAB_KEYS[2].into(),
            source: Source {
                transaction_id: "11".repeat(32),
                index: 0,
                amount: 24_000_000,
            },
        }
    }
    fn operator() -> Plan {
        use secp256k1::{Keypair, Secp256k1, rand::thread_rng};
        let key = || {
            encode_hex(
                &Keypair::new(&Secp256k1::new(), &mut thread_rng())
                    .x_only_public_key()
                    .0
                    .serialize(),
            )
        };
        let mut p = fixture();
        p.purpose = "operator-unsigned-review".into();
        p.funding_key = key();
        p.ticket_key = key();
        p.return_key = key();
        p.run_nonce = "55".repeat(32);
        p.source.transaction_id = "22".repeat(32);
        p
    }
    #[test]
    fn public_addresses_match_native_review_without_fabricating_a_source() {
        let p = operator();
        let keys = RoleKeys {
            funding_key: p.funding_key.clone(),
            ticket_key: p.ticket_key.clone(),
            return_key: p.return_key.clone(),
        };
        let result = addresses(&canonical(&keys).unwrap()).unwrap();
        assert_eq!(result["roles"], review(&p).unwrap()["roles"]);
        assert!(result.get("source").is_none());
        assert!(result.get("transactions").is_none());
    }
    #[test]
    fn address_mode_rejects_alias_fixture_secret_extra_and_noncanonical_input() {
        let p = operator();
        let keys = RoleKeys {
            funding_key: p.funding_key,
            ticket_key: p.ticket_key,
            return_key: p.return_key,
        };
        let mut v = serde_json::to_value(keys).unwrap();
        let raw = canonical(&v).unwrap();
        assert!(addresses(&[b" ".as_slice(), &raw].concat()).is_err());
        v["private_key"] = serde_json::json!("never accepted");
        assert!(addresses(&canonical(&v).unwrap()).is_err());
        v.as_object_mut().unwrap().remove("private_key");
        v["ticket_key"] = v["funding_key"].clone();
        assert!(addresses(&canonical(&v).unwrap()).is_err());
        v["ticket_key"] = serde_json::json!(LAB_KEYS[0]);
        assert!(addresses(&canonical(&v).unwrap()).is_err());
        v["ticket_key"] = serde_json::json!("00".repeat(32));
        assert!(addresses(&canonical(&v).unwrap()).is_err());
    }
    #[test]
    fn unsigned_layouts_link_exact_outpoints_and_never_contain_signatures() {
        let p = fixture();
        let r = review(&p).unwrap();
        let txs = r["transactions"].as_array().unwrap();
        for (n, t) in txs.iter().enumerate() {
            let rpc: RpcTransaction = serde_json::from_value(t["unsigned_rpc"].clone()).unwrap();
            let tx = Transaction::try_from(rpc).unwrap();
            assert_eq!(tx.id().to_string(), t["transaction_id"]);
            assert!(tx.inputs[0].signature_script.is_empty());
            assert_eq!(tx.version, 1);
            assert_eq!(tx.lock_time, 0);
            assert_eq!(tx.gas, 0);
            assert_eq!(tx.inputs[0].sequence, 0);
            assert_eq!(
                tx.inputs[0].compute_commit,
                kaspa_consensus_core::tx::ComputeCommit::ComputeBudget(100.into())
            );
            if n == 0 {
                assert_eq!(
                    tx.inputs[0].previous_outpoint.transaction_id.to_string(),
                    p.source.transaction_id
                );
                assert_eq!(tx.inputs[0].previous_outpoint.index, p.source.index);
                assert_eq!(
                    tx.outputs[0].script_public_key,
                    pay_to_address_script(&address(&p.ticket_key).unwrap())
                );
                assert_eq!(
                    tx.outputs[1].script_public_key,
                    pay_to_address_script(&address(&p.funding_key).unwrap())
                );
            } else {
                assert_eq!(
                    tx.outputs[0].script_public_key,
                    pay_to_address_script(&address(&p.return_key).unwrap())
                );
            }
            assert_eq!(tx.outputs.len(), if n == 0 { 2 } else { 1 });
            assert_eq!(
                tx.outputs[0].value,
                if n == 0 { TICKET } else { TICKET - FEE }
            );
            if n > 0 {
                assert_eq!(
                    tx.inputs[0].previous_outpoint.transaction_id.to_string(),
                    txs[0]["transaction_id"]
                );
                assert_eq!(tx.inputs[0].previous_outpoint.index, 0);
            }
        }
        assert_ne!(txs[1]["transaction_id"], txs[2]["transaction_id"]);
        assert_eq!(r["vm_verified"], false);
        assert_eq!(r["signatures_created"], 0);
    }
    #[test]
    fn operator_public_keys_need_no_private_material() {
        let p = operator();
        assert!(review(&p).is_ok());
    }
    #[test]
    fn known_fixture_relabeling_aliases_and_invalid_curve_keys_fail() {
        let mut p = fixture();
        p.purpose = "operator-unsigned-review".into();
        assert!(review(&p).is_err());
        for k in LAB_KEYS.into_iter().chain([COLD_FIXTURE_KEY]) {
            let mut p = operator();
            p.return_key = k.into();
            assert!(review(&p).is_err());
        }
        let mut p = operator();
        p.ticket_key = p.funding_key.clone();
        assert!(review(&p).is_err());
        let mut p = operator();
        p.return_key = "00".repeat(32);
        assert!(review(&p).is_err());
    }
    #[test]
    fn wrong_network_namespace_and_amount_fail() {
        let mut p = fixture();
        p.network = "mainnet".into();
        assert!(review(&p).is_err());
        let mut p = fixture();
        p.namespace = "icp-native-ticket-n0".into();
        assert!(review(&p).is_err());
        for amount in [0, 23_999_999, 100_000_001, u64::MAX] {
            let mut p = fixture();
            p.source.amount = amount;
            assert!(review(&p).is_err());
        }
    }
    #[test]
    fn canonical_closed_schema_rejects_ambiguity() {
        let p = fixture();
        let raw = String::from_utf8(canonical(&p).unwrap()).unwrap();
        assert!(Plan::parse(raw.as_bytes()).is_ok());
        for bad in [
            format!(" {raw}"),
            raw.replacen('{', "{\"extra\":0,", 1),
            raw.replacen('{', "{\"network\":\"testnet-10\",", 1),
            raw.replace("24000000", "24000000.0"),
            raw.replace("24000000", "true"),
            " ".repeat(16385),
        ] {
            assert!(Plan::parse(bad.as_bytes()).is_err());
        }
    }
    #[test]
    fn all_previews_bind_run_source_and_evidence() {
        let p = operator();
        let original = review(&p).unwrap();
        for field in [0, 1, 2] {
            let mut q = p.clone();
            match field {
                0 => q.run_nonce = "66".repeat(32),
                1 => q.source.index = 1,
                _ => q.evidence_digest = "88".repeat(32),
            }
            let changed = review(&q).unwrap();
            assert_ne!(changed["review_id"], original["review_id"]);
            for n in 0..3 {
                assert_ne!(
                    changed["transactions"][n]["transaction_id"],
                    original["transactions"][n]["transaction_id"]
                );
            }
        }
    }
    #[test]
    fn maximum_index_and_amount_boundary_have_exact_change() {
        for amount in [24_000_000, 100_000_000] {
            let mut p = operator();
            p.source.index = u32::MAX;
            p.source.amount = amount;
            let r = review(&p).unwrap();
            assert_eq!(
                r["transactions"][0]["unsigned_rpc"]["inputs"][0]["previousOutpoint"]["index"],
                u32::MAX
            );
            assert_eq!(
                r["transactions"][0]["unsigned_rpc"]["outputs"][1]["value"],
                amount - TICKET - FEE
            );
        }
    }
    #[test]
    fn payloads_cannot_be_mistaken_for_lab0_or_n0() {
        let r = review(&fixture()).unwrap();
        for t in r["transactions"].as_array().unwrap() {
            let raw = decode_hex(t["unsigned_rpc"]["payload"].as_str().unwrap()).unwrap();
            let action = t["action"].as_str().unwrap();
            assert!(
                raw.starts_with(format!("ICP-RT-{}-TN10-P0\0", action.to_uppercase()).as_bytes())
            );
            assert!(!raw.windows(3).any(|w| w == b"N0\0"));
            assert!(!raw.windows(5).any(|w| w == b"LAB0\0"));
        }
    }
}
