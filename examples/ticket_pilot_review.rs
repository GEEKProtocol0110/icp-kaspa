//! Unsigned P0 pilot review only. No key loading, signing, RPC or submission.
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::tx::{
    Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_rpc_core::RpcTransaction;
use kaspa_txscript::standard::pay_to_address_script;
use secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use silverscript_abi::{decode_hex, encode_hex};
use std::io::{self, Read};

type Result<T> = std::result::Result<T, String>;
const FEE: u64 = 2_000_000;
const TICKET: u64 = 12_000_000;
const COLD_FIXTURE_KEY: &str = "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13";
const LAB_KEYS: [&str; 3] = [
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
];

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    transaction_id: String,
    index: u32,
    amount: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    namespace: String,
    network: String,
    purpose: String,
    run_nonce: String,
    evidence_digest: String,
    funding_key: String,
    ticket_key: String,
    return_key: String,
    source: Source,
}
fn canonical<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    icp_testnet::native_ticket_lab::canonical(v)
}
fn hex32(s: &str) -> Result<()> {
    let b = decode_hex(s).map_err(|e| e.to_string())?;
    if b.len() != 32 || encode_hex(&b) != s {
        return Err("Expected lowercase 32-byte hex".into());
    }
    Ok(())
}
fn digest(domain: &[u8], raw: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(raw);
    encode_hex(&h.finalize())
}
fn address(key: &str) -> Result<Address> {
    hex32(key)?;
    let key: XOnlyPublicKey = key
        .parse()
        .map_err(|e| format!("Invalid native key: {e}"))?;
    Ok(Address::new(
        Prefix::Testnet,
        Version::PubKey,
        &key.serialize(),
    ))
}
impl Plan {
    fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() > 16384 || !raw.is_ascii() {
            return Err("Bounded ASCII plan required".into());
        }
        let p: Self = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
        if canonical(&p)? != raw {
            return Err("Canonical closed plan required".into());
        }
        p.validate()?;
        Ok(p)
    }
    fn validate(&self) -> Result<()> {
        if self.namespace != "icp-ticket-pilot-review-p0"
            || self.network != "testnet-10"
            || !(24_000_000..=100_000_000).contains(&self.source.amount)
        {
            return Err("Wrong pilot profile, network or amount".into());
        }
        for s in [
            &self.run_nonce,
            &self.evidence_digest,
            &self.source.transaction_id,
        ] {
            hex32(s)?;
        }
        if self.run_nonce == "00".repeat(32) {
            return Err("Nonzero run nonce required".into());
        }
        let keys = [
            self.funding_key.as_str(),
            self.ticket_key.as_str(),
            self.return_key.as_str(),
        ];
        for k in keys {
            address(k)?;
        }
        if keys[0] == keys[1] || keys[0] == keys[2] || keys[1] == keys[2] {
            return Err("Distinct native roles required".into());
        }
        match self.purpose.as_str() {
            "public-fixture-never-fund"
                if keys == LAB_KEYS
                    && self.source.transaction_id == "11".repeat(32)
                    && self.source.index == 0
                    && self.run_nonce == "44".repeat(32) =>
            {
                ()
            }
            "operator-unsigned-review"
                if keys
                    .iter()
                    .all(|k| !LAB_KEYS.contains(k) && *k != COLD_FIXTURE_KEY)
                    && self.source.transaction_id != "00".repeat(32)
                    && self.source.transaction_id != "11".repeat(32)
                    && self.run_nonce != "44".repeat(32) =>
            {
                ()
            }
            _ => {
                return Err(
                    "Invalid purpose, known native lab key/source or fixture relabeling".into(),
                );
            }
        }
        Ok(())
    }
}
fn unsigned(
    point: TransactionOutpoint,
    amount: u64,
    key: &str,
    outputs: Vec<TransactionOutput>,
    payload: Vec<u8>,
) -> Result<Transaction> {
    let tx = Transaction::new(
        1,
        vec![TransactionInput::new_with_compute_budget(
            point,
            vec![],
            0,
            100,
        )],
        outputs,
        0,
        Default::default(),
        0,
        payload,
    );
    let entry = UtxoEntry::new(
        amount,
        pay_to_address_script(&address(key)?),
        0,
        false,
        None,
    );
    icp_testnet::commit_storage_mass(&tx, &[entry]).map_err(str::to_string)?;
    Ok(tx)
}
fn payload(action: &str, commitment: &str) -> Result<Vec<u8>> {
    let mut p = format!("ICP-RT-{}-TN10-P0\0", action.to_uppercase()).into_bytes();
    p.extend(decode_hex(commitment).map_err(|e| e.to_string())?);
    Ok(p)
}
fn review(p: &Plan) -> Result<Value> {
    p.validate()?;
    let id = digest(b"icp/ticket-pilot-review/p0\0", &canonical(p)?);
    let issue = unsigned(
        TransactionOutpoint {
            transaction_id: p
                .source
                .transaction_id
                .parse()
                .map_err(|e| format!("{e}"))?,
            index: p.source.index,
        },
        p.source.amount,
        &p.funding_key,
        vec![
            TransactionOutput::new(TICKET, pay_to_address_script(&address(&p.ticket_key)?)),
            TransactionOutput::new(
                p.source.amount - TICKET - FEE,
                pay_to_address_script(&address(&p.funding_key)?),
            ),
        ],
        payload("issue", &id)?,
    )?;
    let mut txs = vec![("issue", issue.clone())];
    for action in ["consume", "refund"] {
        let body = json!({"review_id":id,"issue_id":issue.id().to_string(),"index":0});
        let terminal = digest(
            format!("icp/ticket-pilot-review/p0/{action}\0").as_bytes(),
            &canonical(&body)?,
        );
        txs.push((
            action,
            unsigned(
                TransactionOutpoint {
                    transaction_id: issue.id(),
                    index: 0,
                },
                TICKET,
                &p.ticket_key,
                vec![TransactionOutput::new(
                    TICKET - FEE,
                    pay_to_address_script(&address(&p.return_key)?),
                )],
                payload(action, &terminal)?,
            )?,
        ));
    }
    Ok(
        json!({"mode":"UNSIGNED_P0_REVIEW_NOT_FUNDING_AUTHORIZATION","review_id":id,"purpose":p.purpose,
        "network":"testnet-10","source_observed":false,"vm_verified":false,"signatures_created":0,"rpc_calls":0,"broadcasts":0,
        "maximum_lifecycle_fee":2*FEE,
        "roles":{"funding":address(&p.funding_key)?.to_string(),"ticket":address(&p.ticket_key)?.to_string(),"return":address(&p.return_key)?.to_string()},
        "transactions":txs.iter().map(|(action,tx)|json!({"action":action,"transaction_id":tx.id().to_string(),
            "fee":FEE,"unsigned_rpc":RpcTransaction::from(tx)})).collect::<Vec<_>>()}),
    )
}
fn main() -> Result<()> {
    if std::env::args().len() != 1 {
        return Err("Usage: ticket_pilot_review < canonical-public-plan.json".into());
    }
    let mut raw = Vec::new();
    io::stdin()
        .take(16385)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    println!(
        "{}",
        serde_json::to_string(&review(&Plan::parse(&raw)?)?).map_err(|e| e.to_string())?
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
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
