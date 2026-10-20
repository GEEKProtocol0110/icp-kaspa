//! Offline private channel only. No key generation, files, node or submission.
#[path = "support/ticket_pilot.rs"]
mod pilot;
use kaspa_consensus_core::{
    hashing::{
        sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash},
        sighash_type::SIG_HASH_ALL,
    },
    tx::{MutableTransaction, PopulatedTransaction, Transaction, UtxoEntry},
};
use kaspa_rpc_core::RpcTransaction;
use kaspa_txscript::{
    EngineCtx, EngineFlags, TxScriptEngine, caches::Cache, script_builder::ScriptBuilder,
    standard::pay_to_address_script,
};
use pilot::{Plan, Result, address, hex32, review};
use secp256k1::{Keypair, Message};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::{self, Read};
const MODE: &str = "OFFLINE_P0_PRIVATE_SIGNED_NOT_CHAIN_PROOF";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    mode: String,
    plan: Plan,
    action: String,
    entry: UtxoEntry,
    signed_rpc: RpcTransaction,
    transaction_id: String,
    full_hash: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Prepare {
    plan: Plan,
    action: String,
    entry: UtxoEntry,
    secret_key: String,
}
// The private entry has a typed coinbase boolean. The public plan retains its
// stricter codec; private wire values additionally allow booleans.
fn canonical<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    fn check(v: &Value) -> bool {
        match v {
            Value::Null | Value::Bool(_) => true,
            Value::String(s) => s.is_ascii(),
            Value::Number(n) => n.as_u64().is_some_and(|n| n < (1u64 << 53)),
            Value::Array(a) => a.iter().all(check),
            Value::Object(m) => m.iter().all(|(k, v)| k.is_ascii() && check(v)),
        }
    }
    let v = serde_json::to_value(v).map_err(|_| "Invalid private value")?;
    if !check(&v) {
        return Err("Invalid private wire encoding".into());
    }
    serde_json::to_vec(&v).map_err(|_| "Private encoding failed".into())
}
fn parse<T: serde::de::DeserializeOwned + Serialize>(raw: &[u8]) -> Result<T> {
    if raw.len() > 65536 || !raw.is_ascii() {
        return Err("Bounded canonical private input required".into());
    }
    let v: T = serde_json::from_slice(raw).map_err(|_| "Closed private schema required")?;
    if canonical(&v)? != raw {
        return Err("Canonical private input required".into());
    }
    Ok(v)
}
fn material(p: &Plan, action: &str, entry: &UtxoEntry) -> Result<Transaction> {
    // Reuse exactly the unsigned public review semantics, including fixture rejection.
    Plan::parse(&pilot::canonical(p)?)?;
    if p.purpose != "operator-unsigned-review" {
        return Err("Public fixtures cannot be privately prepared".into());
    }
    let (index, key, amount) = match action {
        "issue" => (0, &p.funding_key, p.source.amount),
        "consume" => (1, &p.ticket_key, 12_000_000),
        "refund" => (2, &p.ticket_key, 12_000_000),
        _ => return Err("Invalid P0 action".into()),
    };
    if entry.amount != amount
        || entry.script_public_key != pay_to_address_script(&address(key)?)
        || entry.is_coinbase
        || entry.covenant_id.is_some()
    {
        return Err("Exact asserted ordinary P2PK entry required".into());
    }
    let rpc: RpcTransaction =
        serde_json::from_value(review(p)?["transactions"][index]["unsigned_rpc"].clone())
            .map_err(|e| e.to_string())?;
    let tx = Transaction::try_from(rpc).map_err(|e| e.to_string())?;
    icp_testnet::commit_storage_mass(&tx, std::slice::from_ref(entry)).map_err(str::to_string)?;
    Ok(tx)
}
fn vm(tx: &Transaction, entry: &UtxoEntry) -> Result<()> {
    let populated = PopulatedTransaction::new(tx, vec![entry.clone()]);
    let cache = Cache::new(1000);
    let reuse = SigHashReusedValuesUnsync::new();
    TxScriptEngine::from_transaction_input_with_script_units_limit(
        &populated,
        &tx.inputs[0],
        0,
        entry,
        EngineCtx::new(&cache).with_reused(&reuse),
        EngineFlags {
            covenants_enabled: true,
            ..Default::default()
        },
        tx.inputs[0].compute_commit.allowed_script_units(),
    )
    .execute()
    .map_err(|e| e.to_string())?;
    Ok(())
}
fn verify(r: &Record) -> Result<Value> {
    if r.mode != MODE {
        return Err("Wrong private profile".into());
    }
    let mut expected = material(&r.plan, &r.action, &r.entry)?;
    let tx = Transaction::try_from(r.signed_rpc.clone()).map_err(|e| e.to_string())?;
    if tx.inputs.len() != 1 {
        return Err("Wrong input count".into());
    }
    let sig = &tx.inputs[0].signature_script;
    if sig.len() != 66 || sig[0] != 65 || sig[65] != SIG_HASH_ALL.to_u8() {
        return Err("Expected minimal Schnorr SIG_HASH_ALL push".into());
    }
    // Comparing the normalized RPC checks every field, including budgets and mass
    // excluded from native ID. Requiring an exact roundtrip also rejects verbose/extra RPC data.
    expected.inputs[0].signature_script = tx.inputs[0].signature_script.clone();
    expected.finalize();
    let normalized = RpcTransaction::from(&tx);
    if canonical(&r.signed_rpc)? != canonical(&normalized)?
        || canonical(&normalized)? != canonical(&RpcTransaction::from(&expected))?
        || tx.id().to_string() != r.transaction_id
        || kaspa_consensus_core::hashing::tx::hash(&tx).to_string() != r.full_hash
    {
        return Err("Signed outbox differs from exact P0 semantics".into());
    }
    vm(&tx, &r.entry)?;
    Ok(
        json!({"mode":MODE,"action":r.action,"transaction_id":r.transaction_id,"full_hash":r.full_hash,
        "review_id":review(&r.plan)?["review_id"],"vm_verified":true,"source_observed":false,"broadcasts":0}),
    )
}
fn prepare(req: Prepare) -> Result<Record> {
    let mut tx = material(&req.plan, &req.action, &req.entry)?;
    hex32(&req.secret_key)?;
    let key = Keypair::from_seckey_str(secp256k1::SECP256K1, &req.secret_key)
        .map_err(|_| "Invalid private key")?;
    let role = if req.action == "issue" {
        &req.plan.funding_key
    } else {
        &req.plan.ticket_key
    };
    if key.x_only_public_key().0.to_string() != *role {
        return Err("Wrong private role key".into());
    }
    let mutable = MutableTransaction::with_entries(tx.clone(), vec![req.entry.clone()]);
    let h = calc_schnorr_signature_hash(
        &mutable.as_verifiable(),
        0,
        SIG_HASH_ALL,
        &SigHashReusedValuesUnsync::new(),
    );
    let mut sig = key
        .sign_schnorr(Message::from_digest_slice(&h.as_bytes()).map_err(|_| "Invalid digest")?)
        .as_ref()
        .to_vec();
    sig.push(SIG_HASH_ALL.to_u8());
    let mut script = ScriptBuilder::new();
    script.add_data(&sig).map_err(|e| e.to_string())?;
    tx.inputs[0].signature_script = script.drain();
    tx.finalize();
    let r = Record {
        mode: MODE.into(),
        plan: req.plan,
        action: req.action,
        entry: req.entry,
        transaction_id: tx.id().to_string(),
        full_hash: kaspa_consensus_core::hashing::tx::hash(&tx).to_string(),
        signed_rpc: RpcTransaction::from(&tx),
    };
    verify(&r)?;
    Ok(r)
}
fn run(op: &str, raw: &[u8]) -> Result<Vec<u8>> {
    match op {
        "prepare" => canonical(&prepare(parse(raw)?)?),
        "verify" => canonical(&verify(&parse(raw)?)?),
        _ => Err("Only private prepare/verify are available".into()),
    }
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 {
        return Err("Expected private prepare or verify".into());
    }
    let mut raw = Vec::new();
    io::stdin()
        .take(65537)
        .read_to_end(&mut raw)
        .map_err(|_| "Private read failed")?;
    // Deliberately suppress parse details and all private input on the error path.
    let reply = run(&args[1], &raw).map_err(|_| "Private P0 request rejected".to_string())?;
    use std::io::Write;
    io::stdout()
        .write_all(&reply)
        .map_err(|_| "Private write failed".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Secp256k1, rand::thread_rng};
    fn request(action: &str) -> Prepare {
        let key = || Keypair::new(&Secp256k1::new(), &mut thread_rng());
        let (f, t, r) = (key(), key(), key());
        let p = Plan {
            namespace: "icp-ticket-pilot-review-p0".into(),
            network: "testnet-10".into(),
            purpose: "operator-unsigned-review".into(),
            run_nonce: "55".repeat(32),
            evidence_digest: "77".repeat(32),
            funding_key: f.x_only_public_key().0.to_string(),
            ticket_key: t.x_only_public_key().0.to_string(),
            return_key: r.x_only_public_key().0.to_string(),
            source: pilot::Source {
                transaction_id: "22".repeat(32),
                index: 0,
                amount: 24_000_000,
            },
        };
        let issue = action == "issue";
        let entry = UtxoEntry::new(
            if issue { p.source.amount } else { 12_000_000 },
            pay_to_address_script(
                &address(if issue { &p.funding_key } else { &p.ticket_key }).unwrap(),
            ),
            123,
            false,
            None,
        );
        Prepare {
            plan: p,
            action: action.into(),
            entry,
            secret_key: if issue { f } else { t }.display_secret().to_string(),
        }
    }
    #[test]
    fn all_actions_are_signed_vm_checked_and_match_unsigned_ids() {
        for action in ["issue", "consume", "refund"] {
            let req = request(action);
            let index = if action == "issue" {
                0
            } else if action == "consume" {
                1
            } else {
                2
            };
            let id = review(&req.plan).unwrap()["transactions"][index]["transaction_id"].clone();
            let r = prepare(req).unwrap();
            assert_eq!(r.transaction_id, id);
            assert!(verify(&r).is_ok());
            assert!(!r.signed_rpc.inputs[0].signature_script.is_empty());
        }
    }
    #[test]
    fn exact_semantics_and_full_hash_required_even_when_id_unchanged() {
        let mut r = prepare(request("issue")).unwrap();
        r.signed_rpc.storage_mass += 1;
        assert!(verify(&r).is_err());
        let mut r = prepare(request("issue")).unwrap();
        r.full_hash = "00".repeat(32);
        assert!(verify(&r).is_err());
        let mut r = prepare(request("issue")).unwrap();
        r.signed_rpc.outputs[0].value -= 1;
        assert!(verify(&r).is_err());
    }
    #[test]
    fn wrong_role_entry_and_fixture_modes_fail() {
        let mut q = request("issue");
        q.secret_key = "01".repeat(32);
        assert!(prepare(q).is_err());
        let mut q = request("issue");
        q.entry.amount -= 1;
        assert!(prepare(q).is_err());
        let mut q = request("issue");
        q.entry.is_coinbase = true;
        assert!(prepare(q).is_err());
        let mut q = request("issue");
        q.plan.purpose = "public-fixture-never-fund".into();
        assert!(prepare(q).is_err());
    }
    #[test]
    fn signatures_and_action_are_verified() {
        let mut r = prepare(request("consume")).unwrap();
        r.action = "refund".into();
        assert!(verify(&r).is_err());
        let mut r = prepare(request("issue")).unwrap();
        r.signed_rpc.inputs[0].signature_script.clear();
        assert!(verify(&r).is_err());
    }
    #[test]
    fn private_channel_is_closed_canonical_and_effect_free() {
        let raw = canonical(&request("issue")).unwrap();
        assert!(run("prepare", &raw).is_ok());
        for op in ["broadcast", "submit", "keygen"] {
            assert!(run(op, &raw).is_err());
        }
        let mut bad = vec![b' '];
        bad.extend(&raw);
        assert!(run("prepare", &bad).is_err());
        assert!(run("prepare", &vec![b' '; 65537]).is_err());
    }
}
