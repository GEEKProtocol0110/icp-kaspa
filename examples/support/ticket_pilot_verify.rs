//! Shared closed P0 record verification; no key loader, signing or network effects.
#[path = "ticket_pilot.rs"]
pub(crate) mod pilot;
use kaspa_consensus_core::{
    hashing::{sighash::SigHashReusedValuesUnsync, sighash_type::SIG_HASH_ALL},
    tx::{PopulatedTransaction, Transaction, UtxoEntry},
};
use kaspa_rpc_core::RpcTransaction;
use kaspa_txscript::{
    EngineCtx, EngineFlags, TxScriptEngine, caches::Cache, standard::pay_to_address_script,
};
use pilot::{Plan, Result, address, review};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
pub(crate) const MODE: &str = "OFFLINE_P0_PRIVATE_SIGNED_NOT_CHAIN_PROOF";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    pub(crate) mode: String,
    pub(crate) plan: Plan,
    pub(crate) action: String,
    pub(crate) entry: UtxoEntry,
    pub(crate) signed_rpc: RpcTransaction,
    pub(crate) transaction_id: String,
    pub(crate) full_hash: String,
}
// The private entry has a typed coinbase boolean. The public plan retains its
// stricter codec; private wire values additionally allow booleans.
pub(crate) fn canonical<T: Serialize>(v: &T) -> Result<Vec<u8>> {
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
pub(crate) fn parse<T: serde::de::DeserializeOwned + Serialize>(raw: &[u8]) -> Result<T> {
    if raw.len() > 65536 || !raw.is_ascii() {
        return Err("Bounded canonical private input required".into());
    }
    let v: T = serde_json::from_slice(raw).map_err(|_| "Closed private schema required")?;
    if canonical(&v)? != raw {
        return Err("Canonical private input required".into());
    }
    Ok(v)
}
pub(crate) fn material(p: &Plan, action: &str, entry: &UtxoEntry) -> Result<Transaction> {
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
pub(crate) fn verify(r: &Record) -> Result<Value> {
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
