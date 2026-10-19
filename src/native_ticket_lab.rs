//! Fixture-only native transaction experiment. No network, external keys or authorization.
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::{
    hashing::{
        sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash},
        sighash_type::SIG_HASH_ALL,
        tx::hash,
    },
    tx::{
        MutableTransaction, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionInput,
        TransactionOutpoint, TransactionOutput, UtxoEntry,
    },
};
use kaspa_txscript::{
    EngineCtx, EngineFlags, TxScriptEngine, caches::Cache, script_builder::ScriptBuilder,
    standard::pay_to_address_script,
};
use secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use silverscript_abi::{decode_hex, encode_hex};

pub type Result<T> = std::result::Result<T, String>;
pub const MODE: &str = "OFFLINE_NATIVE_FIXTURES_NO_CHAIN_NO_AUTHORIZATION";
pub const NAMESPACE: &str = "icp-native-ticket-lab-v0";
pub const FEE: u64 = 2_000_000;
pub const TICKET: u64 = 12_000_000;
const MAX_JSON: usize = 16_384;
const MAX_INT: u64 = (1 << 53) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Issue,
    Consume,
    Refund,
}
impl Action {
    fn label(self) -> &'static str {
        match self {
            Self::Issue => "issue",
            Self::Consume => "consume",
            Self::Refund => "refund",
        }
    }
    fn prefix(self) -> &'static [u8] {
        match self {
            Self::Issue => b"ICP-RT-ISSUE-TN10-LAB0\0",
            Self::Consume => b"ICP-RT-CONSUME-TN10-LAB0\0",
            Self::Refund => b"ICP-RT-REFUND-TN10-LAB0\0",
        }
    }
}

/// These digests are invented inputs, not verified approvals, records or certificates.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub service: String,
    pub budget: String,
    pub grant: String,
    pub intent_nonce: String,
    pub policy: String,
    pub record: String,
    pub ciphertext: String,
    pub ciphertext_bytes: u64,
    pub delivery_binding: String,
    pub dual_approval: String,
    pub policy_epoch: u64,
    pub delivery_epoch: u64,
    pub not_before: u64,
    pub expires: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub transaction_id: String,
    pub output_index: u32,
    pub amount: u64,
    pub script: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Admission {
    pub request_digest: String,
    pub window_start: u64,
    pub window_end: u64,
    pub original_deadline: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Closure {
    pub reason: String,
    pub sequence: u64,
    pub closure_digest: String,
    pub cleanup_approval: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub namespace: String,
    pub mode: String,
    pub network: String,
    pub profile: String,
    pub action: Action,
    pub funding_transaction_id: String,
    pub funding_index: u32,
    pub funding_amount: u64,
    pub funding_key: String,
    pub ticket_key: String,
    pub return_key: String,
    pub context: Context,
    pub issuance: Option<Binding>,
    pub admission: Option<Admission>,
    pub closure: Option<Closure>,
}

fn digest(raw: &[u8]) -> String {
    encode_hex(&Sha256::digest(raw))
}

pub fn canonical<T: Serialize>(object: &T) -> Result<Vec<u8>> {
    fn check(v: &Value) -> Result<()> {
        match v {
            Value::Number(n) if n.as_u64().is_some_and(|x| x <= MAX_INT) => Ok(()),
            Value::String(s) if s.is_ascii() => Ok(()),
            Value::Null => Ok(()),
            Value::Array(a) => {
                for v in a {
                    check(v)?;
                }
                Ok(())
            }
            Value::Object(o) => {
                for (k, v) in o {
                    if !k.is_ascii() {
                        return Err("Non-ASCII key".into());
                    }
                    check(v)?;
                }
                Ok(())
            }
            _ => Err("Only ASCII strings, bounded unsigned integers and null are allowed".into()),
        }
    }
    let mut value = serde_json::to_value(object).map_err(|e| e.to_string())?;
    check(&value)?;
    value.sort_all_objects();
    let raw = serde_json::to_vec(&value).map_err(|e| e.to_string())?;
    if raw.len() > MAX_JSON {
        return Err("Oversized fixture object".into());
    }
    Ok(raw)
}

fn hex32(s: &str) -> Result<()> {
    let b = decode_hex(s).map_err(|_| "Invalid digest")?;
    if b.len() != 32 || encode_hex(&b) != s {
        return Err("Expected lowercase 32-byte hex".into());
    }
    Ok(())
}

fn label(s: &str) -> Result<()> {
    if !s.starts_with("model:")
        || s.len() > 96
        || s.len() <= 6
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b":-_".contains(&b))
    {
        return Err("Expected bounded model label".into());
    }
    Ok(())
}

// Known public scalar keys. No loader, user-supplied secret or live signer exists.
fn key(role: u8) -> Keypair {
    let mut bytes = [0; 32];
    bytes[31] = role;
    Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&bytes).unwrap())
}
fn public(role: u8) -> String {
    encode_hex(&key(role).x_only_public_key().0.serialize())
}
fn script(role: u8) -> ScriptPublicKey {
    pay_to_address_script(&Address::new(
        Prefix::Testnet,
        Version::PubKey,
        &key(role).x_only_public_key().0.serialize(),
    ))
}

impl Plan {
    pub fn from_json(raw: &[u8]) -> Result<Self> {
        if raw.len() > MAX_JSON || !raw.is_ascii() {
            return Err("Invalid fixture input size/encoding".into());
        }
        let p: Self = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
        // Typed decoding rejects duplicate known fields; canonical equality rejects
        // alternate whitespace, escaped keys, numbers and trailing material.
        if canonical(&p)? != raw {
            return Err("Noncanonical fixture plan".into());
        }
        p.validate()?;
        Ok(p)
    }

    fn issue_plan(&self) -> Self {
        let mut p = self.clone();
        p.action = Action::Issue;
        p.issuance = None;
        p.admission = None;
        p.closure = None;
        p
    }

    pub fn validate(&self) -> Result<()> {
        canonical(self)?;
        if self.namespace != NAMESPACE
            || self.mode != MODE
            || self.network != "testnet-10"
            || self.profile != "n0-layout-lab-v0"
            || self.funding_transaction_id != "11".repeat(32)
            || self.funding_index != 0
            || !(24_000_000..=100_000_000).contains(&self.funding_amount)
            || self.funding_key != public(1)
            || self.ticket_key != public(2)
            || self.return_key != public(3)
        {
            return Err("Expected exact offline fixture policy/source".into());
        }
        let c = &self.context;
        for s in [&c.service, &c.budget, &c.grant] {
            label(s)?;
        }
        for s in [
            &c.intent_nonce,
            &c.policy,
            &c.record,
            &c.ciphertext,
            &c.delivery_binding,
            &c.dual_approval,
        ] {
            hex32(s)?;
        }
        if c.ciphertext_bytes == 0 || c.not_before >= c.expires {
            return Err("Invalid fixture record/deadline".into());
        }
        match self.action {
            Action::Issue => {
                if self.issuance.is_some() || self.admission.is_some() || self.closure.is_some() {
                    return Err("Issue cannot bind future IDs or terminal evidence".into());
                }
            }
            Action::Consume | Action::Refund => {
                let issue = unsigned(&self.issue_plan())?;
                if self.issuance.as_ref() != Some(&binding(&issue)) {
                    return Err("Exact fabricated issuance binding mismatch".into());
                }
                if self.action == Action::Consume {
                    let a = self.admission.as_ref().ok_or("Missing fixture admission")?;
                    hex32(&a.request_digest)?;
                    if self.closure.is_some()
                        || a.window_start < c.not_before
                        || a.window_start >= a.window_end
                        || a.window_end > c.expires
                        || a.original_deadline <= a.window_start
                        || a.original_deadline > a.window_end
                    {
                        return Err("Invalid consume fixture bounds".into());
                    }
                } else {
                    let x = self.closure.as_ref().ok_or("Missing fixture closure")?;
                    hex32(&x.closure_digest)?;
                    hex32(&x.cleanup_approval)?;
                    if self.admission.is_some()
                        || x.sequence == 0
                        || !["expired", "revoked"].contains(&x.reason.as_str())
                    {
                        return Err("Refund cannot carry reservation evidence".into());
                    }
                }
            }
        }
        Ok(())
    }

    pub fn commitment(&self) -> Result<String> {
        let mut raw = format!("icp/native-ticket-lab/v0/{}\0", self.action.label()).into_bytes();
        raw.extend(canonical(self)?);
        Ok(digest(&raw))
    }

    fn source(&self) -> Result<TransactionOutpoint> {
        let (id, index) = match &self.issuance {
            Some(b) => (&b.transaction_id, b.output_index),
            None => (&self.funding_transaction_id, self.funding_index),
        };
        Ok(TransactionOutpoint {
            transaction_id: id.parse().map_err(|_| "Invalid transaction ID")?,
            index,
        })
    }

    pub fn entry(&self) -> UtxoEntry {
        let (amount, role) = if self.action == Action::Issue {
            (self.funding_amount, 1)
        } else {
            (TICKET, 2)
        };
        UtxoEntry::new(amount, script(role), 467_579_700, false, None)
    }
}

fn binding(issue: &Transaction) -> Binding {
    Binding {
        transaction_id: issue.id().to_string(),
        output_index: 0,
        amount: issue.outputs[0].value,
        script: encode_hex(issue.outputs[0].script_public_key.script()),
    }
}

fn unsigned(p: &Plan) -> Result<Transaction> {
    let mut payload = p.action.prefix().to_vec();
    payload.extend(decode_hex(&p.commitment()?).map_err(|e| e.to_string())?);
    let outputs = if p.action == Action::Issue {
        vec![
            TransactionOutput::new(TICKET, script(2)),
            TransactionOutput::new(
                p.funding_amount
                    .checked_sub(TICKET + FEE)
                    .ok_or("Underflow")?,
                script(1),
            ),
        ]
    } else {
        vec![TransactionOutput::new(TICKET - FEE, script(3))]
    };
    let tx = Transaction::new(
        1,
        vec![TransactionInput::new_with_compute_budget(
            p.source()?,
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
    crate::commit_storage_mass(&tx, &[p.entry()]).map_err(str::to_string)?;
    Ok(tx)
}

pub fn verify_vm(tx: &Transaction, entry: &UtxoEntry) -> Result<()> {
    if tx.inputs.len() != 1 {
        return Err("Expected sole fixture input".into());
    }
    let populated = PopulatedTransaction::new(tx, vec![entry.clone()]);
    let cache = Cache::new(1000);
    let reused = SigHashReusedValuesUnsync::new();
    TxScriptEngine::from_transaction_input_with_script_units_limit(
        &populated,
        &tx.inputs[0],
        0,
        entry,
        EngineCtx::new(&cache).with_reused(&reused),
        EngineFlags {
            covenants_enabled: true,
            ..Default::default()
        },
        tx.inputs[0].compute_commit.allowed_script_units(),
    )
    .execute()
    .map_err(|e| e.to_string())
}

fn sign(tx: &mut Transaction, entry: &UtxoEntry, signer: &Keypair) -> Result<()> {
    let mutable = MutableTransaction::with_entries(tx.clone(), vec![entry.clone()]);
    let hash = calc_schnorr_signature_hash(
        &mutable.as_verifiable(),
        0,
        SIG_HASH_ALL,
        &SigHashReusedValuesUnsync::new(),
    );
    let message = Message::from_digest_slice(&hash.as_bytes()).map_err(|e| e.to_string())?;
    let mut sig = Secp256k1::new()
        .sign_schnorr_no_aux_rand(&message, signer)
        .as_ref()
        .to_vec();
    sig.push(SIG_HASH_ALL.to_u8());
    let mut builder = ScriptBuilder::new();
    builder.add_data(&sig).map_err(|e| e.to_string())?;
    tx.inputs[0].signature_script = builder.drain();
    tx.finalize();
    Ok(())
}

/// Returns signed in-memory fixtures only. No outbox, persistence or live effect.
pub fn prepare(p: &Plan, entry: &UtxoEntry) -> Result<Transaction> {
    p.validate()?;
    if entry != &p.entry() {
        return Err("Exact fabricated UTXO mismatch".into());
    }
    let mut tx = unsigned(p)?;
    sign(
        &mut tx,
        entry,
        &key(if p.action == Action::Issue { 1 } else { 2 }),
    )?;
    check_prepared(p, &tx, entry)?;
    Ok(tx)
}

/// Policy/layout checking is stronger than ordinary P2PK script validity.
pub fn check_prepared(p: &Plan, tx: &Transaction, entry: &UtxoEntry) -> Result<()> {
    p.validate()?;
    if entry != &p.entry() {
        return Err("Fixture UTXO changed".into());
    }
    let expected = unsigned(p)?;
    let mut body = tx.clone();
    if body.inputs.len() != 1 {
        return Err("Fixture input count changed".into());
    }
    let sig = &body.inputs[0].signature_script;
    if sig.len() != 66 || sig[0] != 65 || sig[65] != SIG_HASH_ALL.to_u8() {
        return Err("Expected minimal Schnorr SIG_HASH_ALL push".into());
    }
    body.inputs[0].signature_script.clear();
    body.finalize();
    // Full native hash includes mass/compute, unlike the transaction ID.
    if hash(&body) != hash(&expected) || body.id() != expected.id() || tx.id() != body.id() {
        return Err("Prepared fixture layout/mass/compute mismatch".into());
    }
    verify_vm(tx, entry)
}

/// Full native hash pins signature, mass and compute against a trusted saved value.
pub fn check_saved(
    p: &Plan,
    tx: &Transaction,
    entry: &UtxoEntry,
    expected_hash: &str,
) -> Result<()> {
    check_prepared(p, tx, entry)?;
    if hash(tx).to_string() != expected_hash {
        return Err("Saved native transaction hash mismatch".into());
    }
    Ok(())
}

pub fn fixture_issue(amount: u64) -> Plan {
    Plan {
        namespace: NAMESPACE.into(),
        mode: MODE.into(),
        network: "testnet-10".into(),
        profile: "n0-layout-lab-v0".into(),
        action: Action::Issue,
        funding_transaction_id: "11".repeat(32),
        funding_index: 0,
        funding_amount: amount,
        funding_key: public(1),
        ticket_key: public(2),
        return_key: public(3),
        context: Context {
            service: "model:service".into(),
            budget: "model:budget".into(),
            grant: "model:grant".into(),
            intent_nonce: "20".repeat(32),
            policy: "21".repeat(32),
            record: "22".repeat(32),
            ciphertext: "23".repeat(32),
            ciphertext_bytes: 128,
            delivery_binding: "24".repeat(32),
            dual_approval: "25".repeat(32),
            policy_epoch: 0,
            delivery_epoch: 0,
            not_before: 100,
            expires: 200,
        },
        issuance: None,
        admission: None,
        closure: None,
    }
}

pub fn fixture_terminal(issue: &Plan, action: Action) -> Result<Plan> {
    if issue.action != Action::Issue || action == Action::Issue {
        return Err("Expected issue and terminal action".into());
    }
    let tx = prepare(issue, &issue.entry())?;
    let mut p = issue.clone();
    p.action = action;
    p.issuance = Some(binding(&tx));
    match action {
        Action::Consume => {
            p.admission = Some(Admission {
                request_digest: "26".repeat(32),
                window_start: 100,
                window_end: 180,
                original_deadline: 170,
            })
        }
        Action::Refund => {
            p.closure = Some(Closure {
                reason: "expired".into(),
                sequence: 1,
                closure_digest: "27".repeat(32),
                cleanup_approval: "28".repeat(32),
            })
        }
        Action::Issue => unreachable!(),
    }
    p.validate()?;
    Ok(p)
}

/// Public summary intentionally omits signed transaction bytes and private material.
pub fn summary(p: &Plan, tx: &Transaction) -> Result<Value> {
    check_prepared(p, tx, &p.entry())?;
    Ok(
        serde_json::json!({"mode": MODE, "plan": p, "action": p.action, "transaction_id": tx.id().to_string(),
        "native_hash": hash(tx).to_string(), "commitment": p.commitment()?, "payload": encode_hex(&tx.payload),
        "input": {"transaction_id": tx.inputs[0].previous_outpoint.transaction_id.to_string(), "index": tx.inputs[0].previous_outpoint.index},
        "outputs": tx.outputs.iter().map(|o| serde_json::json!({"amount":o.value,"script":encode_hex(o.script_public_key.script())})).collect::<Vec<_>>(),
        "fee": FEE, "storage_mass": tx.storage_mass(), "compute_budget": 100, "vm_verified": true}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::{hashing::sighash_type::SIG_HASH_NONE, tx::ComputeCommit};

    fn cases() -> Vec<Plan> {
        let issue = fixture_issue(24_000_000);
        vec![
            issue.clone(),
            fixture_terminal(&issue, Action::Consume).unwrap(),
            fixture_terminal(&issue, Action::Refund).unwrap(),
        ]
    }
    fn signed(p: &Plan) -> Transaction {
        prepare(p, &p.entry()).unwrap()
    }
    fn sig_hash(tx: &Transaction, entry: &UtxoEntry) -> String {
        let m = MutableTransaction::with_entries(tx.clone(), vec![entry.clone()]);
        calc_schnorr_signature_hash(
            &m.as_verifiable(),
            0,
            SIG_HASH_ALL,
            &SigHashReusedValuesUnsync::new(),
        )
        .to_string()
    }

    #[test]
    fn issue_and_both_alternative_terminal_layouts_verify() {
        for p in cases() {
            let tx = signed(&p);
            assert_eq!(tx.inputs.len(), 1);
            assert_eq!(tx.version, 1);
            assert_eq!(tx.inputs[0].sequence, 0);
            assert_eq!(tx.lock_time, 0);
            assert!(tx.subnetwork_id.is_native());
            assert_eq!(tx.gas, 0);
            assert_eq!(
                p.entry().amount - tx.outputs.iter().map(|o| o.value).sum::<u64>(),
                FEE
            );
            assert!(tx.outputs.iter().all(|o| o.covenant.is_none()));
            assert_eq!(
                tx.outputs.len(),
                if p.action == Action::Issue { 2 } else { 1 }
            );
            assert_eq!(
                tx.outputs[0].value,
                if p.action == Action::Issue {
                    TICKET
                } else {
                    TICKET - FEE
                }
            );
            verify_vm(&tx, &p.entry()).unwrap();
            check_saved(&p, &tx, &p.entry(), &hash(&tx).to_string()).unwrap();
        }
    }
    #[test]
    fn issuance_binding_links_to_real_native_fixture_id() {
        let plans = cases();
        let issue = signed(&plans[0]);
        for p in &plans[1..] {
            assert_eq!(p.issuance, Some(binding(&issue)));
            assert_eq!(
                signed(p).inputs[0].previous_outpoint.transaction_id,
                issue.id()
            );
            assert_eq!(signed(p).inputs[0].previous_outpoint.index, 0);
        }
    }
    #[test]
    fn canonical_plan_roundtrips_for_every_action() {
        for p in cases() {
            let raw = canonical(&p).unwrap();
            assert_eq!(Plan::from_json(&raw).unwrap(), p);
        }
    }
    #[test]
    fn noncanonical_duplicate_unknown_and_wrong_type_inputs_fail() {
        let raw = String::from_utf8(canonical(&fixture_issue(24_000_000)).unwrap()).unwrap();
        for bad in [
            format!(" {raw}"),
            format!("{raw}\n"),
            raw.replacen("{", "{\"extra\":0,", 1),
            raw.replacen("{", "{\"network\":\"testnet-10\",", 1),
            raw.replace("24000000", "24000000.0"),
            raw.replace("\"policy_epoch\":0", "\"policy_epoch\":false"),
            raw.replace("\"network\"", "\"net\\u0077ork\""),
            format!("{raw}{{}}"),
            " ".repeat(MAX_JSON + 1),
        ] {
            assert!(Plan::from_json(bad.as_bytes()).is_err());
        }
    }
    #[test]
    fn canonical_scalar_bounds_and_unicode_are_rejected() {
        for value in [
            serde_json::json!(-1),
            serde_json::json!(1.0),
            serde_json::json!(true),
            serde_json::json!(MAX_INT + 1),
            serde_json::json!("é"),
        ] {
            assert!(canonical(&value).is_err());
        }
        assert!(canonical(&serde_json::json!(MAX_INT)).is_ok());
    }
    #[test]
    fn network_mode_profile_and_external_source_are_refused() {
        let original = fixture_issue(24_000_000);
        for field in [
            "network",
            "namespace",
            "mode",
            "profile",
            "funding_transaction_id",
        ] {
            let mut v = serde_json::to_value(&original).unwrap();
            v[field] = serde_json::json!("invalid");
            assert!(Plan::from_json(&canonical(&v).unwrap()).is_err());
        }
        let mut p = original;
        p.funding_index = 1;
        assert!(p.validate().is_err());
    }
    #[test]
    fn only_distinct_known_fixture_native_keys_are_accepted() {
        for field in ["funding_key", "ticket_key", "return_key"] {
            for bad in [
                public(4),
                public(1),
                "ff".repeat(32),
                public(2).to_uppercase(),
            ] {
                let mut v = serde_json::to_value(fixture_issue(24_000_000)).unwrap();
                if v[field] == bad {
                    continue;
                }
                v[field] = serde_json::json!(bad);
                assert!(Plan::from_json(&canonical(&v).unwrap()).is_err());
            }
        }
    }
    #[test]
    fn funding_amount_boundaries_preserve_exact_change() {
        for amount in [24_000_000, 100_000_000] {
            let p = fixture_issue(amount);
            let tx = signed(&p);
            assert_eq!(tx.outputs[1].value, amount - TICKET - FEE);
            assert!(tx.outputs[1].value >= 10_000_000);
        }
        for amount in [0, 23_999_999, 100_000_001, u64::MAX] {
            let p = fixture_issue(amount);
            assert!(prepare(&p, &p.entry()).is_err());
        }
    }
    #[test]
    fn exact_source_amount_script_coinbase_daa_and_covenant_are_pinned() {
        let p = fixture_issue(24_000_000);
        let original = p.entry();
        for n in 0..5 {
            let mut u = original.clone();
            match n {
                0 => u.amount += 1,
                1 => u.script_public_key = script(2),
                2 => u.is_coinbase = true,
                3 => u.block_daa_score += 1,
                _ => u.covenant_id = Some("22".repeat(32).parse().unwrap()),
            }
            assert!(prepare(&p, &u).is_err());
        }
    }
    #[test]
    fn issue_rejects_future_issuance_and_terminal_evidence() {
        let plans = cases();
        for n in 0..3 {
            let mut p = plans[0].clone();
            match n {
                0 => p.issuance = plans[1].issuance.clone(),
                1 => p.admission = plans[1].admission.clone(),
                _ => p.closure = plans[2].closure.clone(),
            }
            assert!(p.validate().is_err());
        }
    }
    #[test]
    fn terminal_issuance_id_index_value_and_script_are_checked() {
        for mut p in cases().into_iter().skip(1) {
            let original = p.issuance.clone();
            for n in 0..4 {
                p.issuance = original.clone();
                let b = p.issuance.as_mut().unwrap();
                match n {
                    0 => b.transaction_id = "33".repeat(32),
                    1 => b.output_index = 1,
                    2 => b.amount += 1,
                    _ => b.script.push_str("00"),
                }
                assert!(p.validate().is_err());
            }
        }
    }
    #[test]
    fn reservation_and_closure_evidence_are_mutually_exclusive() {
        let plans = cases();
        let mut consume = plans[1].clone();
        let mut refund = plans[2].clone();
        consume.closure = refund.closure.clone();
        refund.admission = consume.admission.clone();
        assert!(consume.validate().is_err());
        assert!(refund.validate().is_err());
        consume.closure = None;
        consume.admission = None;
        assert!(consume.validate().is_err());
        refund.admission = None;
        refund.closure = None;
        assert!(refund.validate().is_err());
    }
    #[test]
    fn original_window_and_deadline_must_be_bounded() {
        for n in 0..5 {
            let mut p = cases()[1].clone();
            let a = p.admission.as_mut().unwrap();
            match n {
                0 => a.window_start = 99,
                1 => a.window_end = 201,
                2 => a.original_deadline = 181,
                3 => a.original_deadline = 100,
                _ => a.window_start = 180,
            }
            assert!(p.validate().is_err());
        }
        let mut p = cases()[2].clone();
        p.closure.as_mut().unwrap().reason = "retry".into();
        assert!(p.validate().is_err());
        p.closure.as_mut().unwrap().reason = "revoked".into();
        p.closure.as_mut().unwrap().sequence = 0;
        assert!(p.validate().is_err());
    }
    #[test]
    fn digest_encoding_and_model_labels_fail_closed() {
        let p = fixture_issue(24_000_000);
        for field in [
            "intent_nonce",
            "policy",
            "record",
            "ciphertext",
            "delivery_binding",
            "dual_approval",
        ] {
            for bad in ["".to_string(), "AB".repeat(32), "00".repeat(33)] {
                let mut v = serde_json::to_value(&p).unwrap();
                v["context"][field] = serde_json::json!(bad);
                assert!(Plan::from_json(&canonical(&v).unwrap()).is_err());
            }
        }
        let mut p = p;
        p.context.service = "real-service".into();
        assert!(p.validate().is_err());
    }
    #[test]
    fn action_and_context_changes_produce_distinct_commitments() {
        let plans = cases();
        assert_ne!(
            plans[1].commitment().unwrap(),
            plans[2].commitment().unwrap()
        );
        let mut other = plans[0].clone();
        other.context.grant = "model:another".into();
        assert_ne!(other.commitment().unwrap(), plans[0].commitment().unwrap());
        let consume = fixture_terminal(&other, Action::Consume).unwrap();
        assert_ne!(consume.issuance, plans[1].issuance);
    }
    #[test]
    fn payload_and_output_mutations_fail_native_vm_and_layout() {
        for p in cases() {
            let tx = signed(&p);
            for n in 0..4 {
                let mut wrong = tx.clone();
                match n {
                    0 => wrong.payload[0] ^= 1,
                    1 => wrong.outputs[0].value -= 1,
                    2 => wrong.outputs[0].script_public_key = script(4),
                    _ => wrong.outputs.push(TransactionOutput::new(1, script(4))),
                }
                wrong.finalize();
                assert!(verify_vm(&wrong, &p.entry()).is_err());
                assert!(check_prepared(&p, &wrong, &p.entry()).is_err());
            }
        }
    }
    #[test]
    fn issue_output_reordering_invalidates_signature() {
        let p = fixture_issue(24_000_000);
        let mut tx = signed(&p);
        tx.outputs.swap(0, 1);
        tx.finalize();
        assert!(verify_vm(&tx, &p.entry()).is_err());
        assert!(check_prepared(&p, &tx, &p.entry()).is_err());
    }
    #[test]
    fn input_sequence_locktime_and_gas_mutations_fail_native_vm() {
        for p in cases() {
            for n in 0..5 {
                let mut tx = signed(&p);
                match n {
                    0 => tx.inputs[0].previous_outpoint.index += 1,
                    1 => tx.inputs[0].sequence = 1,
                    2 => tx.lock_time = 1,
                    3 => tx.gas = 1,
                    _ => tx.inputs.push(tx.inputs[0].clone()),
                }
                tx.finalize();
                assert!(verify_vm(&tx, &p.entry()).is_err());
                assert!(check_prepared(&p, &tx, &p.entry()).is_err());
            }
        }
    }
    #[test]
    fn spent_amount_and_script_are_signature_bound() {
        let p = fixture_issue(24_000_000);
        let tx = signed(&p);
        let mut u = p.entry();
        u.amount += 1;
        assert!(verify_vm(&tx, &u).is_err());
        u = p.entry();
        u.script_public_key = script(2);
        assert!(verify_vm(&tx, &u).is_err());
    }
    #[test]
    fn compute_budget_is_not_id_or_signature_bound_but_outbox_detects_it() {
        let p = fixture_issue(24_000_000);
        let tx = signed(&p);
        let mut other = tx.clone();
        other.inputs[0].compute_commit = ComputeCommit::ComputeBudget(101.into());
        other.finalize();
        assert_eq!(tx.id(), other.id());
        assert_eq!(sig_hash(&tx, &p.entry()), sig_hash(&other, &p.entry()));
        assert_ne!(hash(&tx), hash(&other));
        verify_vm(&other, &p.entry()).unwrap();
        assert!(check_prepared(&p, &other, &p.entry()).is_err());
    }
    #[test]
    fn storage_mass_is_not_id_or_signature_bound_but_outbox_detects_it() {
        let p = cases()[1].clone();
        let tx = signed(&p);
        let mut other = tx.clone();
        other.set_storage_mass(tx.storage_mass() + 1);
        other.finalize();
        assert_eq!(tx.id(), other.id());
        assert_eq!(sig_hash(&tx, &p.entry()), sig_hash(&other, &p.entry()));
        assert_ne!(hash(&tx), hash(&other));
        verify_vm(&other, &p.entry()).unwrap();
        assert!(check_prepared(&p, &other, &p.entry()).is_err());
    }
    #[test]
    fn changed_valid_signature_preserves_id_but_not_saved_hash() {
        let p = cases()[1].clone();
        let original = signed(&p);
        let expected = hash(&original).to_string();
        let m = MutableTransaction::with_entries(original.clone(), vec![p.entry()]);
        let h = calc_schnorr_signature_hash(
            &m.as_verifiable(),
            0,
            SIG_HASH_ALL,
            &SigHashReusedValuesUnsync::new(),
        );
        let msg = Message::from_digest_slice(&h.as_bytes()).unwrap();
        let mut sig = Secp256k1::new()
            .sign_schnorr_with_aux_rand(&msg, &key(2), &[9; 32])
            .as_ref()
            .to_vec();
        sig.push(SIG_HASH_ALL.to_u8());
        let mut b = ScriptBuilder::new();
        b.add_data(&sig).unwrap();
        let mut tx = original.clone();
        tx.inputs[0].signature_script = b.drain();
        tx.finalize();
        assert_eq!(original.id(), tx.id());
        check_prepared(&p, &tx, &p.entry()).unwrap();
        assert!(check_saved(&p, &tx, &p.entry(), &expected).is_err());
    }
    #[test]
    fn damaged_signature_and_wrong_role_fail_vm() {
        for p in cases() {
            let mut tx = signed(&p);
            tx.inputs[0].signature_script[12] ^= 1;
            tx.finalize();
            assert!(verify_vm(&tx, &p.entry()).is_err());
            sign(&mut tx, &p.entry(), &key(4)).unwrap();
            assert!(verify_vm(&tx, &p.entry()).is_err());
        }
    }
    #[test]
    fn valid_alternate_sighash_is_rejected_by_preparer() {
        let p = fixture_issue(24_000_000);
        let mut tx = signed(&p);
        let m = MutableTransaction::with_entries(tx.clone(), vec![p.entry()]);
        let h = calc_schnorr_signature_hash(
            &m.as_verifiable(),
            0,
            SIG_HASH_NONE,
            &SigHashReusedValuesUnsync::new(),
        );
        let msg = Message::from_digest_slice(&h.as_bytes()).unwrap();
        let mut sig = Secp256k1::new()
            .sign_schnorr_no_aux_rand(&msg, &key(1))
            .as_ref()
            .to_vec();
        sig.push(SIG_HASH_NONE.to_u8());
        let mut b = ScriptBuilder::new();
        b.add_data(&sig).unwrap();
        tx.inputs[0].signature_script = b.drain();
        tx.finalize();
        verify_vm(&tx, &p.entry()).unwrap();
        assert!(check_prepared(&p, &tx, &p.entry()).is_err());
    }
    #[test]
    fn controller_can_sign_policy_violating_p2pk_spend_counterexample() {
        let p = cases()[1].clone();
        let mut tx = signed(&p);
        tx.outputs[0].script_public_key = script(4);
        tx.payload = b"arbitrary".to_vec();
        sign(&mut tx, &p.entry(), &key(2)).unwrap();
        verify_vm(&tx, &p.entry()).unwrap();
        assert!(check_prepared(&p, &tx, &p.entry()).is_err());
    }
    #[test]
    fn separate_alternative_branches_conflict_on_the_same_ticket() {
        let plans = cases();
        let consume = signed(&plans[1]);
        let refund = signed(&plans[2]);
        assert_eq!(
            consume.inputs[0].previous_outpoint,
            refund.inputs[0].previous_outpoint
        );
        assert_ne!(consume.id(), refund.id());
        assert!(check_prepared(&plans[1], &refund, &plans[1].entry()).is_err());
        // Both can be signed offline: this is not a durable branch controller.
        verify_vm(&consume, &plans[1].entry()).unwrap();
        verify_vm(&refund, &plans[2].entry()).unwrap();
    }
    #[test]
    fn published_vectors_match_native_ids_hashes_and_commitments() {
        let demo: Value =
            serde_json::from_str(include_str!("../evidence/native-ticket-lab-demo.json")).unwrap();
        assert_eq!(demo["mode"], MODE);
        let examples = demo["examples"].as_array().unwrap();
        assert_eq!(examples.len(), 3);
        for (expected, action) in
            examples
                .iter()
                .zip([Action::Issue, Action::Consume, Action::Refund])
        {
            let p = Plan::from_json(&canonical(&expected["plan"]).unwrap()).unwrap();
            assert_eq!(p.action, action);
            assert_eq!(summary(&p, &signed(&p)).unwrap(), *expected);
        }
    }

    #[test]
    fn summary_contains_no_signed_transaction_bytes() {
        for p in cases() {
            let v = summary(&p, &signed(&p)).unwrap();
            let raw = serde_json::to_string(&v).unwrap();
            assert!(!raw.contains("signature"));
            assert_eq!(v["mode"], MODE);
            assert_eq!(v["vm_verified"], true);
        }
    }
}
