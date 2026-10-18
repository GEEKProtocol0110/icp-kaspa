use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::hashing::sighash::{
    SigHashReusedValuesUnsync, calc_schnorr_signature_hash,
};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::tx::{
    MutableTransaction, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId,
    TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_txscript::{
    EngineCtx, EngineFlags, SEQUENCE_LOCK_TIME_DISABLED, TxScriptEngine, caches::Cache,
    pay_to_script_hash_script, script_builder::ScriptBuilder, standard::pay_to_address_script,
};
use secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use silverscript_abi::{ArtifactValue, SilAbiArtifact, encode_contract_entry_sig_script};

const VALUE: u64 = 100_000_000;
const FEE: u64 = 2_000_000;
const DELAY: u64 = 600;

#[test]
fn initiation_cannot_replace_immutable_policy() {
    for raw in [
        include_str!("../artifacts/changed_recipient.json"),
        include_str!("../artifacts/changed_recovery.json"),
        include_str!("../artifacts/short_delay.json"),
        include_str!("../artifacts/large_fee.json"),
    ] {
        let foreign: SilAbiArtifact = serde_json::from_str(raw).unwrap();
        foreign.check_consistency().unwrap();
        let mut a = Attempt::new(false, "initiate");
        a.tx.outputs[0].script_public_key = pay_to_script_hash_script(&code(&foreign));
        a.rejects();
    }
}

fn key(scalar: u8) -> Keypair {
    let mut bytes = [0; 32];
    bytes[31] = scalar;
    Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&bytes).unwrap())
}
fn artifact(pending: bool) -> SilAbiArtifact {
    let raw = if pending {
        include_str!("../artifacts/pending.json")
    } else {
        include_str!("../artifacts/idle.json")
    };
    let a: SilAbiArtifact = serde_json::from_str(raw).unwrap();
    a.check_consistency().unwrap();
    a
}
fn code(a: &SilAbiArtifact) -> Vec<u8> {
    a.contract("IcpVault").unwrap().compiled.bytecode.clone()
}
fn p2pk(scalar: u8) -> ScriptPublicKey {
    pay_to_address_script(&Address::new(
        Prefix::Testnet,
        Version::PubKey,
        &key(scalar).x_only_public_key().0.serialize(),
    ))
}

struct Attempt {
    a: SilAbiArtifact,
    tx: Transaction,
    entries: Vec<UtxoEntry>,
    entry: &'static str,
    signer: u8,
}
impl Attempt {
    fn new(pending: bool, entry: &'static str) -> Self {
        let a = artifact(pending);
        let spk = match entry {
            "initiate" => pay_to_script_hash_script(&code(&artifact(true))),
            "recover" => p2pk(2),
            _ => p2pk(3),
        };
        let input = TransactionInput::new_with_compute_budget(
            TransactionOutpoint {
                transaction_id: TransactionId::from_bytes([7; 32]),
                index: 0,
            },
            vec![],
            if entry == "execute" { DELAY } else { 0 },
            100,
        );
        let output = TransactionOutput::new(VALUE - FEE, spk);
        let tx = Transaction::new(
            1,
            vec![input],
            vec![output],
            0,
            Default::default(),
            0,
            vec![],
        );
        let entries = vec![UtxoEntry::new(
            VALUE,
            pay_to_script_hash_script(&code(&a)),
            1000,
            false,
            None,
        )];
        Self {
            a,
            tx,
            entries,
            entry,
            signer: if entry == "recover" { 2 } else { 1 },
        }
    }
    fn signed(mut self) -> Self {
        self.tx.finalize();
        // Malformed zero-value outputs are tested at script level without
        // invoking the mass calculator, whose consensus precondition is >0.
        if self.tx.outputs.iter().all(|o| o.value > 0) {
            icp_testnet::commit_storage_mass(&self.tx, &self.entries).unwrap();
        }
        let populated = MutableTransaction::with_entries(self.tx.clone(), self.entries.clone());
        let digest = calc_schnorr_signature_hash(
            &populated.as_verifiable(),
            0,
            SIG_HASH_ALL,
            &SigHashReusedValuesUnsync::new(),
        );
        let signature =
            key(self.signer).sign_schnorr(Message::from_digest_slice(&digest.as_bytes()).unwrap());
        let mut sig = signature.as_ref().to_vec();
        sig.push(SIG_HASH_ALL.to_u8());
        let args = encode_contract_entry_sig_script(
            &self.a,
            "IcpVault",
            self.entry,
            &[ArtifactValue::Bytes(sig)],
        )
        .unwrap();
        let mut b = ScriptBuilder::new();
        b.add_data(&code(&self.a)).unwrap();
        self.tx.inputs[0].signature_script = [args, b.drain()].concat();
        self.tx.finalize();
        self
    }
    fn result(&self) -> Result<(), String> {
        let populated = PopulatedTransaction::new(&self.tx, self.entries.clone());
        let cache = Cache::new(1000);
        let reused = SigHashReusedValuesUnsync::new();
        TxScriptEngine::from_transaction_input_with_script_units_limit(
            &populated,
            &self.tx.inputs[0],
            0,
            &self.entries[0],
            EngineCtx::new(&cache).with_reused(&reused),
            EngineFlags {
                covenants_enabled: true,
                ..Default::default()
            },
            self.tx.inputs[0].compute_commit.allowed_script_units(),
        )
        .execute()
        .map_err(|e| e.to_string())
    }
    fn accepts(self) {
        assert_eq!(self.signed().result(), Ok(()));
    }
    fn rejects(self) {
        assert!(
            self.signed().result().is_err(),
            "attack unexpectedly accepted"
        );
    }
}

#[test]
fn initiate_creates_pending() {
    Attempt::new(false, "initiate").accepts();
}
#[test]
fn execute_commits_required_sequence() {
    Attempt::new(true, "execute").accepts();
}
#[test]
fn recover_idle() {
    Attempt::new(false, "recover").accepts();
}
#[test]
fn recover_pending() {
    Attempt::new(true, "recover").accepts();
}
#[test]
fn pending_cannot_be_initiated_again() {
    Attempt::new(true, "initiate").rejects();
}
#[test]
fn old_idle_deposit_cannot_execute_directly() {
    let mut a = Attempt::new(false, "execute");
    a.entries[0].block_daa_score = 0;
    a.rejects();
}
#[test]
fn wrong_owner_signature_rejected() {
    let mut a = Attempt::new(false, "initiate");
    a.signer = 4;
    a.rejects();
}
#[test]
fn owner_cannot_authorize_recovery() {
    let mut a = Attempt::new(true, "recover");
    a.signer = 1;
    a.rejects();
}
#[test]
fn recovery_cannot_authorize_execution() {
    let mut a = Attempt::new(true, "execute");
    a.signer = 2;
    a.rejects();
}
#[test]
fn sequence_below_delay_rejected() {
    let mut a = Attempt::new(true, "execute");
    a.tx.inputs[0].sequence = DELAY - 1;
    a.rejects();
}
#[test]
fn disabled_relative_lock_rejected() {
    let mut a = Attempt::new(true, "execute");
    a.tx.inputs[0].sequence = DELAY | SEQUENCE_LOCK_TIME_DISABLED;
    a.rejects();
}
#[test]
fn execution_cannot_redirect() {
    let mut a = Attempt::new(true, "execute");
    a.tx.outputs[0].script_public_key = p2pk(4);
    a.rejects();
}
#[test]
fn recovery_cannot_redirect() {
    let mut a = Attempt::new(true, "recover");
    a.tx.outputs[0].script_public_key = p2pk(4);
    a.rejects();
}
#[test]
fn initiate_cannot_pay_attacker() {
    let mut a = Attempt::new(false, "initiate");
    a.tx.outputs[0].script_public_key = p2pk(4);
    a.rejects();
}
#[test]
fn initiate_cannot_reset_idle() {
    let mut a = Attempt::new(false, "initiate");
    a.tx.outputs[0].script_public_key = pay_to_script_hash_script(&code(&artifact(false)));
    a.rejects();
}
#[test]
fn extra_output_rejected() {
    for e in ["initiate", "execute", "recover"] {
        let mut a = Attempt::new(e != "initiate", e);
        a.tx.outputs.push(TransactionOutput::new(1, p2pk(4)));
        a.rejects();
    }
}
#[test]
fn extra_input_rejected() {
    let mut a = Attempt::new(false, "initiate");
    a.tx.inputs.push(TransactionInput::new_with_compute_budget(
        TransactionOutpoint {
            transaction_id: TransactionId::from_bytes([8; 32]),
            index: 0,
        },
        vec![],
        0,
        100,
    ));
    a.entries.push(a.entries[0].clone());
    a.rejects();
}
#[test]
fn fee_drain_rejected_on_all_paths() {
    for e in ["initiate", "execute", "recover"] {
        let mut a = Attempt::new(e != "initiate", e);
        a.tx.outputs[0].value = VALUE - FEE - 1;
        a.rejects();
    }
}
#[test]
fn zero_output_rejected() {
    let mut a = Attempt::new(true, "recover");
    a.tx.outputs[0].value = 0;
    a.rejects();
}
#[test]
fn output_value_cannot_exceed_input() {
    let mut a = Attempt::new(true, "execute");
    a.tx.outputs[0].value = VALUE + 1;
    a.rejects();
}
#[test]
fn lower_fee_allowed() {
    let mut a = Attempt::new(false, "initiate");
    a.tx.outputs[0].value = VALUE - 1;
    a.accepts();
}
#[test]
fn zero_fee_is_not_an_authorization_bypass() {
    let mut a = Attempt::new(false, "initiate");
    a.tx.outputs[0].value = VALUE;
    a.accepts();
}
#[test]
fn mutated_signed_transaction_rejected() {
    let mut a = Attempt::new(true, "execute").signed();
    a.tx.outputs[0].value += 1;
    a.tx.finalize();
    assert!(a.result().is_err());
}
#[test]
fn signature_replay_on_different_outpoint_rejected() {
    let mut a = Attempt::new(true, "execute").signed();
    a.tx.inputs[0].previous_outpoint.index = 1;
    a.tx.finalize();
    assert!(a.result().is_err());
}
#[test]
fn wrong_selector_rejected() {
    let mut a = Attempt::new(true, "execute").signed();
    a.tx.inputs[0].signature_script[67] ^= 0x01;
    a.tx.finalize();
    assert!(a.result().is_err());
}

// This deliberately demonstrates why VM tests cannot establish network age:
// CSV verifies sequence; the node separately verifies actual UTXO age.
#[test]
fn vm_alone_does_not_establish_pending_utxo_age() {
    let mut a = Attempt::new(true, "execute");
    a.entries[0].block_daa_score = u64::MAX / 2;
    a.accepts();
}
