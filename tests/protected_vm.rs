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
const COLD_DELAY: u64 = 1800;

fn key(scalar: u8) -> Keypair {
    let mut bytes = [0; 32];
    bytes[31] = scalar;
    Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&bytes).unwrap())
}
fn artifact(stage: u8) -> SilAbiArtifact {
    let raw = match stage {
        0 => include_str!("../artifacts/protected/idle.json"),
        1 => include_str!("../artifacts/protected/pending.json"),
        2 => include_str!("../artifacts/protected/quarantined.json"),
        _ => include_str!("../artifacts/protected/invalid_stage.json"),
    };
    let a: SilAbiArtifact = serde_json::from_str(raw).unwrap();
    a.check_consistency().unwrap();
    a
}
fn code(a: &SilAbiArtifact) -> Vec<u8> {
    a.contract("IcpProtected")
        .unwrap()
        .compiled
        .bytecode
        .clone()
}
fn p2pk(scalar: u8) -> ScriptPublicKey {
    pay_to_address_script(&Address::new(
        Prefix::Testnet,
        Version::PubKey,
        &key(scalar).x_only_public_key().0.serialize(),
    ))
}

fn verify_input(tx: &Transaction, entries: &[UtxoEntry]) -> Result<(), String> {
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let cache = Cache::new(1000);
    let reused = SigHashReusedValuesUnsync::new();
    TxScriptEngine::from_transaction_input_with_script_units_limit(
        &populated,
        &tx.inputs[0],
        0,
        &entries[0],
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

fn output_utxo(source: &Transaction) -> UtxoEntry {
    UtxoEntry::new(
        source.outputs[0].value,
        source.outputs[0].script_public_key.clone(),
        2000,
        false,
        None,
    )
}

// Spend the actual terminal output, with no covenant redeem script. Public
// deterministic fixture keys model key possession, not a quantum computation.
fn spend_p2pk(source: &Transaction, signer: u8, destination: u8) -> (Transaction, UtxoEntry) {
    let utxo = output_utxo(source);
    let mut tx = Transaction::new(
        1,
        vec![TransactionInput::new_with_compute_budget(
            TransactionOutpoint {
                transaction_id: source.id(),
                index: 0,
            },
            vec![],
            0,
            100,
        )],
        // The old covenant fee cap also ends at its terminal output.
        vec![TransactionOutput::new(
            utxo.amount - FEE - 1,
            p2pk(destination),
        )],
        0,
        Default::default(),
        0,
        vec![],
    );
    icp_testnet::commit_storage_mass(&tx, std::slice::from_ref(&utxo)).unwrap();
    let populated = MutableTransaction::with_entries(tx.clone(), vec![utxo.clone()]);
    let hash = calc_schnorr_signature_hash(
        &populated.as_verifiable(),
        0,
        SIG_HASH_ALL,
        &SigHashReusedValuesUnsync::new(),
    );
    let mut signature = key(signer)
        .sign_schnorr(Message::from_digest_slice(&hash.as_bytes()).unwrap())
        .as_ref()
        .to_vec();
    signature.push(SIG_HASH_ALL.to_u8());
    let mut script = ScriptBuilder::new();
    script.add_data(&signature).unwrap();
    tx.inputs[0].signature_script = script.drain();
    tx.finalize();
    (tx, utxo)
}

struct Attempt {
    a: SilAbiArtifact,
    tx: Transaction,
    entries: Vec<UtxoEntry>,
    entry: &'static str,
    signer: u8,
}
impl Attempt {
    fn new(stage: u8, entry: &'static str) -> Self {
        let a = artifact(stage);
        let spk = match entry {
            "initiate" => pay_to_script_hash_script(&code(&artifact(1))),
            "recover" => pay_to_script_hash_script(&code(&artifact(2))),
            "release" => p2pk(4),
            _ => p2pk(3),
        };
        let input = TransactionInput::new_with_compute_budget(
            TransactionOutpoint {
                transaction_id: TransactionId::from_bytes([7; 32]),
                index: 0,
            },
            vec![],
            match entry {
                "execute" => DELAY,
                "release" => COLD_DELAY,
                _ => 0,
            },
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
            signer: match entry {
                "recover" => 2,
                "release" => 4,
                _ => 1,
            },
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
            "IcpProtected",
            self.entry,
            &[ArtifactValue::Bytes(sig)],
        )
        .unwrap();
        let mut b = ScriptBuilder::with_flags(kaspa_txscript::EngineFlags {
            covenants_enabled: true,
            ..Default::default()
        });
        b.add_data(&code(&self.a)).unwrap();
        self.tx.inputs[0].signature_script = [args, b.drain()].concat();
        self.tx.finalize();
        self
    }
    fn result(&self) -> Result<(), String> {
        verify_input(&self.tx, &self.entries)
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

const PATHS: [(u8, &str); 5] = [
    (0, "initiate"),
    (1, "execute"),
    (0, "recover"),
    (1, "recover"),
    (2, "release"),
];

#[test]
fn all_five_allowed_paths_execute_real_bytecode() {
    for (state, entry) in PATHS {
        Attempt::new(state, entry).accepts();
    }
}
#[test]
fn complete_state_entry_matrix_rejects_other_paths() {
    for stage in 0..=3 {
        for entry in ["initiate", "execute", "recover", "release"] {
            if !PATHS.contains(&(stage, entry)) {
                Attempt::new(stage, entry).rejects();
            }
        }
    }
}
#[test]
fn only_the_exact_role_can_sign_each_entry() {
    for (stage, entry) in PATHS {
        for signer in 1..=5 {
            let mut a = Attempt::new(stage, entry);
            if signer != a.signer {
                a.signer = signer;
                a.rejects();
            }
        }
    }
}
#[test]
fn recovery_cannot_exit_to_any_public_key() {
    for stage in [0, 1] {
        for dest in 1..=5 {
            let mut a = Attempt::new(stage, "recover");
            a.tx.outputs[0].script_public_key = p2pk(dest);
            a.rejects();
        }
    }
}
#[test]
fn recovery_cannot_return_to_hot_states() {
    for stage in [0, 1] {
        for target in [0, 1] {
            let mut a = Attempt::new(stage, "recover");
            a.tx.outputs[0].script_public_key = pay_to_script_hash_script(&code(&artifact(target)));
            a.rejects();
        }
    }
}
#[test]
fn initiation_cannot_skip_to_quarantine_or_reset_idle() {
    for target in [0, 2] {
        let mut a = Attempt::new(0, "initiate");
        a.tx.outputs[0].script_public_key = pay_to_script_hash_script(&code(&artifact(target)));
        a.rejects();
    }
}
#[test]
fn cold_release_cannot_redirect() {
    for dest in [1, 2, 3, 5] {
        let mut a = Attempt::new(2, "release");
        a.tx.outputs[0].script_public_key = p2pk(dest);
        a.rejects();
    }
}
#[test]
fn cold_release_cannot_rearm_or_loop() {
    for target in [0, 1, 2] {
        let mut a = Attempt::new(2, "release");
        a.tx.outputs[0].script_public_key = pay_to_script_hash_script(&code(&artifact(target)));
        a.rejects();
    }
}
#[test]
fn both_exit_delays_reject_short_sequences() {
    for (stage, entry, delay) in [(1, "execute", DELAY), (2, "release", COLD_DELAY)] {
        for seq in [0, delay - 1] {
            let mut a = Attempt::new(stage, entry);
            a.tx.inputs[0].sequence = seq;
            a.rejects();
        }
    }
}
#[test]
fn cold_release_cannot_reuse_normal_delay() {
    let mut a = Attempt::new(2, "release");
    a.tx.inputs[0].sequence = DELAY;
    a.rejects();
}
#[test]
fn disabled_locks_rejected_for_both_exits() {
    for (stage, entry, delay) in [(1, "execute", DELAY), (2, "release", COLD_DELAY)] {
        let mut a = Attempt::new(stage, entry);
        a.tx.inputs[0].sequence = delay | SEQUENCE_LOCK_TIME_DISABLED;
        a.rejects();
    }
}
#[test]
fn recovery_pins_all_immutable_parameters() {
    for raw in [
        include_str!("../artifacts/protected/changed_cold.json"),
        include_str!("../artifacts/protected/changed_trigger.json"),
        include_str!("../artifacts/protected/changed_recipient.json"),
        include_str!("../artifacts/protected/short_cold_delay.json"),
        include_str!("../artifacts/protected/large_fee.json"),
    ] {
        let foreign: SilAbiArtifact = serde_json::from_str(raw).unwrap();
        let mut a = Attempt::new(1, "recover");
        a.tx.outputs[0].script_public_key = pay_to_script_hash_script(&code(&foreign));
        a.rejects();
    }
}
#[test]
fn shared_cold_and_owner_key_is_unspendable() {
    {
        let mut a = Attempt::new(2, "release");
        a.a =
            serde_json::from_str(include_str!("../artifacts/protected/shared_cold.json")).unwrap();
        a.entries[0].script_public_key = pay_to_script_hash_script(&code(&a.a));
        a.signer = 1;
        a.tx.outputs[0].script_public_key = p2pk(1);
        a.rejects();
    }
}
#[test]
fn every_path_rejects_fee_drain_zero_and_inflation() {
    for (stage, entry) in PATHS {
        for value in [0, VALUE - FEE - 1, VALUE + 1] {
            let mut a = Attempt::new(stage, entry);
            a.tx.outputs[0].value = value;
            a.rejects();
        }
    }
}
#[test]
fn every_path_rejects_extra_outputs() {
    for (stage, entry) in PATHS {
        let mut a = Attempt::new(stage, entry);
        a.tx.outputs.push(TransactionOutput::new(1, p2pk(5)));
        a.rejects();
    }
}
#[test]
fn every_path_rejects_extra_inputs() {
    for (stage, entry) in PATHS {
        let mut a = Attempt::new(stage, entry);
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
}
#[test]
fn mutated_signed_cold_release_fails() {
    let mut a = Attempt::new(2, "release").signed();
    a.tx.outputs[0].value += 1;
    a.tx.finalize();
    assert!(a.result().is_err());
}
#[test]
fn cold_signature_cannot_replay_on_another_outpoint() {
    let mut a = Attempt::new(2, "release").signed();
    a.tx.inputs[0].previous_outpoint.index = 1;
    a.tx.finalize();
    assert!(a.result().is_err());
}
#[test]
fn vm_sequence_check_does_not_establish_actual_cold_utxo_age() {
    let mut a = Attempt::new(2, "release");
    a.entries[0].block_daa_score = u64::MAX / 2;
    a.accepts();
}
#[test]
fn native_builder_produces_valid_chain_to_cold_release() {
    use icp_testnet::protected::{Entry, Policy, Stage, build_transition};
    let p: Policy =
        serde_json::from_str(include_str!("../artifacts/protected/policy.json")).unwrap();
    let mut point = TransactionOutpoint {
        transaction_id: TransactionId::from_bytes([9; 32]),
        index: 0,
    };
    let mut utxo = UtxoEntry::new(
        VALUE,
        pay_to_script_hash_script(&code(&artifact(0))),
        1000,
        false,
        None,
    );
    for (state, stage, entry, entry_name, target, signer) in [
        (0, Stage::Idle, Entry::Initiate, "initiate", Some(1), 1),
        (1, Stage::Pending, Entry::Recover, "recover", Some(2), 2),
        (2, Stage::Quarantined, Entry::Release, "release", None, 4),
    ] {
        let source = artifact(state);
        let next = target.map(artifact);
        let tx = build_transition(
            &p,
            &source,
            next.as_ref(),
            stage,
            entry,
            point,
            utxo.clone(),
            &key(signer),
        )
        .unwrap();
        let a = Attempt {
            a: source,
            tx: tx.clone(),
            entries: vec![utxo],
            entry: entry_name,
            signer,
        };
        assert_eq!(a.result(), Ok(()));
        point = TransactionOutpoint {
            transaction_id: tx.id(),
            index: 0,
        };
        utxo = UtxoEntry::new(
            tx.outputs[0].value,
            tx.outputs[0].script_public_key.clone(),
            2000,
            false,
            None,
        );
    }
    assert_eq!(utxo.amount, VALUE - 3 * FEE);
    assert_eq!(utxo.script_public_key, p2pk(4));
}

#[test]
fn normal_payout_ends_destination_delay_and_fee_constraints() {
    let payout = Attempt::new(1, "execute").signed();
    assert_eq!(payout.result(), Ok(()));
    let (spend, utxo) = spend_p2pk(&payout.tx, 3, 5);
    assert_eq!(verify_input(&spend, &[utxo]), Ok(()));
    assert_eq!(spend.inputs[0].sequence, 0);
    assert_eq!(spend.lock_time, 0);
    assert_eq!(spend.outputs[0].script_public_key, p2pk(5));
    let (wrong_role, utxo) = spend_p2pk(&payout.tx, 1, 5);
    assert!(verify_input(&wrong_role, &[utxo]).is_err());
}

#[test]
fn cold_payout_ends_destination_delay_and_fee_constraints() {
    let payout = Attempt::new(2, "release").signed();
    assert_eq!(payout.result(), Ok(()));
    let (spend, utxo) = spend_p2pk(&payout.tx, 4, 5);
    assert_eq!(verify_input(&spend, &[utxo]), Ok(()));
    assert_eq!(spend.inputs[0].sequence, 0);
    assert_eq!(spend.lock_time, 0);
    assert_eq!(spend.outputs[0].script_public_key, p2pk(5));
    let (wrong_role, utxo) = spend_p2pk(&payout.tx, 2, 5);
    assert!(verify_input(&wrong_role, &[utxo]).is_err());
}

#[test]
fn all_role_keys_allow_linked_recovery_and_final_p2pk_spend() {
    let initiate = Attempt::new(0, "initiate").signed();
    assert_eq!(initiate.result(), Ok(()));
    let mut previous = initiate.tx;
    for (stage, entry) in [(1, "recover"), (2, "release")] {
        let mut next = Attempt::new(stage, entry);
        next.tx.inputs[0].previous_outpoint = TransactionOutpoint {
            transaction_id: previous.id(),
            index: 0,
        };
        next.entries = vec![output_utxo(&previous)];
        let next = next.signed();
        assert_eq!(next.result(), Ok(()));
        previous = next.tx;
    }
    assert_eq!(previous.outputs[0].script_public_key, p2pk(4));
    let (spend, utxo) = spend_p2pk(&previous, 4, 5);
    assert_eq!(verify_input(&spend, &[utxo]), Ok(()));
    assert_eq!(spend.outputs[0].script_public_key, p2pk(5));
    // VM-only: sequence commitments are checked, actual age is a node gate.
    // This accepted path needs the role keys; it does not rewrite DAG history.
}
