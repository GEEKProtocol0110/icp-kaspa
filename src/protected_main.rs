//! Separate testnet-only CLI for protected recovery. No combined-key fallback.
use icp_testnet::protected::{self, Entry, Policy, Role, Stage};
use kaspa_consensus_core::tx::{Transaction, TransactionOutpoint, TransactionOutput, UtxoEntry};
use kaspa_rpc_core::{RpcTransaction, api::rpc::RpcApi};
use kaspa_txscript::{
    EngineCtx, EngineFlags, TxScriptEngine,
    caches::Cache,
    pay_to_script_hash_script,
    standard::{extract_script_pub_key_address, pay_to_address_script},
};
use kaspa_wrpc_client::{
    KaspaRpcClient, Resolver, WrpcEncoding,
    client::{ConnectOptions, ConnectStrategy},
    prelude::{NetworkId, NetworkType},
};
use serde_json::{Value, json};
use silverscript_abi::SilAbiArtifact;
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

struct Session {
    dir: PathBuf,
    policy: Policy,
    artifacts: Vec<SilAbiArtifact>,
}
impl Session {
    fn load(dir: PathBuf) -> Result<Self> {
        let policy: Policy = serde_json::from_slice(&fs::read(dir.join("public-policy.json"))?)?;
        policy.validate()?;
        let mut artifacts = Vec::new();
        let mut template = None;
        for stage in [Stage::Idle, Stage::Pending, Stage::Quarantined] {
            let a: SilAbiArtifact =
                serde_json::from_slice(&fs::read(dir.join(format!("{}.json", stage.name())))?)?;
            protected::bytecode(&a)?;
            let t = a
                .contract(protected::CONTRACT)
                .ok_or("Expected IcpProtected artifact")?
                .compiled
                .template_hash
                .clone();
            if template.as_ref().is_some_and(|old| old != &t) {
                return Err("State artifacts have different immutable templates".into());
            }
            template = Some(t);
            artifacts.push(a);
        }
        Ok(Self {
            dir,
            policy,
            artifacts,
        })
    }
    fn artifact(&self, stage: Stage) -> &SilAbiArtifact {
        &self.artifacts[match stage {
            Stage::Idle => 0,
            Stage::Pending => 1,
            Stage::Quarantined => 2,
        }]
    }
    fn script(&self, stage: Stage) -> Result<kaspa_consensus_core::tx::ScriptPublicKey> {
        Ok(pay_to_script_hash_script(&protected::bytecode(
            self.artifact(stage),
        )?))
    }
    fn address(&self, stage: Stage) -> Result<kaspa_addresses::Address> {
        Ok(extract_script_pub_key_address(
            &self.script(stage)?,
            kaspa_addresses::Prefix::Testnet,
        )?)
    }
    fn signer(&self, role: Role) -> Result<secp256k1::Keypair> {
        let file = std::env::var_os("ICP_SIGNER_KEY_FILE")
            .ok_or("Set ICP_SIGNER_KEY_FILE to the one required role file")?;
        Ok(protected::load_signer(
            Path::new(&file),
            role,
            &self.policy,
        )?)
    }
    fn descriptor(&self) -> Result<Value> {
        Ok(json!({"version":"protected-v1","network":"testnet-10",
            "idle_spk":self.script(Stage::Idle)?,"pending_spk":self.script(Stage::Pending)?,
            "recovery_spk":self.script(Stage::Quarantined)?,
            "recipient_spk":pay_to_address_script(&self.policy.address(Role::Recipient)?),
            "cold_spk":pay_to_address_script(&self.policy.address(Role::Cold)?),
            "delay_daa":self.policy.delay_daa,"cold_delay_daa":self.policy.cold_delay_daa,"max_fee":self.policy.max_fee}))
    }
    fn addresses(&self) -> Result<Value> {
        Ok(json!({"version":"protected-v1","network":"testnet-10",
            "funding_address":self.policy.address(Role::Owner)?.to_string(),
            "recipient_address":self.policy.address(Role::Recipient)?.to_string(),
            "cold_address":self.policy.address(Role::Cold)?.to_string(),
            "idle_vault":self.address(Stage::Idle)?.to_string(),
            "pending_vault":self.address(Stage::Pending)?.to_string(),
            "quarantined_vault":self.address(Stage::Quarantined)?.to_string()}))
    }
}
fn print(value: &Value) -> Result<()> {
    println!("{}", serde_json::to_string(value)?);
    Ok(())
}
fn verify(tx: &Transaction, utxo: UtxoEntry) -> Result<()> {
    let populated = kaspa_consensus_core::tx::PopulatedTransaction::new(tx, vec![utxo.clone()]);
    let cache = Cache::new(1000);
    let reuse = kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync::new();
    TxScriptEngine::from_transaction_input_with_script_units_limit(
        &populated,
        &tx.inputs[0],
        0,
        &utxo,
        EngineCtx::new(&cache).with_reused(&reuse),
        EngineFlags {
            covenants_enabled: true,
            ..Default::default()
        },
        tx.inputs[0].compute_commit.allowed_script_units(),
    )
    .execute()?;
    Ok(())
}
async fn gate(c: &KaspaRpcClient) -> Result<Value> {
    let n = c.get_server_info().await?;
    icp_testnet::check_network(
        &n.network_id.to_string(),
        n.is_synced,
        n.has_utxo_index,
        n.virtual_daa_score,
    )?;
    Ok(serde_json::to_value(n)?)
}
async fn submit(
    c: &KaspaRpcClient,
    dir: &Path,
    tx: &Transaction,
    entry: &str,
    prepare: bool,
) -> Result<()> {
    let node = gate(c).await?;
    let receipt_dir = std::env::var_os("ICP_PROTECTED_RECEIPT_DIR").map(PathBuf::from);
    let dir = receipt_dir.as_deref().unwrap_or(dir);
    fs::create_dir_all(dir)?;
    let path = dir.join(format!(
        "{}-{}-{}.json",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
        entry,
        tx.id()
    ));
    let mut receipt = json!({"version":"protected-v1","network":"testnet-10","status":"PREPARED",
        "node":node,"id":tx.id().to_string(),"transaction":RpcTransaction::from(tx),"path":path});
    fs::write(&path, serde_json::to_vec_pretty(&receipt)?)?;
    if prepare {
        return print(&receipt);
    }
    match c.submit_transaction(RpcTransaction::from(tx), false).await {
        Ok(id) => {
            receipt["status"] = json!("MEMPOOL_ACCEPTED");
            fs::write(&path, serde_json::to_vec_pretty(&receipt)?)?;
            println!("Broadcast {entry}: {id}. Confirm accepted-chain inclusion separately.");
            Ok(())
        }
        Err(e) => {
            receipt["status"] = json!("REJECTED_OR_UNKNOWN");
            receipt["error"] = json!(e.to_string());
            fs::write(&path, serde_json::to_vec_pretty(&receipt)?)?;
            Err(e.into())
        }
    }
}
async fn spend(c: &KaspaRpcClient, s: &Session, command: &str, point: &str) -> Result<()> {
    let entry = Entry::parse(command.strip_prefix("prepare-").unwrap_or(command))?;
    let (id, index) = point.split_once(':').ok_or("Expected TXID:INDEX")?;
    let requested = TransactionOutpoint {
        transaction_id: id.parse()?,
        index: index.parse()?,
    };
    let mut found = None;
    for stage in [Stage::Idle, Stage::Pending, Stage::Quarantined] {
        for u in c.get_utxos_by_addresses(vec![s.address(stage)?]).await? {
            if TransactionOutpoint::from(u.outpoint) == requested {
                found = Some((stage, u));
            }
        }
    }
    let (stage, u) = found.ok_or("Exact outpoint is not live at a pinned protected-v1 address")?;
    let target = entry.target(stage)?;
    let key = s.signer(entry.role())?;
    let utxo: UtxoEntry = u.utxo_entry.into();
    let tx = protected::build_transition(
        &s.policy,
        s.artifact(stage),
        target.map(|t| s.artifact(t)),
        stage,
        entry,
        requested,
        utxo.clone(),
        &key,
    )?;
    verify(&tx, utxo)?;
    submit(
        c,
        &s.dir,
        &tx,
        entry.name(),
        command.starts_with("prepare-"),
    )
    .await
}
async fn deposit(c: &KaspaRpcClient, s: &Session, amount: u64) -> Result<()> {
    if !(10_000_000..=100_000_000).contains(&amount) {
        return Err("Deposit must be 0.1 to 1 test KAS".into());
    }
    let key = s.signer(Role::Owner)?;
    let funding = s.policy.address(Role::Owner)?;
    let fee = s.policy.max_fee;
    let all = c.get_utxos_by_addresses(vec![funding.clone()]).await?;
    let u = all
        .iter()
        .filter(|u| {
            !u.utxo_entry.is_coinbase
                && u.utxo_entry.covenant_id.is_none()
                && u.utxo_entry.script_public_key == pay_to_address_script(&funding)
                && u.utxo_entry.amount >= amount + 2 * fee
        })
        .min_by_key(|u| u.utxo_entry.amount)
        .ok_or("Insufficient testnet funding UTXO")?;
    let utxo: UtxoEntry = u.utxo_entry.clone().into();
    let mut tx = Transaction::new(
        1,
        vec![
            kaspa_consensus_core::tx::TransactionInput::new_with_compute_budget(
                u.outpoint.into(),
                vec![],
                0,
                100,
            ),
        ],
        vec![
            TransactionOutput::new(amount, s.script(Stage::Idle)?),
            TransactionOutput::new(utxo.amount - amount - fee, pay_to_address_script(&funding)),
        ],
        0,
        Default::default(),
        0,
        vec![],
    );
    icp_testnet::commit_storage_mass(&tx, std::slice::from_ref(&utxo))?;
    let p =
        kaspa_consensus_core::tx::MutableTransaction::with_entries(tx.clone(), vec![utxo.clone()]);
    let hash = kaspa_consensus_core::hashing::sighash::calc_schnorr_signature_hash(
        &p.as_verifiable(),
        0,
        kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL,
        &kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync::new(),
    );
    let mut sig = key
        .sign_schnorr(secp256k1::Message::from_digest_slice(&hash.as_bytes())?)
        .as_ref()
        .to_vec();
    sig.push(kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL.to_u8());
    let mut b = kaspa_txscript::script_builder::ScriptBuilder::new();
    b.add_data(&sig)?;
    tx.inputs[0].signature_script = b.drain();
    tx.finalize();
    verify(&tx, utxo)?;
    submit(c, &s.dir, &tx, "deposit", false).await
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("help");
    if cmd == "help" {
        println!(
            "icp-protected keygen ROLE FILE | setup PUBLIC_POLICY.json | addresses | descriptor | node | status | anchor | scan HASH | deposit [SOMPI] | [prepare-]initiate TXID:INDEX | [prepare-]execute TXID:INDEX | [prepare-]recover TXID:INDEX | [prepare-]release TXID:INDEX | broadcast RECEIPT.json\nTN10 only. ICP_SIGNER_KEY_FILE selects ONE role. ICP_PROTECTED_STATE_DIR defaults to runtime/protected. ICP_RPC_URL optionally selects Borsh wRPC."
        );
        return Ok(());
    }
    if cmd == "keygen" {
        if args.len() != 4 {
            return Err("keygen requires ROLE and FILE".into());
        }
        return print(&protected::generate_role_key(
            Role::parse(&args[2])?,
            Path::new(&args[3]),
        )?);
    }
    let dir = std::env::var_os("ICP_PROTECTED_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("runtime/protected"));
    if cmd == "setup" {
        let path = args.get(2).ok_or("setup requires a public policy file")?;
        let policy: Policy = serde_json::from_slice(&fs::read(path)?)?;
        policy.validate()?;
        fs::create_dir_all(&dir)?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join("public-policy.json"))?;
        use std::io::Write;
        file.write_all(&serde_json::to_vec_pretty(&policy)?)?;
        file.sync_all()?;
        let output = std::process::Command::new("python3")
            .args(["scripts/compile_protected.py", "--policy"])
            .arg(dir.join("public-policy.json"))
            .arg("--output")
            .arg(&dir)
            .output()?;
        if !output.status.success() {
            eprint!("{}", String::from_utf8_lossy(&output.stderr));
            return Err("Compilation failed; policy preserved. Re-run compile_protected.py with that policy and output directory".into());
        }
        return print(&Session::load(dir)?.addresses()?);
    }
    let read = matches!(
        cmd,
        "addresses"
            | "descriptor"
            | "node"
            | "status"
            | "anchor"
            | "scan"
            | "broadcast"
            | "deposit"
    );
    if !read {
        Entry::parse(cmd.strip_prefix("prepare-").unwrap_or(cmd))?;
    }
    if (matches!(cmd, "scan" | "broadcast") || !read) && args.get(2).is_none() {
        return Err("Missing transaction outpoint, hash or receipt path".into());
    }
    if matches!(cmd, "addresses" | "descriptor") {
        let s = Session::load(dir)?;
        return print(&if cmd == "addresses" {
            s.addresses()?
        } else {
            s.descriptor()?
        });
    }
    let url = std::env::var("ICP_RPC_URL").ok();
    let c = KaspaRpcClient::new(
        WrpcEncoding::Borsh,
        url.as_deref(),
        if url.is_none() {
            Some(Resolver::default())
        } else {
            None
        },
        Some(NetworkId::with_suffix(NetworkType::Testnet, 10)),
        None,
    )?;
    tokio::time::timeout(
        Duration::from_secs(20),
        c.connect(Some(ConnectOptions {
            block_async_connect: true,
            connect_timeout: Some(Duration::from_secs(10)),
            strategy: ConnectStrategy::Fallback,
            ..Default::default()
        })),
    )
    .await??;
    let result = async {
        let info = gate(&c).await?;
        if cmd == "node" {
            return print(&info);
        }
        if cmd == "anchor" {
            return print(
                &json!({"node":info,"anchor":c.get_block_dag_info().await?.sink.to_string()}),
            );
        }
        if cmd == "scan" {
            let target = tokio::time::timeout(Duration::from_secs(10), c.get_block_dag_info())
                .await??
                .sink;
            let changes = tokio::time::timeout(
                Duration::from_secs(15),
                c.get_virtual_chain_from_block_v2(
                    args[2].parse()?,
                    Some(kaspa_rpc_core::RpcDataVerbosityLevel::Full),
                    Some(0),
                ),
            )
            .await??;
            return print(
                &json!({"node":info,"from":args[2],"target":target.to_string(),"changes":changes}),
            );
        }
        if cmd == "broadcast" {
            let receipt: Value = serde_json::from_slice(&fs::read(&args[2])?)?;
            if receipt["version"] != "protected-v1" || receipt["network"] != "testnet-10" {
                return Err("Wrong prepared receipt version or network".into());
            }
            let tx = Transaction::try_from(serde_json::from_value::<RpcTransaction>(
                receipt["transaction"].clone(),
            )?)?;
            if receipt["id"].as_str() != Some(&tx.id().to_string()) {
                return Err("Prepared transaction ID mismatch".into());
            }
            fs::create_dir_all(&dir)?;
            return submit(&c, &dir, &tx, "rebroadcast", false).await;
        }
        let s = Session::load(dir)?;
        if cmd == "status" {
            let mut addresses = vec![];
            for role in [Role::Owner, Role::Recovery, Role::Recipient, Role::Cold] {
                addresses.push(s.policy.address(role)?);
            }
            for stage in [Stage::Idle, Stage::Pending, Stage::Quarantined] {
                addresses.push(s.address(stage)?);
            }
            return print(&json!({"node":info,"utxos":c.get_utxos_by_addresses(addresses).await?}));
        }
        if cmd == "deposit" {
            return deposit(
                &c,
                &s,
                args.get(2)
                    .map(|a| a.parse())
                    .transpose()?
                    .unwrap_or(30_000_000),
            )
            .await;
        }
        spend(&c, &s, cmd, &args[2]).await
    }
    .await;
    c.disconnect().await?;
    result
}
