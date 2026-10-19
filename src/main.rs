//! Testnet-10 operator CLI. Seeds are never accepted in arguments or printed.
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::{
    hashing::{
        sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash},
        sighash_type::SIG_HASH_ALL,
    },
    tx::{
        MutableTransaction, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput,
        UtxoEntry,
    },
};
use kaspa_rpc_core::{RpcTransaction, RpcUtxosByAddressesEntry, api::rpc::RpcApi};
use kaspa_txscript::{
    EngineCtx, EngineFlags,
    caches::Cache,
    pay_to_script_hash_script,
    script_builder::ScriptBuilder,
    standard::{extract_script_pub_key_address, pay_to_address_script},
};
use kaspa_wrpc_client::{
    KaspaRpcClient, Resolver, WrpcEncoding,
    client::{ConnectOptions, ConnectStrategy},
    prelude::{NetworkId, NetworkType},
};
use secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use silverscript_abi::{
    ArtifactValue, SilAbiArtifact, decode_hex, encode_contract_entry_sig_script, encode_hex,
};
use std::{
    error::Error,
    fs,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
const AMOUNT: u64 = 100_000_000; // 1 test KAS
const FEE: u64 = 2_000_000; // 0.02 test KAS, capped in contract
const DELAY: u64 = 600; // DAA units, not a guaranteed wall-clock duration
#[derive(Serialize, Deserialize)]
struct Keys {
    owner: String,
    recovery: String,
    recipient: String,
}
fn pair(secret: &str) -> Result<Keypair> {
    Ok(Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&decode_hex(secret)?)?,
    ))
}
fn address(k: &Keypair) -> Address {
    Address::new(
        Prefix::Testnet,
        Version::PubKey,
        &k.x_only_public_key().0.serialize(),
    )
}
fn code(a: &SilAbiArtifact) -> Vec<u8> {
    a.contract("IcpVault")
        .expect("IcpVault artifact")
        .compiled
        .bytecode
        .clone()
}
fn artifact(pending: bool) -> Result<SilAbiArtifact> {
    let a: SilAbiArtifact = serde_json::from_slice(&fs::read(if pending {
        "runtime/pending.json"
    } else {
        "runtime/idle.json"
    })?)?;
    a.check_consistency()?;
    Ok(a)
}
fn sign(tx: &Transaction, entries: &[UtxoEntry], k: &Keypair) -> Vec<u8> {
    icp_testnet::commit_storage_mass(tx, entries).expect("valid storage mass");
    let p = MutableTransaction::with_entries(tx.clone(), entries.to_vec());
    let h = calc_schnorr_signature_hash(
        &p.as_verifiable(),
        0,
        SIG_HASH_ALL,
        &SigHashReusedValuesUnsync::new(),
    );
    let mut s = k
        .sign_schnorr(Message::from_digest_slice(&h.as_bytes()).unwrap())
        .as_ref()
        .to_vec();
    s.push(SIG_HASH_ALL.to_u8());
    s
}
fn utxo_input(u: &RpcUtxosByAddressesEntry, seq: u64) -> TransactionInput {
    TransactionInput::new_with_compute_budget(u.outpoint.into(), vec![], seq, 100)
}
fn verify(tx: &Transaction, entry: UtxoEntry) -> Result<()> {
    let p = kaspa_consensus_core::tx::PopulatedTransaction::new(tx, vec![entry.clone()]);
    let cache = Cache::new(1000);
    let reuse = SigHashReusedValuesUnsync::new();
    kaspa_txscript::TxScriptEngine::from_transaction_input_with_script_units_limit(
        &p,
        &tx.inputs[0],
        0,
        &entry,
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
fn init() -> Result<()> {
    if Path::new(".secrets/keys.json").exists() {
        return Err("Keys already exist; preserve them and use addresses/status".into());
    }
    fs::create_dir_all(".secrets")?;
    fs::create_dir_all("runtime")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(".secrets", fs::Permissions::from_mode(0o700))?;
    }
    let secp = Secp256k1::new();
    let fresh = || {
        let (s, _) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());
        encode_hex(&s.secret_bytes())
    };
    // Separate conventional authorities. This runner is not a quantum-safe wallet.
    let keys = Keys {
        owner: fresh(),
        recovery: fresh(),
        recipient: fresh(),
    };
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    use std::io::Write;
    options
        .open(".secrets/keys.json")?
        .write_all(serde_json::to_string_pretty(&keys)?.as_bytes())?;
    let mut args = vec![];
    for s in [&keys.owner, &keys.recovery, &keys.recipient] {
        args.push(
            json!({"kind":"bytes","value":pair(s)?.x_only_public_key().0.serialize().to_vec()}),
        );
    }
    args.push(json!({"kind":"int","value":DELAY}));
    args.push(json!({"kind":"int","value":FEE}));
    fs::write(
        "runtime/public.args.json",
        serde_json::to_vec_pretty(&args)?,
    )?;
    let status = std::process::Command::new("python3")
        .args([
            "scripts/compile.py",
            "--args",
            "runtime/public.args.json",
            "--output",
            "runtime",
        ])
        .status()?;
    if !status.success() {
        return Err("Compilation failed; keys preserved. Re-run compile.py, not init".into());
    }
    addresses(&keys)
}
fn addresses(keys: &Keys) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"network":"testnet-10","funding_address":address(&pair(&keys.owner)?).to_string(),"recovery_address":address(&pair(&keys.recovery)?).to_string(),"recipient_address":address(&pair(&keys.recipient)?).to_string(),"idle_vault":extract_script_pub_key_address(&pay_to_script_hash_script(&code(&artifact(false)?)),Prefix::Testnet)?.to_string(),"pending_vault":extract_script_pub_key_address(&pay_to_script_hash_script(&code(&artifact(true)?)),Prefix::Testnet)?.to_string(),"suggested_funding_test_kas":"3"})
        )?
    );
    Ok(())
}
async fn gate(c: &KaspaRpcClient) -> Result<Value> {
    let info = c.get_server_info().await?;
    icp_testnet::check_network(
        &info.network_id.to_string(),
        info.is_synced,
        info.has_utxo_index,
        info.virtual_daa_score,
    )?;
    Ok(serde_json::to_value(info)?)
}
async fn submit(c: &KaspaRpcClient, tx: &Transaction, label: &str) -> Result<()> {
    let node = gate(c).await?;
    let rpc = RpcTransaction::from(tx);
    let path = format!(
        "runtime/{}-{}-{}.json",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
        label,
        tx.id()
    );
    fs::write(
        &path,
        serde_json::to_vec_pretty(
            &json!({"status":"PREPARED","node":node,"transaction":rpc,"id":tx.id().to_string()}),
        )?,
    )?;
    if label.starts_with("prepare-") {
        println!(
            "{}",
            serde_json::to_string(
                &json!({"status":"PREPARED","id":tx.id().to_string(),"path":path,"transaction":rpc})
            )?
        );
        return Ok(());
    }
    let result = c.submit_transaction(rpc, false).await;
    match result {
        Ok(id) => {
            fs::write(
                &path,
                serde_json::to_vec_pretty(
                    &json!({"status":"MEMPOOL_ACCEPTED","node":node,"transaction":RpcTransaction::from(tx),"id":id.to_string()}),
                )?,
            )?;
            println!(
                "Broadcast {label}: {id}. Verify UTXO inclusion with status; broadcast is not confirmation."
            );
            Ok(())
        }
        Err(e) => {
            fs::write(
                &path,
                serde_json::to_vec_pretty(
                    &json!({"status":"REJECTED_OR_UNKNOWN","node":node,"transaction":RpcTransaction::from(tx),"id":tx.id().to_string(),"error":e.to_string()}),
                )?,
            )?;
            Err(e.into())
        }
    }
}
async fn status(c: &KaspaRpcClient) -> Result<()> {
    let public: Vec<ArtifactValue> =
        serde_json::from_slice(&fs::read("runtime/public.args.json")?)?;
    let mut addresses = Vec::new();
    for value in &public[..3] {
        if let ArtifactValue::Bytes(bytes) = value {
            addresses.push(Address::new(Prefix::Testnet, Version::PubKey, bytes));
        } else {
            return Err("Invalid public key descriptor".into());
        }
    }
    let node = gate(c).await?;
    let idle = extract_script_pub_key_address(
        &pay_to_script_hash_script(&code(&artifact(false)?)),
        Prefix::Testnet,
    )?;
    let pending = extract_script_pub_key_address(
        &pay_to_script_hash_script(&code(&artifact(true)?)),
        Prefix::Testnet,
    )?;
    let utxos = c
        .get_utxos_by_addresses(vec![
            addresses[0].clone(),
            addresses[1].clone(),
            addresses[2].clone(),
            idle,
            pending,
        ])
        .await?;
    let result = json!({"node":node,"utxos":utxos});
    fs::write(
        "runtime/last-status.json",
        serde_json::to_vec_pretty(&result)?,
    )?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
async fn deposit(c: &KaspaRpcClient, keys: &Keys, amount: u64) -> Result<()> {
    if amount < 10_000_000 || amount > AMOUNT {
        return Err("Test deposit amount must be 0.1 to 1 test KAS per vault output".into());
    }
    let owner = pair(&keys.owner)?;
    let owner_address = address(&owner);
    let all = c
        .get_utxos_by_addresses(vec![owner_address.clone()])
        .await?;
    let u = all
        .iter()
        .filter(|x| {
            !x.utxo_entry.is_coinbase
                && x.utxo_entry.covenant_id.is_none()
                && x.utxo_entry.script_public_key == pay_to_address_script(&owner_address)
                && x.utxo_entry.amount >= 2 * amount + 2 * FEE
        })
        .min_by_key(|x| x.utxo_entry.amount)
        .ok_or("Fund the printed funding address with at least 3 TN10 test KAS")?;
    let idle = pay_to_script_hash_script(&code(&artifact(false)?));
    let outputs = vec![
        TransactionOutput::new(amount, idle.clone()),
        TransactionOutput::new(amount, idle),
        TransactionOutput::new(
            u.utxo_entry.amount - 2 * amount - FEE,
            pay_to_address_script(&owner_address),
        ),
    ];
    let mut tx = Transaction::new(
        1,
        vec![utxo_input(u, 0)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    let mut b = ScriptBuilder::new();
    b.add_data(&sign(&tx, &[u.utxo_entry.clone().into()], &owner))?;
    tx.inputs[0].signature_script = b.drain();
    tx.finalize();
    verify(&tx, u.utxo_entry.clone().into())?;
    submit(c, &tx, "deposit").await
}
async fn spend(
    c: &KaspaRpcClient,
    keys: &Keys,
    requested_entry: &str,
    outpoint: &str,
) -> Result<()> {
    let prepared = requested_entry.starts_with("prepare-");
    let entry = requested_entry
        .strip_prefix("prepare-")
        .unwrap_or(requested_entry);
    let (txid, index) = outpoint.split_once(':').ok_or("Expected TXID:INDEX")?;
    let requested = TransactionOutpoint {
        transaction_id: txid.parse()?,
        index: index.parse()?,
    };
    let mut found = None;
    for pending in [false, true] {
        let a = artifact(pending)?;
        let addr =
            extract_script_pub_key_address(&pay_to_script_hash_script(&code(&a)), Prefix::Testnet)?;
        for u in c.get_utxos_by_addresses(vec![addr]).await? {
            if TransactionOutpoint::from(u.outpoint) == requested {
                found = Some((a.clone(), u, pending));
            }
        }
    }
    let (a, u, pending) = found.ok_or(
        "Exact outpoint is not an unspent output at this session's pinned vault addresses",
    )?;
    if entry == "initiate" && pending {
        return Err("Already pending".into());
    }
    if entry == "execute" && !pending {
        return Err("Idle output cannot execute".into());
    }
    if u.utxo_entry.covenant_id.is_some() {
        return Err("Unexpected covenant ID binding; refusing incompatible UTXO".into());
    }
    let (signer, destination) = match entry {
        "initiate" => (
            pair(&keys.owner)?,
            pay_to_script_hash_script(&code(&artifact(true)?)),
        ),
        "execute" => (
            pair(&keys.owner)?,
            pay_to_address_script(&address(&pair(&keys.recipient)?)),
        ),
        "recover" => (
            pair(&keys.recovery)?,
            pay_to_address_script(&address(&pair(&keys.recovery)?)),
        ),
        _ => return Err("Unknown entrypoint".into()),
    };
    let amount = u
        .utxo_entry
        .amount
        .checked_sub(FEE)
        .filter(|v| *v > 0)
        .ok_or("Insufficient vault value for fee")?;
    let mut tx = Transaction::new(
        1,
        vec![utxo_input(&u, if entry == "execute" { DELAY } else { 0 })],
        vec![TransactionOutput::new(amount, destination)],
        0,
        Default::default(),
        0,
        vec![],
    );
    let sig = sign(&tx, &[u.utxo_entry.clone().into()], &signer);
    let arg =
        encode_contract_entry_sig_script(&a, "IcpVault", entry, &[ArtifactValue::Bytes(sig)])?;
    let mut b = ScriptBuilder::new();
    b.add_data(&code(&a))?;
    tx.inputs[0].signature_script = [arg, b.drain()].concat();
    tx.finalize();
    verify(&tx, u.utxo_entry.clone().into())?;
    // Deliberately no client-side age veto: an early execute records the NODE's rejection.
    let label = if prepared {
        format!("prepare-{entry}")
    } else {
        entry.to_string()
    };
    submit(c, &tx, &label).await
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(String::as_str).unwrap_or("help");
    if command == "help" {
        println!(
            "icp init | addresses | node | status | anchor | scan HASH | broadcast PREPARED.json | deposit | initiate TXID:INDEX | execute TXID:INDEX | recover TXID:INDEX | prepare-initiate TXID:INDEX | prepare-recover TXID:INDEX\nTestnet-10 only. ICP_RPC_URL optionally selects a Borsh wRPC endpoint. Run from project root."
        );
        return Ok(());
    }
    if command == "init" {
        return init();
    }
    if command == "addresses" {
        let keys: Keys = serde_json::from_slice(&fs::read(".secrets/keys.json")?)?;
        return addresses(&keys);
    }
    if ![
        "node",
        "descriptor",
        "anchor",
        "scan",
        "broadcast",
        "status",
        "deposit",
        "initiate",
        "execute",
        "recover",
        "prepare-initiate",
        "prepare-recover",
    ]
    .contains(&command)
    {
        return Err("Unknown command".into());
    }
    if [
        "scan",
        "broadcast",
        "initiate",
        "execute",
        "recover",
        "prepare-initiate",
        "prepare-recover",
    ]
    .contains(&command)
        && args.get(2).is_none()
    {
        return Err("Expected TXID:INDEX".into());
    }
    fs::create_dir_all("runtime")?;
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
        fs::write("runtime/node.json", serde_json::to_vec_pretty(&info)?)?;
        if command == "node" {
            println!("{}", serde_json::to_string_pretty(&info)?);
            return Ok(());
        }
        if command=="descriptor" {
            let public:Vec<ArtifactValue>=serde_json::from_slice(&fs::read("runtime/public.args.json")?)?;
            let bytes=|i:usize|->Result<Vec<u8>>{if let ArtifactValue::Bytes(b)=&public[i]{Ok(b.clone())}else{Err("Invalid public key".into())}};
            let number=|i:usize|->Result<i64>{if let ArtifactValue::Int(n)=public[i]{Ok(n)}else{Err("Invalid parameter".into())}};
            let recovery=pay_to_address_script(&Address::new(Prefix::Testnet,Version::PubKey,&bytes(1)?));
            let recipient=pay_to_address_script(&Address::new(Prefix::Testnet,Version::PubKey,&bytes(2)?));
            println!("{}",serde_json::to_string(&json!({"network":"testnet-10","idle_spk":pay_to_script_hash_script(&code(&artifact(false)?)),"pending_spk":pay_to_script_hash_script(&code(&artifact(true)?)),"recovery_spk":recovery,"recipient_spk":recipient,"delay_daa":number(3)?,"max_fee":number(4)?}))?);
            return Ok(());
        }
        if command == "anchor" {
            let dag = c.get_block_dag_info().await?;
            println!(
                "{}",
                serde_json::to_string(&json!({"node":info,"anchor":dag.sink.to_string()}))?
            );
            return Ok(());
        }
        if command == "scan" {
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
            println!(
                "{}",
                serde_json::to_string(&json!({"node":info,"from":args[2],"target":target.to_string(),"changes":changes}))?
            );
            return Ok(());
        }
        if command == "broadcast" {
            let prepared: Value = serde_json::from_slice(&fs::read(&args[2])?)?;
            let rpc: RpcTransaction = serde_json::from_value(prepared["transaction"].clone())?;
            let tx = Transaction::try_from(rpc)?;
            if prepared["id"].as_str() != Some(&tx.id().to_string()) {
                return Err("Prepared transaction ID mismatch".into());
            }
            return submit(&c, &tx, "rebroadcast").await;
        }
        if command == "status" {
            return status(&c).await;
        }
        let keys: Keys = serde_json::from_slice(&fs::read(".secrets/keys.json")?)?;
        match command {
            "deposit" => deposit(&c, &keys, args.get(2).map(|v|v.parse()).transpose()?.unwrap_or(AMOUNT)).await,
            _ => spend(&c, &keys, command, &args[2]).await,
        }
    }
    .await;
    c.disconnect().await?;
    result
}
