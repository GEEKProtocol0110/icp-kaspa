//! Transfer one explicitly pinned, <=1-test-KAS P2PK UTXO to a fresh v1 owner.
//! Source key is an independent role file; this helper never loads a legacy bundle.
use icp_testnet::protected::{Policy, Role, load_signer};
use kaspa_consensus_core::{
    hashing::{
        sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash},
        sighash_type::SIG_HASH_ALL,
    },
    tx::{
        MutableTransaction, PopulatedTransaction, Transaction, TransactionInput,
        TransactionOutpoint, TransactionOutput, UtxoEntry,
    },
};
use kaspa_rpc_core::{RpcTransaction, api::rpc::RpcApi};
use kaspa_txscript::{
    EngineCtx, EngineFlags, TxScriptEngine, caches::Cache, script_builder::ScriptBuilder,
    standard::pay_to_address_script,
};
use kaspa_wrpc_client::{
    KaspaRpcClient, WrpcEncoding,
    client::{ConnectOptions, ConnectStrategy},
    prelude::{NetworkId, NetworkType},
};
use serde_json::{Value, json};
use std::{error::Error, fs, io::Write, path::Path, time::Duration};
type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
const FEE: u64 = 2_000_000;

#[tokio::main]
async fn main() -> Result<()> {
    let file = std::env::args()
        .nth(1)
        .ok_or("Expected public funding plan JSON")?;
    let plan: Value = serde_json::from_slice(&fs::read(file)?)?;
    let mut source: Policy =
        serde_json::from_slice(&fs::read(plan["policy"].as_str().ok_or("Missing policy")?)?)?;
    source.validate()?;
    let destination = pay_to_address_script(&source.address(Role::Owner)?);
    source.owner = plan["source_public_key"]
        .as_str()
        .ok_or("Missing source public key")?
        .into();
    source.validate()?;
    let key = load_signer(
        Path::new(&std::env::var("ICP_SIGNER_KEY_FILE")?),
        Role::Owner,
        &source,
    )?;
    let amount = plan["amount"].as_u64().ok_or("Missing amount")?;
    let input_amount = plan["source_amount"]
        .as_u64()
        .ok_or("Missing source amount")?;
    if !(10_000_000..=100_000_000).contains(&amount)
        || input_amount > 100_000_000
        || input_amount <= amount + FEE
    {
        return Err("Funding plan exceeds test-only limits or leaves no change".into());
    }
    let (id, index) = plan["source_outpoint"]
        .as_str()
        .ok_or("Missing exact outpoint")?
        .split_once(':')
        .ok_or("Invalid outpoint")?;
    let requested = TransactionOutpoint {
        transaction_id: id.parse()?,
        index: index.parse()?,
    };
    let path = Path::new(plan["receipt"].as_str().ok_or("Missing receipt path")?);
    if path.exists() {
        return Err("Funding receipt exists; reconcile it before taking any further action".into());
    }
    let url = std::env::var("ICP_RPC_URL")?;
    let c = KaspaRpcClient::new(
        WrpcEncoding::Borsh,
        Some(&url),
        None,
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
    let outcome=async {
        let node=c.get_server_info().await?;
        icp_testnet::check_network(&node.network_id.to_string(),node.is_synced,node.has_utxo_index,node.virtual_daa_score)?;
        let utxos=c.get_utxos_by_addresses(vec![source.address(Role::Owner)?]).await?;
        let u=utxos.iter().find(|u|TransactionOutpoint::from(u.outpoint)==requested).ok_or("Pinned donor outpoint is not unspent")?;
        if u.utxo_entry.amount!=input_amount || u.utxo_entry.covenant_id.is_some() || u.utxo_entry.is_coinbase || u.utxo_entry.script_public_key!=pay_to_address_script(&source.address(Role::Owner)?) {return Err("Pinned donor UTXO mismatch".into());}
        let entry:UtxoEntry=u.utxo_entry.clone().into();
        let mut tx=Transaction::new(1,vec![TransactionInput::new_with_compute_budget(requested,vec![],0,100)],
            vec![TransactionOutput::new(amount,destination),TransactionOutput::new(input_amount-amount-FEE,pay_to_address_script(&source.address(Role::Owner)?))],0,Default::default(),0,vec![]);
        icp_testnet::commit_storage_mass(&tx,std::slice::from_ref(&entry))?;
        let mutable=MutableTransaction::with_entries(tx.clone(),vec![entry.clone()]);
        let hash=calc_schnorr_signature_hash(&mutable.as_verifiable(),0,SIG_HASH_ALL,&SigHashReusedValuesUnsync::new());
        let mut sig=key.sign_schnorr(secp256k1::Message::from_digest_slice(&hash.as_bytes())?).as_ref().to_vec();sig.push(SIG_HASH_ALL.to_u8());
        let mut builder=ScriptBuilder::new();builder.add_data(&sig)?;tx.inputs[0].signature_script=builder.drain();tx.finalize();
        let populated=PopulatedTransaction::new(&tx,vec![entry.clone()]);let cache=Cache::new(1000);let reuse=SigHashReusedValuesUnsync::new();
        TxScriptEngine::from_transaction_input_with_script_units_limit(&populated,&tx.inputs[0],0,&entry,EngineCtx::new(&cache).with_reused(&reuse),EngineFlags{covenants_enabled:true,..Default::default()},tx.inputs[0].compute_commit.allowed_script_units()).execute()?;
        let rpc=RpcTransaction::from(&tx);
        let mut receipt=json!({"version":"protected-v1","network":"testnet-10","status":"PREPARED","node":node,"transaction":rpc,"id":tx.id().to_string(),"funding_amount":amount});
        let mut file=fs::OpenOptions::new().write(true).create_new(true).open(path)?;file.write_all(&serde_json::to_vec_pretty(&receipt)?)?;file.sync_all()?;
        let node=c.get_server_info().await?;icp_testnet::check_network(&node.network_id.to_string(),node.is_synced,node.has_utxo_index,node.virtual_daa_score)?;
        match c.submit_transaction(rpc,false).await {
            Ok(id)=>{receipt["status"]=json!("MEMPOOL_ACCEPTED");fs::write(path,serde_json::to_vec_pretty(&receipt)?)?;println!("Funding broadcast: {id}; confirmation must be checked separately.");Ok(())},
            Err(e)=>{receipt["status"]=json!("REJECTED_OR_UNKNOWN");receipt["error"]=json!(e.to_string());fs::write(path,serde_json::to_vec_pretty(&receipt)?)?;Err(e.into())}
        }
    }.await;
    c.disconnect().await?;
    outcome
}
