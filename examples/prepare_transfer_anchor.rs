//! TN10-only self-returning payload anchor. Preparation never broadcasts.
use icp_testnet::protected::{Policy, Role, load_signer};
use kaspa_addresses::{Address, Prefix, Version};
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
use secp256k1::{Keypair, Message, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use silverscript_abi::{decode_hex, encode_hex};
use std::{error::Error, fs, io::Write, path::Path, time::Duration};
type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
const FEE: u64 = 2_000_000;
const PREFIX: &[u8] = b"ICP-XFER-TN10-V0\0";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    version: String,
    network: String,
    policy: Policy,
    source_outpoint: String,
    source_amount: u64,
    payload: String,
}

impl Plan {
    fn material(&self) -> Result<(TransactionOutpoint, Vec<u8>, Address)> {
        self.policy.validate()?;
        if self.version != "icp-transfer-anchor-v0"
            || self.network != "testnet-10"
            || !(12_000_000..=100_000_000).contains(&self.source_amount)
        {
            return Err("Invalid TN10 anchor plan or source limit".into());
        }
        let (id, index) = self
            .source_outpoint
            .split_once(':')
            .ok_or("Expected exact outpoint")?;
        let point = TransactionOutpoint {
            transaction_id: id.parse()?,
            index: index.parse()?,
        };
        if format!("{}:{}", point.transaction_id, point.index) != self.source_outpoint {
            return Err("Noncanonical outpoint".into());
        }
        let payload = decode_hex(&self.payload)?;
        if payload.len() != PREFIX.len() + 32
            || !payload.starts_with(PREFIX)
            || encode_hex(&payload) != self.payload
        {
            return Err("Expected exact transfer commitment payload".into());
        }
        Ok((point, payload, self.policy.address(Role::Owner)?))
    }
}

fn build(plan: &Plan, entry: UtxoEntry, key: &Keypair) -> Result<Transaction> {
    let (point, payload, address) = plan.material()?;
    let spk = pay_to_address_script(&address);
    if entry.amount != plan.source_amount
        || entry.script_public_key != spk
        || entry.is_coinbase
        || entry.covenant_id.is_some()
        || key.x_only_public_key().0.serialize().as_slice()
            != plan.policy.public_key(Role::Owner)?
    {
        return Err("Exact source UTXO or signer mismatch".into());
    }
    let mut tx = Transaction::new(
        1,
        vec![TransactionInput::new_with_compute_budget(
            point,
            vec![],
            0,
            100,
        )],
        vec![TransactionOutput::new(plan.source_amount - FEE, spk)],
        0,
        Default::default(),
        0,
        payload,
    );
    icp_testnet::commit_storage_mass(&tx, std::slice::from_ref(&entry))?;
    let mutable = MutableTransaction::with_entries(tx.clone(), vec![entry.clone()]);
    let hash = calc_schnorr_signature_hash(
        &mutable.as_verifiable(),
        0,
        SIG_HASH_ALL,
        &SigHashReusedValuesUnsync::new(),
    );
    let mut signature = key
        .sign_schnorr(Message::from_digest_slice(&hash.as_bytes())?)
        .as_ref()
        .to_vec();
    signature.push(SIG_HASH_ALL.to_u8());
    let mut script = ScriptBuilder::new();
    script.add_data(&signature)?;
    tx.inputs[0].signature_script = script.drain();
    tx.finalize();
    verify(&tx, &entry)?;
    Ok(tx)
}

fn verify(tx: &Transaction, entry: &UtxoEntry) -> Result<()> {
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
    .execute()?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3
        || !["utxos", "prepare"].contains(&args[1].as_str())
        || (args[1] == "prepare" && args.len() != 4)
    {
        return Err(
            "Usage: prepare_transfer_anchor utxos PUBLIC_KEY | prepare PLAN.json NEW_RECEIPT.json"
                .into(),
        );
    }
    let plan: Option<Plan> = if args[1] == "prepare" {
        Some(serde_json::from_slice(&fs::read(&args[2])?)?)
    } else {
        None
    };
    let address = if let Some(p) = &plan {
        if Path::new(&args[3]).exists() {
            return Err("Receipt exists; reconcile before retrying".into());
        }
        p.material()?.2
    } else {
        let key: XOnlyPublicKey = args[2].parse()?;
        Address::new(Prefix::Testnet, Version::PubKey, &key.serialize())
    };
    let url = std::env::var("ICP_RPC_URL")?;
    let client = KaspaRpcClient::new(
        WrpcEncoding::Borsh,
        Some(&url),
        None,
        Some(NetworkId::with_suffix(NetworkType::Testnet, 10)),
        None,
    )?;
    tokio::time::timeout(
        Duration::from_secs(20),
        client.connect(Some(ConnectOptions {
            block_async_connect: true,
            connect_timeout: Some(Duration::from_secs(10)),
            strategy: ConnectStrategy::Fallback,
            ..Default::default()
        })),
    )
    .await??;
    let outcome = async {
        let node = client.get_server_info().await?;
        icp_testnet::check_network(&node.network_id.to_string(), node.is_synced, node.has_utxo_index, node.virtual_daa_score)?;
        let utxos = client.get_utxos_by_addresses(vec![address.clone()]).await?;
        if let Some(p) = plan {
            let point = p.material()?.0;
            let source = utxos.iter().find(|u| TransactionOutpoint::from(u.outpoint) == point).ok_or("Pinned source is not unspent; reconcile")?;
            let key = load_signer(Path::new(&std::env::var("ICP_SIGNER_KEY_FILE")?), Role::Owner, &p.policy)?;
            let tx = build(&p, source.utxo_entry.clone().into(), &key)?;
            let value = json!({"version":"icp-transfer-anchor-v0","network":"testnet-10","status":"PREPARED","id":tx.id().to_string(),"transaction":RpcTransaction::from(&tx),"node":node,"plan":p,"source":source,"fee":FEE});
            let mut options = fs::OpenOptions::new(); options.write(true).create_new(true);
            #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
            let mut file = options.open(&args[3])?; file.write_all(&serde_json::to_vec_pretty(&value)?)?; file.sync_all()?;
            // Persist the directory entry before a caller can broadcast.
            fs::File::open(Path::new(&args[3]).parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")))?.sync_all()?;
            println!("{}", serde_json::to_string(&value)?);
        } else {
            println!("{}", serde_json::to_string(&json!({"node":node,"address":address.to_string(),"utxos":utxos}))?);
        }
        Ok(())
    }.await;
    client.disconnect().await?;
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Secp256k1, SecretKey};
    fn fixture() -> (Plan, UtxoEntry, Keypair) {
        let key = |n| {
            Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[n; 32]).unwrap())
        };
        let public = |n| encode_hex(&key(n).x_only_public_key().0.serialize());
        let policy = Policy {
            version: "protected-v1".into(),
            network: "testnet-10".into(),
            owner: public(1),
            recovery: public(2),
            recipient: public(3),
            cold: public(4),
            delay_daa: 600,
            cold_delay_daa: 1800,
            max_fee: FEE,
        };
        let mut bytes = PREFIX.to_vec();
        bytes.extend([7; 32]);
        let plan = Plan {
            version: "icp-transfer-anchor-v0".into(),
            network: "testnet-10".into(),
            policy,
            source_outpoint: format!("{}:0", "11".repeat(32)),
            source_amount: 30_000_000,
            payload: encode_hex(&bytes),
        };
        let entry = UtxoEntry::new(
            plan.source_amount,
            pay_to_address_script(&plan.policy.address(Role::Owner).unwrap()),
            467579700,
            false,
            None,
        );
        (plan, entry, key(1))
    }
    #[test]
    fn exact_self_return_and_native_signature() {
        let (p, u, k) = fixture();
        let tx = build(&p, u.clone(), &k).unwrap();
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.inputs[0].previous_outpoint, p.material().unwrap().0);
        assert_eq!(tx.outputs[0].value, p.source_amount - FEE);
        assert_eq!(tx.outputs[0].script_public_key, u.script_public_key);
        assert_eq!(encode_hex(&tx.payload), p.payload);
        verify(&tx, &u).unwrap();
    }
    #[test]
    fn payload_and_output_tampering_invalidate_signature() {
        let (p, u, k) = fixture();
        let original = build(&p, u.clone(), &k).unwrap();
        let mut tx = original.clone();
        tx.payload[48] ^= 1;
        tx.finalize();
        assert!(verify(&tx, &u).is_err());
        let mut tx = original;
        tx.outputs[0].value -= 1;
        tx.finalize();
        assert!(verify(&tx, &u).is_err());
    }
    #[test]
    fn source_amount_script_and_coinbase_must_match() {
        let (p, u, k) = fixture();
        let mut wrong = u.clone();
        wrong.amount += 1;
        assert!(build(&p, wrong, &k).is_err());
        let mut wrong = u.clone();
        wrong.script_public_key = pay_to_address_script(&p.policy.address(Role::Cold).unwrap());
        assert!(build(&p, wrong, &k).is_err());
        let mut wrong = u;
        wrong.is_coinbase = true;
        assert!(build(&p, wrong, &k).is_err());
    }
    #[test]
    fn wrong_role_key_is_rejected() {
        let (p, u, _) = fixture();
        let key =
            Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[4; 32]).unwrap());
        assert!(build(&p, u, &key).is_err());
    }
    #[test]
    fn network_value_and_payload_limits_fail_closed() {
        let (p, _, _) = fixture();
        for amount in [0, 11_999_999, 100_000_001, u64::MAX] {
            let mut wrong = p.clone();
            wrong.source_amount = amount;
            assert!(wrong.material().is_err());
        }
        let mut wrong = p.clone();
        wrong.network = "mainnet".into();
        assert!(wrong.material().is_err());
        for payload in [
            String::new(),
            p.payload.to_uppercase(),
            format!("{}00", p.payload),
        ] {
            let mut wrong = p.clone();
            wrong.payload = payload;
            assert!(wrong.material().is_err());
        }
    }
    #[test]
    fn noncanonical_outpoint_is_rejected() {
        let (mut p, _, _) = fixture();
        p.source_outpoint.push('0');
        assert!(p.material().is_err());
    }
}
