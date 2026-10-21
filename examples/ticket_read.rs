//! Read-only TN10 adapter. No key loader, signing, broadcast or release command.
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::tx::Transaction;
use kaspa_rpc_core::{RpcTransaction, api::rpc::RpcApi};
use kaspa_wrpc_client::{
    KaspaRpcClient, WrpcEncoding,
    client::{ConnectOptions, ConnectStrategy},
    prelude::{NetworkId, NetworkType},
};
use secp256k1::XOnlyPublicKey;
use serde_json::{Value, json};
use silverscript_abi::encode_hex;
use std::{
    error::Error,
    io::{self, Read},
    time::Duration,
};
type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

fn project(mut value: Value) -> Result<Value> {
    let claimed = value["verboseData"]["transactionId"]
        .as_str()
        .ok_or("Missing accepted transaction ID")?
        .to_string();
    // Auxiliary RPC verbosity is not part of the transaction body or ID.
    value["verboseData"] = Value::Null;
    let rpc: RpcTransaction = serde_json::from_value(value)?;
    let tx = Transaction::try_from(rpc)?;
    if claimed != tx.id().to_string() {
        return Err("Reported native ID differs from recomputed ID".into());
    }
    Ok(
        json!({"transaction_id":tx.id().to_string(),"version":tx.version,
        "inputs":tx.inputs.iter().map(|i|json!({"transaction_id":i.previous_outpoint.transaction_id.to_string(),
            "index":i.previous_outpoint.index,"sequence":i.sequence})).collect::<Vec<_>>(),
        "outputs":tx.outputs.iter().map(|o|json!({"value":o.value,"script_version":o.script_public_key.version(),
            "script":encode_hex(o.script_public_key.script()),"covenant":o.covenant})).collect::<Vec<_>>(),
        "lock_time":tx.lock_time,"subnetwork_id":tx.subnetwork_id.to_string(),"gas":tx.gas,"payload":encode_hex(&tx.payload)}),
    )
}

// P0 pins also bind ID-excluded compute/storage fields. Signature bytes are
// deliberately not compared with the unsigned review: chain acceptance remains
// a trusted-node assertion, independently of private outbox verification.
fn project_p0(value: Value) -> Result<Value> {
    let mut body = value.clone();
    body["verboseData"] = Value::Null;
    let rpc: RpcTransaction = serde_json::from_value(body)?;
    let tx = Transaction::try_from(rpc)?;
    let normalized = serde_json::to_value(RpcTransaction::from(&tx))?;
    let mut projection = project(value)?;
    for (index, input) in projection["inputs"]
        .as_array_mut()
        .ok_or("Missing inputs")?
        .iter_mut()
        .enumerate()
    {
        input["compute_budget"] = normalized["inputs"][index]["computeBudget"].clone();
    }
    projection["storage_mass"] = normalized["storageMass"].clone();
    Ok(projection)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 && ["project", "project-p0"].contains(&args[1].as_str()) {
        let mut raw = Vec::new();
        io::stdin().take(262_145).read_to_end(&mut raw)?;
        if raw.len() > 262_144 {
            return Err("Oversized native projection request".into());
        }
        println!(
            "{}",
            serde_json::to_string(&if args[1] == "project-p0" {
                project_p0(serde_json::from_slice(&raw)?)?
            } else {
                project(serde_json::from_slice(&raw)?)?
            })?
        );
        return Ok(());
    }
    if args.len() != 3 || !["scan", "utxos"].contains(&args[1].as_str()) {
        return Err(
            "Usage: ticket_read project|project-p0 (stdin) | scan HASH | utxos PUBLIC_KEY".into(),
        );
    }
    // Validate arguments before opening a connection.
    let start = if args[1] == "scan" {
        Some(args[2].parse::<kaspa_consensus_core::tx::TransactionId>()?)
    } else {
        None
    };
    let address = if args[1] == "utxos" {
        let key: XOnlyPublicKey = args[2].parse()?;
        Some(Address::new(
            Prefix::Testnet,
            Version::PubKey,
            &key.serialize(),
        ))
    } else {
        None
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
    let result=async {
        let node=tokio::time::timeout(Duration::from_secs(10),client.get_server_info()).await??;
        icp_testnet::check_network(&node.network_id.to_string(),node.is_synced,node.has_utxo_index,node.virtual_daa_score)?;
        let before=tokio::time::timeout(Duration::from_secs(10),client.get_block_dag_info()).await??.sink;
        if let Some(from)=start {
            let changes=tokio::time::timeout(Duration::from_secs(15),client.get_virtual_chain_from_block_v2(
                from,Some(kaspa_rpc_core::RpcDataVerbosityLevel::Full),Some(0))).await??;
            println!("{}",serde_json::to_string(&json!({"node":node,"from":from.to_string(),"target":before.to_string(),"changes":changes}))?);
        } else {
            let address=address.ok_or("Missing read address")?;
            let utxos=tokio::time::timeout(Duration::from_secs(10),client.get_utxos_by_addresses(vec![address.clone()])).await??;
            let after=tokio::time::timeout(Duration::from_secs(10),client.get_block_dag_info()).await??.sink;
            println!("{}",serde_json::to_string(&json!({"node":node,"publicKey":args[2],"address":address.to_string(),"from":before.to_string(),
                "target":after.to_string(),"utxos":utxos}))?);
        }
        Ok(())
    }.await;
    client.disconnect().await?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::tx::{
        ScriptPublicKey, TransactionInput, TransactionOutpoint, TransactionOutput,
    };
    fn fixture() -> Value {
        let tx = Transaction::new(
            1,
            vec![TransactionInput::new_with_compute_budget(
                TransactionOutpoint {
                    transaction_id: "11".repeat(32).parse().unwrap(),
                    index: 0,
                },
                vec![],
                0,
                100,
            )],
            vec![TransactionOutput::new(
                10_000_000,
                ScriptPublicKey::new(0, vec![0x51].into()),
            )],
            0,
            Default::default(),
            0,
            vec![1, 2, 3],
        );
        let mut v = serde_json::to_value(RpcTransaction::from(&tx)).unwrap();
        v["verboseData"] = json!({"transactionId":tx.id().to_string()});
        v
    }
    #[test]
    fn recomputes_native_id_and_projects_body() {
        let v = fixture();
        let p = project(v.clone()).unwrap();
        assert_eq!(p["transaction_id"], v["verboseData"]["transactionId"]);
        assert_eq!(p["outputs"][0]["script_version"], 0);
    }
    #[test]
    fn payload_mutation_with_copied_id_fails() {
        let mut v = fixture();
        v["payload"] = json!("00");
        assert!(project(v).is_err());
    }
    #[test]
    fn output_mutation_with_copied_id_fails() {
        let mut v = fixture();
        v["outputs"][0]["value"] = json!(9);
        assert!(project(v).is_err());
    }
    #[test]
    fn input_mutation_with_copied_id_fails() {
        let mut v = fixture();
        v["inputs"][0]["previousOutpoint"]["index"] = json!(1);
        assert!(project(v).is_err());
    }
    #[test]
    fn claimed_id_is_mandatory_and_canonical() {
        let mut v = fixture();
        v["verboseData"] = Value::Null;
        assert!(project(v).is_err());
        let mut v = fixture();
        v["verboseData"]["transactionId"] = json!("ab".repeat(32));
        assert!(project(v).is_err());
    }
    #[test]
    fn ambiguous_integer_types_fail() {
        for bad in [json!(false), json!(1.0), json!(-1)] {
            let mut v = fixture();
            v["inputs"][0]["sequence"] = bad;
            assert!(project(v).is_err());
        }
    }
    #[test]
    fn compute_mass_and_signature_are_outside_projection() {
        let v = fixture();
        let expected = project(v.clone()).unwrap();
        let mut v = v;
        v["inputs"][0]["computeBudget"] = json!(101);
        v["inputs"][0]["signatureScript"] = json!("abcd");
        v["storageMass"] = json!(99);
        v["mass"] = json!(99);
        assert_eq!(project(v).unwrap(), expected);
    }
    #[test]
    fn native_conversion_rejects_wrong_v1_mass_variant() {
        let mut v = fixture();
        v["inputs"][0]["sigOpCount"] = json!(1);
        assert!(project(v).is_err());
    }
    #[test]
    fn p0_projection_binds_compute_and_storage_excluded_by_legacy_projection() {
        let v = fixture();
        let expected = project_p0(v.clone()).unwrap();
        assert_eq!(expected["inputs"][0]["compute_budget"], 100);
        for field in ["compute", "storage"] {
            let mut changed = v.clone();
            if field == "compute" {
                changed["inputs"][0]["computeBudget"] = json!(101);
            } else {
                changed["storageMass"] = json!(99);
                changed["mass"] = json!(99);
            }
            assert_eq!(
                project(changed.clone()).unwrap(),
                project(v.clone()).unwrap()
            );
            assert_ne!(project_p0(changed).unwrap(), expected);
        }
    }
    #[test]
    fn p0_projection_allows_signed_body_but_does_not_attest_signature_validity() {
        let v = fixture();
        let expected = project_p0(v.clone()).unwrap();
        let mut changed = v;
        changed["inputs"][0]["signatureScript"] = json!("abcd");
        assert_eq!(project_p0(changed).unwrap(), expected);
    }
    #[test]
    fn p0_recomputes_id_and_rejects_wrong_compute_variant() {
        let mut v = fixture();
        v["payload"] = json!("00");
        assert!(project_p0(v).is_err());
        let mut v = fixture();
        v["inputs"][0]["sigOpCount"] = json!(1);
        assert!(project_p0(v).is_err());
    }
}
