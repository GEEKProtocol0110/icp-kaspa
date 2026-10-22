//! TN10-only P0 submission. No keys/signing, selection, replacement or retry command.
#[path = "support/ticket_pilot_verify.rs"]
mod verified;
use kaspa_consensus_core::tx::UtxoEntry;
use kaspa_rpc_core::{RpcUtxosByAddressesEntry, api::rpc::RpcApi};
use kaspa_wrpc_client::{
    KaspaRpcClient, WrpcEncoding,
    client::{ConnectOptions, ConnectStrategy},
    prelude::{NetworkId, NetworkType},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::HashSet,
    io::{self, Read},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use verified::{Record, canonical, parse, verify};
type Result<T> = std::result::Result<T, String>;
const MODE: &str = "TN10_P0_SUBMISSION_REQUEST_V0";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    mode: String,
    endpoint: String,
    not_before: u64,
    not_after: u64,
    record: Record,
}

fn port(value: &str) -> bool {
    value
        .parse::<u16>()
        .is_ok_and(|p| p > 0 && p.to_string() == value)
}
fn endpoint(value: &str) -> Result<()> {
    let authority = value
        .strip_prefix("wss://")
        .and_then(|v| v.strip_suffix("/kaspa/testnet-10/wrpc/borsh"))
        .ok_or("Pinned TLS TN10 endpoint required")?;
    let host = if let Some((host, p)) = authority.split_once(':') {
        if !port(p) {
            return Err("Invalid endpoint port".into());
        }
        host
    } else {
        authority
    };
    if host.len() > 253
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
    {
        return Err("Canonical endpoint hostname required".into());
    }
    Ok(())
}
fn route(requested: &str, connected: &str, upstream: Option<&str>) -> Result<()> {
    endpoint(requested)?;
    if connected == requested {
        return Ok(());
    }
    if upstream != Some(requested) || !connected.strip_prefix("ws://127.0.0.1:").is_some_and(port) {
        return Err("Only the pinned endpoint or its explicit local relay is allowed".into());
    }
    Ok(())
}
fn window(start: u64, end: u64, now: Duration) -> Result<Duration> {
    if start >= end || end - start > 30 || now.as_secs() < start || now >= Duration::from_secs(end)
    {
        return Err("Submission observation window expired or invalid".into());
    }
    Ok(Duration::from_secs(end) - now)
}
fn now() -> Result<Duration> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "Uncertain native clock".into())
}
fn verified_request(raw: &[u8]) -> Result<Request> {
    let r: Request = parse(raw)?;
    if r.mode != MODE || r.not_before >= r.not_after || r.not_after - r.not_before > 30 {
        return Err("Wrong submission request policy".into());
    }
    endpoint(&r.endpoint)?;
    verify(&r.record)?;
    Ok(r)
}
fn exact_input(
    point: &kaspa_rpc_core::RpcTransactionOutpoint,
    expected: &UtxoEntry,
    rows: &[RpcUtxosByAddressesEntry],
    daa: u64,
) -> Result<()> {
    if rows.len() > 100_000 || expected.block_daa_score > daa {
        return Err("Invalid UTXO view".into());
    }
    let mut seen = HashSet::new();
    let mut found = false;
    for row in rows {
        if !seen.insert((row.outpoint.transaction_id, row.outpoint.index)) {
            return Err("Duplicate UTXO report".into());
        }
        if row.outpoint == *point {
            let entry = UtxoEntry::from(row.utxo_entry.clone());
            if &entry != expected {
                return Err("Live input differs from signed outbox metadata".into());
            }
            found = true;
        }
    }
    if !found {
        return Err("Exact signed input is not currently unspent".into());
    }
    Ok(())
}
async fn send(r: Request) -> Result<serde_json::Value> {
    let started_monotonic = tokio::time::Instant::now();
    let started = now()?;
    let remaining = window(r.not_before, r.not_after, started)?;
    let deadline = started_monotonic + remaining;
    let url = std::env::var("ICP_RPC_URL").unwrap_or_else(|_| r.endpoint.clone());
    let upstream = std::env::var("ICP_UPSTREAM_URL").ok();
    route(&r.endpoint, &url, upstream.as_deref())?;
    let client = KaspaRpcClient::new(
        WrpcEncoding::Borsh,
        Some(&url),
        None,
        Some(NetworkId::with_suffix(NetworkType::Testnet, 10)),
        None,
    )
    .map_err(|_| "Native client failed")?;
    let result = tokio::time::timeout_at(deadline, async {
        client
            .connect(Some(ConnectOptions {
                block_async_connect: true,
                connect_timeout: Some(Duration::from_secs(10)),
                strategy: ConnectStrategy::Fallback,
                ..Default::default()
            }))
            .await
            .map_err(|_| "Pinned connection failed")?;
        let node = client
            .get_server_info()
            .await
            .map_err(|_| "Node gate unavailable")?;
        icp_testnet::check_network(
            &node.network_id.to_string(),
            node.is_synced,
            node.has_utxo_index,
            node.virtual_daa_score,
        )
        .map_err(str::to_string)?;
        let key = if r.record.action == "issue" {
            &r.record.plan.funding_key
        } else {
            &r.record.plan.ticket_key
        };
        let address = verified::pilot::address(key)?;
        let rows = client
            .get_utxos_by_addresses(vec![address])
            .await
            .map_err(|_| "Input gate unavailable")?;
        exact_input(
            &r.record.signed_rpc.inputs[0].previous_outpoint,
            &r.record.entry,
            &rows,
            node.virtual_daa_score,
        )?;
        let node = client
            .get_server_info()
            .await
            .map_err(|_| "Final node gate unavailable")?;
        icp_testnet::check_network(
            &node.network_id.to_string(),
            node.is_synced,
            node.has_utxo_index,
            node.virtual_daa_score,
        )
        .map_err(str::to_string)?;
        exact_input(
            &r.record.signed_rpc.inputs[0].previous_outpoint,
            &r.record.entry,
            &rows,
            node.virtual_daa_score,
        )?;
        let final_time = now()?;
        if final_time < started {
            return Err("Native clock moved backwards".into());
        }
        window(r.not_before, r.not_after, final_time)?;
        // One ordinary submit call with orphan admission disabled; no replacement API.
        // Every error/timeout is uncertain.
        let id = client
            .submit_transaction(r.record.signed_rpc.clone(), false)
            .await
            .map_err(|_| "Submission outcome unknown")?;
        if id.to_string() != r.record.transaction_id {
            return Err("Submission reply ID mismatch".into());
        }
        Ok(json!({"transaction_id":id.to_string(),"accepted":true}))
    })
    .await
    .map_err(|_| "Submission deadline elapsed".to_string())
    .and_then(|v: Result<_>| v);
    // Cleanup cannot create a retry or erase an acknowledged response.
    let _ = tokio::time::timeout(Duration::from_secs(2), client.disconnect()).await;
    result
}
#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 || !["verify", "submit"].contains(&args[1].as_str()) {
        return Err("Usage: ticket_pilot_submit verify|submit (canonical stdin request)".into());
    }
    let mut raw = Vec::new();
    io::stdin()
        .take(65_537)
        .read_to_end(&mut raw)
        .map_err(|_| "Request read failed")?;
    let r = verified_request(&raw).map_err(|_| "P0 submission request rejected")?;
    let reply = if args[1] == "verify" {
        json!({"mode":"TN10_P0_SUBMISSION_REQUEST_VALID_NOT_SENT","transaction_id":r.record.transaction_id})
    } else {
        send(r)
            .await
            .map_err(|_| "P0 submission outcome uncertain; reconcile without retry")?
    };
    println!(
        "{}",
        String::from_utf8(canonical(&reply)?).map_err(|_| "Reply encoding failed")?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input() -> (
        kaspa_rpc_core::RpcTransactionOutpoint,
        UtxoEntry,
        RpcUtxosByAddressesEntry,
    ) {
        let point = kaspa_rpc_core::RpcTransactionOutpoint {
            transaction_id: "11".repeat(32).parse().unwrap(),
            index: 0,
        };
        let entry = UtxoEntry::new(
            24_000_000,
            kaspa_consensus_core::tx::ScriptPublicKey::new(0, vec![0x51].into()),
            123,
            false,
            None,
        );
        let row = RpcUtxosByAddressesEntry {
            address: None,
            outpoint: point.clone(),
            utxo_entry: entry.clone().into(),
        };
        (point, entry, row)
    }
    #[test]
    fn exact_complete_input_is_required() {
        let (point, entry, row) = input();
        assert!(exact_input(&point, &entry, &[row], 123).is_ok());
    }
    #[test]
    fn absent_wrong_or_duplicate_outpoint_blocks_submission() {
        let (point, entry, row) = input();
        assert!(exact_input(&point, &entry, &[], 123).is_err());
        let mut wrong = row.clone();
        wrong.outpoint.index = 1;
        assert!(exact_input(&point, &entry, &[wrong], 123).is_err());
        assert!(exact_input(&point, &entry, &[row.clone(), row], 123).is_err());
    }
    #[test]
    fn all_live_entry_fields_match_saved_native_metadata() {
        let (point, entry, row) = input();
        for field in 0..5 {
            let mut changed = row.clone();
            match field {
                0 => changed.utxo_entry.amount -= 1,
                1 => changed.utxo_entry.block_daa_score += 1,
                2 => changed.utxo_entry.is_coinbase = true,
                3 => changed.utxo_entry.covenant_id = Some("22".repeat(32).parse().unwrap()),
                _ => {
                    changed.utxo_entry.script_public_key =
                        kaspa_consensus_core::tx::ScriptPublicKey::new(0, vec![0x52].into())
                }
            }
            assert!(exact_input(&point, &entry, &[changed], 124).is_err());
        }
    }
    #[test]
    fn input_creation_daa_cannot_exceed_current_node_view() {
        let (point, entry, row) = input();
        assert!(exact_input(&point, &entry, &[row], 122).is_err());
    }
    #[test]
    fn endpoint_has_no_resolver_network_switch_credentials_or_query() {
        assert!(endpoint("wss://node.invalid/kaspa/testnet-10/wrpc/borsh").is_ok());
        for v in [
            "ws://node.invalid/kaspa/testnet-10/wrpc/borsh",
            "wss://node.invalid/kaspa/mainnet/wrpc/borsh",
            "wss://user@node.invalid/kaspa/testnet-10/wrpc/borsh",
            "wss://node.invalid/kaspa/testnet-10/wrpc/borsh?x=1",
            "wss://Node.invalid/kaspa/testnet-10/wrpc/borsh",
            "wss://node.invalid:0/kaspa/testnet-10/wrpc/borsh",
        ] {
            assert!(endpoint(v).is_err(), "{v}");
        }
    }
    #[test]
    fn relay_requires_exact_upstream_and_canonical_local_port() {
        let e = "wss://node.invalid/kaspa/testnet-10/wrpc/borsh";
        assert!(route(e, e, None).is_ok());
        assert!(route(e, "ws://127.0.0.1:1234", Some(e)).is_ok());
        for v in [
            "ws://127.0.0.2:1234",
            "ws://127.0.0.1:01234",
            "ws://127.0.0.1:1234/",
            "ws://attacker:1234",
        ] {
            assert!(route(e, v, Some(e)).is_err());
        }
        assert!(route(e, "ws://127.0.0.1:1234", None).is_err());
        assert!(route(e, "ws://127.0.0.1:1234", Some("wss://other.invalid")).is_err());
    }
    #[test]
    fn deadline_rejects_future_expired_fractional_boundary_and_wide_windows() {
        assert_eq!(
            window(100, 105, Duration::new(101, 500_000_000)).unwrap(),
            Duration::new(3, 500_000_000)
        );
        for (a, b, n) in [
            (100, 105, 99),
            (100, 105, 105),
            (105, 100, 101),
            (100, 131, 101),
            (100, 100, 100),
        ] {
            assert!(window(a, b, Duration::from_secs(n)).is_err());
        }
    }
    #[test]
    fn closed_request_rejects_unknown_and_duplicate_fields_before_network() {
        for raw in [
            b"{}".as_slice(),
            b"{\"mode\":\"a\",\"mode\":\"b\"}".as_slice(),
            &vec![b' '; 65_537],
        ] {
            assert!(verified_request(raw).is_err());
        }
    }
}
