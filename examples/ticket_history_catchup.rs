//! Read-only historical pages. No keys, UTXO samples, signing or submission.
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_wrpc_client::{
    KaspaRpcClient, WrpcEncoding,
    client::{ConnectOptions, ConnectStrategy},
    prelude::{NetworkId, NetworkType},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    error::Error,
    io::{self, Read},
    time::Duration,
};
type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    cursor: String,
    window: u64,
}

fn parse(raw: &[u8]) -> Result<Request> {
    if raw.len() > 1024 || !raw.is_ascii() {
        return Err("Bounded public request required".into());
    }
    let r: Request = serde_json::from_slice(raw)?;
    if icp_testnet::native_ticket_lab::canonical(&r)? != raw
        || r.cursor.len() != 64
        || !r
            .cursor
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !matches!(r.window, 16 | 64 | 256 | 1024)
    {
        return Err("Canonical cursor and supported history window required".into());
    }
    let _: kaspa_rpc_core::RpcHash = r.cursor.parse()?;
    Ok(r)
}

fn confirmations(sink: u64, start: u64, window: u64) -> u64 {
    sink.saturating_sub(start).saturating_sub(window)
}

async fn read(r: Request) -> Result<Value> {
    let url = std::env::var("ICP_RPC_URL")?;
    let client = KaspaRpcClient::new(
        WrpcEncoding::Borsh,
        Some(&url),
        None,
        Some(NetworkId::with_suffix(NetworkType::Testnet, 10)),
        None,
    )?;
    let result = tokio::time::timeout(Duration::from_secs(25), async {
        client
            .connect(Some(ConnectOptions {
                block_async_connect: true,
                connect_timeout: Some(Duration::from_secs(10)),
                strategy: ConnectStrategy::Fallback,
                ..Default::default()
            }))
            .await?;
        let node = client.get_server_info().await?;
        icp_testnet::check_network(
            &node.network_id.to_string(),
            node.is_synced,
            node.has_utxo_index,
            node.virtual_daa_score,
        )?;
        let target = client.get_block_dag_info().await?.sink;
        let start: kaspa_rpc_core::RpcHash = r.cursor.parse()?;
        let start_block = client.get_block(start, false).await?;
        let sink_block = client.get_block(target, false).await?;
        if start_block.verbose_data.as_ref().map(|v| v.hash) != Some(start)
            || sink_block.verbose_data.as_ref().map(|v| v.hash) != Some(target)
        {
            return Err("History header identity mismatch".into());
        }
        let start_score = start_block.header.blue_score;
        let sink_score = sink_block.header.blue_score;
        let minimum = confirmations(sink_score, start_score, r.window);
        // The node strips the new end by blue-score distance before fetching full
        // accepted transactions. This is a page-size hint, never a finality claim.
        let changes = client
            .get_virtual_chain_from_block_v2(
                start,
                Some(kaspa_rpc_core::RpcDataVerbosityLevel::Full),
                Some(minimum),
            )
            .await?;
        let end = client.get_server_info().await?;
        icp_testnet::check_network(
            &end.network_id.to_string(),
            end.is_synced,
            end.has_utxo_index,
            end.virtual_daa_score,
        )?;
        Ok::<_, Box<dyn Error + Send + Sync>>(json!({
            "mode":"TN10_P0_HISTORY_CATCHUP_V1", "window":r.window,
            "start_blue_score":start_score, "sink_blue_score":sink_score,
            "min_confirmation_count":minimum,
            "scan":{"node":end,"from":r.cursor,"target":target.to_string(),"changes":changes}
        }))
    })
    .await;
    let _ = tokio::time::timeout(Duration::from_secs(2), client.disconnect()).await;
    result?
}

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::args().len() != 1 {
        return Err("Read-only stdin request required".into());
    }
    let mut raw = Vec::new();
    io::stdin().take(1025).read_to_end(&mut raw)?;
    let value = read(parse(&raw)?).await?;
    let output = serde_json::to_vec(&value)?;
    if output.len() > 32_000_000 {
        return Err("History output limit exceeded".into());
    }
    println!("{}", std::str::from_utf8(&output)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closed_canonical_bounded_request() {
        let raw = format!("{{\"cursor\":\"{}\",\"window\":256}}", "ab".repeat(32));
        assert_eq!(parse(raw.as_bytes()).unwrap().window, 256);
        for bad in [
            format!(" {raw}"),
            raw.replace("256", "true"),
            raw.replace("256", "255"),
            raw.replace("256", "256.0"),
            raw.replace("ab", "AB"),
            raw.replace("\"window\":", "\"window\":16,\"window\":"),
            raw.replace("256}", "256,\"secret_key\":\"PRIVATE_SENTINEL\"}"),
        ] {
            assert!(parse(bad.as_bytes()).is_err());
        }
        assert!(parse(&vec![b'x'; 1025]).is_err());
    }
    #[test]
    fn blue_score_hint_saturates_and_never_claims_target() {
        assert_eq!(confirmations(10000, 100, 256), 9644);
        assert_eq!(confirmations(100, 90, 256), 0);
        assert_eq!(confirmations(90, 100, 16), 0);
        assert_eq!(confirmations(u64::MAX, 0, 16), u64::MAX - 16);
    }
}
