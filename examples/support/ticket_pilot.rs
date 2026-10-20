//! Shared unsigned P0 semantics. No key loading, signing, RPC or submission.
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::tx::{
    Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_rpc_core::RpcTransaction;
use kaspa_txscript::standard::pay_to_address_script;
use secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use silverscript_abi::{decode_hex, encode_hex};

pub(crate) type Result<T> = std::result::Result<T, String>;
pub(crate) const FEE: u64 = 2_000_000;
pub(crate) const TICKET: u64 = 12_000_000;
pub(crate) const COLD_FIXTURE_KEY: &str =
    "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13";
pub(crate) const LAB_KEYS: [&str; 3] = [
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
];

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Source {
    pub(crate) transaction_id: String,
    pub(crate) index: u32,
    pub(crate) amount: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Plan {
    pub(crate) namespace: String,
    pub(crate) network: String,
    pub(crate) purpose: String,
    pub(crate) run_nonce: String,
    pub(crate) evidence_digest: String,
    pub(crate) funding_key: String,
    pub(crate) ticket_key: String,
    pub(crate) return_key: String,
    pub(crate) source: Source,
}
pub(crate) fn canonical<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    icp_testnet::native_ticket_lab::canonical(v)
}
pub(crate) fn hex32(s: &str) -> Result<()> {
    let b = decode_hex(s).map_err(|e| e.to_string())?;
    if b.len() != 32 || encode_hex(&b) != s {
        return Err("Expected lowercase 32-byte hex".into());
    }
    Ok(())
}
pub(crate) fn digest(domain: &[u8], raw: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(raw);
    encode_hex(&h.finalize())
}
pub(crate) fn address(key: &str) -> Result<Address> {
    hex32(key)?;
    let key: XOnlyPublicKey = key
        .parse()
        .map_err(|e| format!("Invalid native key: {e}"))?;
    Ok(Address::new(
        Prefix::Testnet,
        Version::PubKey,
        &key.serialize(),
    ))
}
impl Plan {
    pub(crate) fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() > 16384 || !raw.is_ascii() {
            return Err("Bounded ASCII plan required".into());
        }
        let p: Self = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
        if canonical(&p)? != raw {
            return Err("Canonical closed plan required".into());
        }
        p.validate()?;
        Ok(p)
    }
    fn validate(&self) -> Result<()> {
        if self.namespace != "icp-ticket-pilot-review-p0"
            || self.network != "testnet-10"
            || !(24_000_000..=100_000_000).contains(&self.source.amount)
        {
            return Err("Wrong pilot profile, network or amount".into());
        }
        for s in [
            &self.run_nonce,
            &self.evidence_digest,
            &self.source.transaction_id,
        ] {
            hex32(s)?;
        }
        if self.run_nonce == "00".repeat(32) {
            return Err("Nonzero run nonce required".into());
        }
        let keys = [
            self.funding_key.as_str(),
            self.ticket_key.as_str(),
            self.return_key.as_str(),
        ];
        for k in keys {
            address(k)?;
        }
        if keys[0] == keys[1] || keys[0] == keys[2] || keys[1] == keys[2] {
            return Err("Distinct native roles required".into());
        }
        match self.purpose.as_str() {
            "public-fixture-never-fund"
                if keys == LAB_KEYS
                    && self.source.transaction_id == "11".repeat(32)
                    && self.source.index == 0
                    && self.run_nonce == "44".repeat(32) =>
            {
                ()
            }
            "operator-unsigned-review"
                if keys
                    .iter()
                    .all(|k| !LAB_KEYS.contains(k) && *k != COLD_FIXTURE_KEY)
                    && self.source.transaction_id != "00".repeat(32)
                    && self.source.transaction_id != "11".repeat(32)
                    && self.run_nonce != "44".repeat(32) =>
            {
                ()
            }
            _ => {
                return Err(
                    "Invalid purpose, known native lab key/source or fixture relabeling".into(),
                );
            }
        }
        Ok(())
    }
}
pub(crate) fn unsigned(
    point: TransactionOutpoint,
    amount: u64,
    key: &str,
    outputs: Vec<TransactionOutput>,
    payload: Vec<u8>,
) -> Result<Transaction> {
    let tx = Transaction::new(
        1,
        vec![TransactionInput::new_with_compute_budget(
            point,
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
    let entry = UtxoEntry::new(
        amount,
        pay_to_address_script(&address(key)?),
        0,
        false,
        None,
    );
    icp_testnet::commit_storage_mass(&tx, &[entry]).map_err(str::to_string)?;
    Ok(tx)
}
pub(crate) fn payload(action: &str, commitment: &str) -> Result<Vec<u8>> {
    let mut p = format!("ICP-RT-{}-TN10-P0\0", action.to_uppercase()).into_bytes();
    p.extend(decode_hex(commitment).map_err(|e| e.to_string())?);
    Ok(p)
}
pub(crate) fn review(p: &Plan) -> Result<Value> {
    p.validate()?;
    let id = digest(b"icp/ticket-pilot-review/p0\0", &canonical(p)?);
    let issue = unsigned(
        TransactionOutpoint {
            transaction_id: p
                .source
                .transaction_id
                .parse()
                .map_err(|e| format!("{e}"))?,
            index: p.source.index,
        },
        p.source.amount,
        &p.funding_key,
        vec![
            TransactionOutput::new(TICKET, pay_to_address_script(&address(&p.ticket_key)?)),
            TransactionOutput::new(
                p.source.amount - TICKET - FEE,
                pay_to_address_script(&address(&p.funding_key)?),
            ),
        ],
        payload("issue", &id)?,
    )?;
    let mut txs = vec![("issue", issue.clone())];
    for action in ["consume", "refund"] {
        let body = json!({"review_id":id,"issue_id":issue.id().to_string(),"index":0});
        let terminal = digest(
            format!("icp/ticket-pilot-review/p0/{action}\0").as_bytes(),
            &canonical(&body)?,
        );
        txs.push((
            action,
            unsigned(
                TransactionOutpoint {
                    transaction_id: issue.id(),
                    index: 0,
                },
                TICKET,
                &p.ticket_key,
                vec![TransactionOutput::new(
                    TICKET - FEE,
                    pay_to_address_script(&address(&p.return_key)?),
                )],
                payload(action, &terminal)?,
            )?,
        ));
    }
    Ok(
        json!({"mode":"UNSIGNED_P0_REVIEW_NOT_FUNDING_AUTHORIZATION","review_id":id,"purpose":p.purpose,
        "network":"testnet-10","source_observed":false,"vm_verified":false,"signatures_created":0,"rpc_calls":0,"broadcasts":0,
        "maximum_lifecycle_fee":2*FEE,
        "roles":{"funding":address(&p.funding_key)?.to_string(),"ticket":address(&p.ticket_key)?.to_string(),"return":address(&p.return_key)?.to_string()},
        "transactions":txs.iter().map(|(action,tx)|json!({"action":action,"transaction_id":tx.id().to_string(),
            "fee":FEE,"unsigned_rpc":RpcTransaction::from(tx)})).collect::<Vec<_>>()}),
    )
}
