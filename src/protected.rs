//! Separate candidate-v1 policy, role-key boundary and native transaction builder.
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
use kaspa_txscript::{
    pay_to_script_hash_script, script_builder::ScriptBuilder, standard::pay_to_address_script,
};
use secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use silverscript_abi::{
    ArtifactValue, SilAbiArtifact, decode_hex, encode_contract_entry_sig_script, encode_hex,
};
use std::{fs, io::Write, path::Path};

pub type Result<T> = std::result::Result<T, String>;
pub const CONTRACT: &str = "IcpProtected";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Owner,
    Recovery,
    Recipient,
    Cold,
}

impl Role {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "owner" => Ok(Self::Owner),
            "recovery" => Ok(Self::Recovery),
            "recipient" => Ok(Self::Recipient),
            "cold" => Ok(Self::Cold),
            _ => Err("Unknown signer role".into()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Idle,
    Pending,
    Quarantined,
}
impl Stage {
    pub fn name(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Pending => "pending",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entry {
    Initiate,
    Execute,
    Recover,
    Release,
}
impl Entry {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "initiate" => Ok(Self::Initiate),
            "execute" => Ok(Self::Execute),
            "recover" => Ok(Self::Recover),
            "release" => Ok(Self::Release),
            _ => Err("Unknown entrypoint".into()),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Initiate => "initiate",
            Self::Execute => "execute",
            Self::Recover => "recover",
            Self::Release => "release",
        }
    }
    pub fn role(self) -> Role {
        match self {
            Self::Initiate | Self::Execute => Role::Owner,
            Self::Recover => Role::Recovery,
            Self::Release => Role::Cold,
        }
    }
    pub fn target(self, stage: Stage) -> Result<Option<Stage>> {
        match (self, stage) {
            (Self::Initiate, Stage::Idle) => Ok(Some(Stage::Pending)),
            (Self::Execute, Stage::Pending) | (Self::Release, Stage::Quarantined) => Ok(None),
            (Self::Recover, Stage::Idle | Stage::Pending) => Ok(Some(Stage::Quarantined)),
            _ => Err("Entrypoint is unavailable in this vault state".into()),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: String,
    pub network: String,
    pub owner: String,
    pub recovery: String,
    pub recipient: String,
    pub cold: String,
    pub delay_daa: u64,
    pub cold_delay_daa: u64,
    pub max_fee: u64,
}
impl Policy {
    pub fn validate(&self) -> Result<()> {
        if self.version != "protected-v1" || self.network != "testnet-10" {
            return Err("Expected protected-v1 on testnet-10".into());
        }
        if self.delay_daa == 0
            || self.cold_delay_daa <= self.delay_daa
            || self.cold_delay_daa > u32::MAX as u64
            || self.max_fee == 0
            || self.max_fee > 2_000_000
        {
            return Err("Invalid delay or testnet fee cap (maximum 2000000 sompi)".into());
        }
        let keys =
            [Role::Owner, Role::Recovery, Role::Recipient, Role::Cold].map(|r| self.public_key(r));
        let mut unique = std::collections::HashSet::new();
        for key in keys {
            if !unique.insert(key?) {
                return Err("All four public keys must differ".into());
            }
        }
        Ok(())
    }
    pub fn public_key(&self, role: Role) -> Result<Vec<u8>> {
        let s = match role {
            Role::Owner => &self.owner,
            Role::Recovery => &self.recovery,
            Role::Recipient => &self.recipient,
            Role::Cold => &self.cold,
        };
        let b = decode_hex(s).map_err(|_| "Invalid public key")?;
        XOnlyPublicKey::from_slice(&b).map_err(|_| "Invalid public key")?;
        Ok(b)
    }
    pub fn address(&self, role: Role) -> Result<Address> {
        Ok(Address::new(
            Prefix::Testnet,
            Version::PubKey,
            &self.public_key(role)?,
        ))
    }
    pub fn sequence(&self, entry: Entry) -> u64 {
        match entry {
            Entry::Execute => self.delay_daa,
            Entry::Release => self.cold_delay_daa,
            _ => 0,
        }
    }
}

// Intentionally not Debug: never format or log secret-bearing objects.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleKey {
    network: String,
    role: Role,
    secret: String,
}

pub fn generate_role_key(role: Role, path: &Path) -> Result<serde_json::Value> {
    let (secret, _) = Secp256k1::new().generate_keypair(&mut secp256k1::rand::thread_rng());
    let pair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(parent)
        .map_err(|_| "Cannot create signer directory")?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "Cannot create signer file; existing files are never overwritten")?;
    let key = RoleKey {
        network: "testnet-10".into(),
        role,
        secret: encode_hex(&secret.secret_bytes()),
    };
    file.write_all(&serde_json::to_vec_pretty(&key).map_err(|_| "Cannot serialize signer")?)
        .map_err(|_| "Cannot save signer")?;
    file.sync_all().map_err(|_| "Cannot persist signer")?;
    Ok(
        serde_json::json!({"network":"testnet-10","role":role,"public_key":encode_hex(&pair.x_only_public_key().0.serialize())}),
    )
}

pub fn load_signer(path: &Path, expected: Role, policy: &Policy) -> Result<Keypair> {
    policy.validate()?;
    let meta = fs::symlink_metadata(path).map_err(|_| "Signer file unavailable")?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err("Signer must be a regular non-symlink file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err("Signer file must not be accessible to group or others".into());
        }
    }
    let key: RoleKey =
        serde_json::from_slice(&fs::read(path).map_err(|_| "Signer file unavailable")?)
            .map_err(|_| "Invalid signer file")?;
    if key.network != "testnet-10" || key.role != expected {
        return Err("Signer network or role mismatch".into());
    }
    let bytes = decode_hex(&key.secret).map_err(|_| "Invalid signer secret")?;
    let secret = SecretKey::from_slice(&bytes).map_err(|_| "Invalid signer secret")?;
    let pair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
    if pair.x_only_public_key().0.serialize().as_slice() != policy.public_key(expected)? {
        return Err("Signer does not match pinned public policy".into());
    }
    Ok(pair)
}

pub fn bytecode(artifact: &SilAbiArtifact) -> Result<Vec<u8>> {
    artifact
        .check_consistency()
        .map_err(|_| "Inconsistent compiled artifact")?;
    Ok(artifact
        .contract(CONTRACT)
        .ok_or("Expected IcpProtected artifact")?
        .compiled
        .bytecode
        .clone())
}

/// Sign exactly one transition with one role. The caller supplies trusted compiled
/// public artifacts; the actual input script and native VM are checked before use.
#[allow(clippy::too_many_arguments)]
pub fn build_transition(
    policy: &Policy,
    source: &SilAbiArtifact,
    target: Option<&SilAbiArtifact>,
    stage: Stage,
    entry: Entry,
    outpoint: TransactionOutpoint,
    utxo: UtxoEntry,
    signer: &Keypair,
) -> Result<Transaction> {
    policy.validate()?;
    let expected = entry.target(stage)?;
    if signer.x_only_public_key().0.serialize().as_slice() != policy.public_key(entry.role())? {
        return Err("Wrong authority for entrypoint".into());
    }
    let code = bytecode(source)?;
    if utxo.covenant_id.is_some() || utxo.script_public_key != pay_to_script_hash_script(&code) {
        return Err("Exact UTXO does not match the pinned source script".into());
    }
    let destination = match (expected, target) {
        (Some(_), Some(a)) => pay_to_script_hash_script(&bytecode(a)?),
        (None, None) => pay_to_address_script(&policy.address(if entry == Entry::Release {
            Role::Cold
        } else {
            Role::Recipient
        })?),
        _ => return Err("Incorrect transition destination type".into()),
    };
    let value = utxo
        .amount
        .checked_sub(policy.max_fee)
        .filter(|v| *v > 0)
        .ok_or("Insufficient vault value for capped fee")?;
    let mut tx = Transaction::new(
        1,
        vec![TransactionInput::new_with_compute_budget(
            outpoint,
            vec![],
            policy.sequence(entry),
            100,
        )],
        vec![TransactionOutput::new(value, destination)],
        0,
        Default::default(),
        0,
        vec![],
    );
    crate::commit_storage_mass(&tx, std::slice::from_ref(&utxo)).map_err(str::to_string)?;
    let p = MutableTransaction::with_entries(tx.clone(), vec![utxo]);
    let hash = calc_schnorr_signature_hash(
        &p.as_verifiable(),
        0,
        SIG_HASH_ALL,
        &SigHashReusedValuesUnsync::new(),
    );
    let mut sig = signer
        .sign_schnorr(Message::from_digest_slice(&hash.as_bytes()).unwrap())
        .as_ref()
        .to_vec();
    sig.push(SIG_HASH_ALL.to_u8());
    let args = encode_contract_entry_sig_script(
        source,
        CONTRACT,
        entry.name(),
        &[ArtifactValue::Bytes(sig)],
    )
    .map_err(|_| "Cannot encode signed transition")?;
    let mut b = ScriptBuilder::with_flags(kaspa_txscript::EngineFlags {
        covenants_enabled: true,
        ..Default::default()
    });
    b.add_data(&code)
        .map_err(|_| "Cannot encode source script")?;
    tx.inputs[0].signature_script = [args, b.drain()].concat();
    tx.finalize();
    Ok(tx)
}
