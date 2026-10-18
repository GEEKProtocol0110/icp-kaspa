use icp_testnet::protected::{Entry, Policy, Role, Stage, generate_role_key, load_signer};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "icp-roles-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn policy() -> Policy {
    serde_json::from_str(include_str!("../artifacts/protected/policy.json")).unwrap()
}

#[test]
fn recovery_role_works_with_no_other_secret_files() {
    let tmp = Temp::new();
    let path = tmp.0.join("recovery.json");
    let public = generate_role_key(Role::Recovery, &path).unwrap();
    let mut p = policy();
    p.recovery = public["public_key"].as_str().unwrap().into();
    assert!(load_signer(&path, Role::Recovery, &p).is_ok());
    assert_eq!(fs::read_dir(&tmp.0).unwrap().count(), 1);
    assert!(public.get("secret").is_none());
}
#[test]
fn owner_and_cold_roles_cannot_be_substituted_for_recovery() {
    let tmp = Temp::new();
    for role in [Role::Owner, Role::Cold] {
        let path = tmp.0.join(format!("{role:?}.json"));
        let public = generate_role_key(role, &path).unwrap();
        let mut p = policy();
        if role == Role::Owner {
            p.owner = public["public_key"].as_str().unwrap().into()
        } else {
            p.cold = public["public_key"].as_str().unwrap().into()
        }
        assert!(
            load_signer(&path, Role::Recovery, &p)
                .unwrap_err()
                .contains("role mismatch")
        );
    }
}
#[test]
fn wrong_public_key_fails_before_signing() {
    let tmp = Temp::new();
    let path = tmp.0.join("cold.json");
    generate_role_key(Role::Cold, &path).unwrap();
    assert!(
        load_signer(&path, Role::Cold, &policy())
            .unwrap_err()
            .contains("pinned public policy")
    );
}
#[test]
fn wrong_network_and_combined_files_rejected() {
    let tmp = Temp::new();
    let path = tmp.0.join("key.json");
    generate_role_key(Role::Recovery, &path).unwrap();
    let mut data: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    data["network"] = serde_json::json!("mainnet");
    fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();
    assert!(
        load_signer(&path, Role::Recovery, &policy())
            .unwrap_err()
            .contains("network or role")
    );
    data["network"] = serde_json::json!("testnet-10");
    data["owner"] = serde_json::json!("combined-secret");
    fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();
    assert_eq!(
        load_signer(&path, Role::Recovery, &policy()).unwrap_err(),
        "Invalid signer file"
    );
}
#[test]
fn existing_signer_is_never_overwritten() {
    let tmp = Temp::new();
    let path = tmp.0.join("key.json");
    generate_role_key(Role::Cold, &path).unwrap();
    let first = fs::read(&path).unwrap();
    assert!(generate_role_key(Role::Cold, &path).is_err());
    assert_eq!(fs::read(path).unwrap(), first);
}
#[cfg(unix)]
#[test]
fn permissive_and_symlink_key_files_rejected() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let tmp = Temp::new();
    let path = tmp.0.join("key.json");
    generate_role_key(Role::Recovery, &path).unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(load_signer(&path, Role::Recovery, &policy()).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let link = tmp.0.join("link.json");
    symlink(&path, &link).unwrap();
    assert!(
        load_signer(&link, Role::Recovery, &policy())
            .unwrap_err()
            .contains("non-symlink")
    );
}
#[test]
fn policy_rejects_aliases_wrong_network_invalid_keys_and_limits() {
    let p = policy();
    p.validate().unwrap();
    let mut x = p.clone();
    x.cold = x.owner.clone();
    assert!(x.validate().is_err());
    x = p.clone();
    x.recovery = x.owner.to_uppercase();
    assert!(x.validate().is_err());
    x = p.clone();
    x.network = "testnet-12".into();
    assert!(x.validate().is_err());
    x = p.clone();
    x.owner = "00".repeat(32);
    assert!(x.validate().is_err());
    x = p.clone();
    x.delay_daa = 0;
    assert!(x.validate().is_err());
    x = p.clone();
    x.cold_delay_daa = x.delay_daa;
    assert!(x.validate().is_err());
    x = p.clone();
    x.cold_delay_daa = u64::MAX;
    assert!(x.validate().is_err());
    x = p.clone();
    x.max_fee = 2_000_001;
    assert!(x.validate().is_err());
}
#[test]
fn quarantine_has_only_cold_release_and_no_hot_clock_reset() {
    for e in [Entry::Initiate, Entry::Execute, Entry::Recover] {
        assert!(e.target(Stage::Quarantined).is_err());
    }
    assert_eq!(Entry::Release.role(), Role::Cold);
    assert_eq!(Entry::Release.target(Stage::Quarantined), Ok(None));
    assert!(policy().sequence(Entry::Release) > policy().sequence(Entry::Execute));
}
