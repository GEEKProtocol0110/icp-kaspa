#![cfg(feature = "live")]
use std::{fs, process::Command};

#[test]
fn setup_addresses_and_descriptor_are_public_only_and_versioned() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let dir = std::env::temp_dir().join(format!("icp-public-cli-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_icp-protected"))
            .current_dir(root)
            .env("ICP_PROTECTED_STATE_DIR", &dir)
            .env("ICP_SIGNER_KEY_FILE", dir.join("nonexistent-secret.json"))
            .args(args)
            .output()
            .unwrap()
    };
    let setup = run(&["setup", "artifacts/protected/policy.json"]);
    assert!(
        setup.status.success(),
        "{}",
        String::from_utf8_lossy(&setup.stderr)
    );
    let public: serde_json::Value = serde_json::from_slice(&setup.stdout).unwrap();
    assert_eq!(public["version"], "protected-v1");
    assert_ne!(public["quarantined_vault"], public["cold_address"]);
    for cmd in ["addresses", "descriptor"] {
        let result = run(&[cmd]);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let d: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(d["network"], "testnet-10");
        if cmd == "descriptor" {
            assert_ne!(d["recovery_spk"], d["cold_spk"]);
            assert_ne!(d["recovery_spk"], d["pending_spk"]);
        }
    }
    assert!(
        !run(&["setup", "artifacts/protected/policy.json"])
            .status
            .success()
    );
    assert!(!run(&["release"]).status.success());
    fs::remove_dir_all(&dir).unwrap();
}
