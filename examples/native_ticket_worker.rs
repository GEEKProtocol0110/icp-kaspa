//! Bounded private stdin/stdout fixture channel; no files, RPC or external keys.
use icp_testnet::native_ticket_lab::{
    Action, Plan, canonical, fixture_terminal, prepare_record, verify_record,
};
use std::io::{self, Read};

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        return Err("Expected validate, prepare or verify".into());
    }
    let mut raw = Vec::new();
    io::stdin()
        .take(65_537)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    if raw.len() > 65_536 {
        return Err("Oversized private fixture request".into());
    }
    let reply = match args[1].as_str() {
        "validate" => {
            String::from_utf8(canonical(&Plan::from_json(&raw)?)?).map_err(|e| e.to_string())?
        }
        "prepare" => prepare_record(&raw)?,
        "consume-plan" | "refund-plan" => {
            let action = if args[1] == "consume-plan" {
                Action::Consume
            } else {
                Action::Refund
            };
            String::from_utf8(canonical(&fixture_terminal(
                &Plan::from_json(&raw)?,
                action,
            )?)?)
            .map_err(|e| e.to_string())?
        }
        "verify" => serde_json::to_string(&verify_record(&raw)?).map_err(|e| e.to_string())?,
        _ => return Err("Unknown fixture operation".into()),
    };
    print!("{reply}");
    Ok(())
}
