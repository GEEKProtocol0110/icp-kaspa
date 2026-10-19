//! No arguments, external keys, RPC or saved signed transactions.
use icp_testnet::native_ticket_lab::{
    Action, MODE, fixture_issue, fixture_terminal, prepare, summary,
};

fn main() -> Result<(), String> {
    if std::env::args().len() != 1 {
        return Err("This example accepts no arguments or live material".into());
    }
    let issue = fixture_issue(24_000_000);
    let mut examples = Vec::new();
    for plan in [
        issue.clone(),
        fixture_terminal(&issue, Action::Consume)?,
        fixture_terminal(&issue, Action::Refund)?,
    ] {
        let tx = prepare(&plan, &plan.entry())?;
        examples.push(summary(&plan, &tx)?);
    }
    println!("{}", serde_json::to_string_pretty(&serde_json::json!({"mode":MODE,
        "note":"Consume and refund are alternative fabricated branches, not two allowed live spends.","examples":examples})).map_err(|e|e.to_string())?);
    Ok(())
}
