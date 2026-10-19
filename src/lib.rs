//! ICP testnet prototype. See docs/VAULT-SPEC.md for the limited threat model.
pub mod protected;
use kaspa_consensus_core::{
    config::params::TESTNET_PARAMS,
    mass::MassCalculator,
    tx::{PopulatedTransaction, Transaction, UtxoEntry},
};

pub fn commit_storage_mass(tx: &Transaction, entries: &[UtxoEntry]) -> Result<(), &'static str> {
    if tx.inputs.is_empty()
        || tx.inputs.len() != entries.len()
        || tx.outputs.iter().any(|o| o.value == 0)
    {
        return Err("invalid transaction shape for mass calculation");
    }
    let p = PopulatedTransaction::new(tx, entries.to_vec());
    let m = MassCalculator::new_with_consensus_params(&TESTNET_PARAMS)
        .calc_contextual_masses(&p)
        .ok_or("storage mass overflow")?;
    tx.set_storage_mass(m.storage_mass);
    Ok(())
}

/// Testnet addresses do not distinguish TN10 and TN12; check the NODE network ID.
pub fn check_network(
    network: &str,
    synced: bool,
    indexed: bool,
    daa: u64,
) -> Result<(), &'static str> {
    if network != "testnet-10" {
        return Err("ICP runner only supports testnet-10");
    }
    if !synced || !indexed {
        return Err("Node must be synced with UTXO indexing");
    }
    if daa < 467_579_632 {
        return Err("Node has not reached the pinned Toccata activation");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_tn10_accepted() {
        for n in ["mainnet", "testnet-12", "testnet", "devnet", "simnet", ""] {
            assert!(check_network(n, true, true, u64::MAX).is_err());
        }
    }
    #[test]
    fn activation_boundary() {
        assert!(check_network("testnet-10", true, true, 467_579_631).is_err());
        assert!(check_network("testnet-10", true, true, 467_579_632).is_ok());
    }
    #[test]
    fn unhealthy_node_rejected() {
        assert!(check_network("testnet-10", false, true, u64::MAX).is_err());
        assert!(check_network("testnet-10", true, false, u64::MAX).is_err());
    }
}
