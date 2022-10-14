use std::collections::HashSet;

use bitcoin::hashes::hex::FromHex;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Network, Script};

/// This example uses test values from the BIP specification.
/// https://github.com/bitcoin/bips/blob/master/bip-0351.mediawiki#appendix-a-test-vectors
fn main() -> Result<(), bip351::Error> {
    let secp = Secp256k1::new();

    let mut accepted_addresses = HashSet::new();
    accepted_addresses.insert(bip351::AddressType::P2wpkh);

    let recipient =
        bip351::Recipient::from_seed(&secp, &[0xFF], Network::Bitcoin, 0, accepted_addresses)?;

    // Recipient finds a valid notification addressed to them.
    let notification_script = Script::from_hex(
        "6a28505049cb55bb02e3217349724307eed5514b53b1f53f0802672a9913d9bbb76afecc86be23f46401",
    )
    .unwrap();

    let recipient_commitment = recipient
        .detect_notification(&secp, &notification_script)
        .unwrap();

    // Recipient starts deriving addresses for a particular commitment starting with index `0` (first address).
    let (address_0, _pubkey, _privkey) = recipient.key_info(&secp, &recipient_commitment, 0)?;
    assert_eq!(
        address_0.to_string(),
        "bc1qw7ld5h9tj2ruwxqvetznjfq9g5jyp0gjhrs30w"
    );

    Ok(())
}
