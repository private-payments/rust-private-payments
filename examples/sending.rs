use std::str::FromStr;

use bitcoin::hashes::hex::ToHex;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Network;

/// This example uses test values from the BIP specification.
/// https://github.com/bitcoin/bips/blob/master/bip-0351.mediawiki#appendix-a-test-vectors
fn main() -> Result<(), bip351::Error> {
    let secp = Secp256k1::new();

    let sender = bip351::Sender::from_seed(&secp, &[0xFE], Network::Bitcoin, 0)?;

    let recipient = bip351::PaymentCode::from_str(
        "pay1qqpsxq4730l4yre4lt3588eyt3f2lwggtfalvtgfns04a8smzkn7yys6xv2gs8",
    )?;

    // Sender makes sure the recipient supports segwit addresses.
    let p2wpkh_addr_type = recipient
        .address_types()
        .get(&bip351::AddressType::P2wpkh)
        .unwrap();

    let (notification_txout, sender_recipient_commitment) =
        sender.notify(&secp, &recipient, 0, p2wpkh_addr_type.clone())?;

    // Here the sender would add `notification_txout` to a transaction and broadcast it.
    // wallet.broadcast(tx)...

    let payload = notification_txout.script_pubkey.as_bytes();
    assert_eq!(
        payload[2..].to_hex(),
        "505049cb55bb02e3217349724307eed5514b53b1f53f0802672a9913d9bbb76afecc86be23f46401"
    );

    // At this point the recipient is notified. Sender can now send funds to their secret address at index `0`.
    let recipient_addr_0 = sender.address(&secp, &sender_recipient_commitment, 0)?;
    assert_eq!(
        recipient_addr_0.to_string(),
        "bc1qw7ld5h9tj2ruwxqvetznjfq9g5jyp0gjhrs30w"
    );

    // wallet.send(&recipient_addr_0, 100000);

    Ok(())
}
