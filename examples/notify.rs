// This example is a simple interactive tool that accepts a payment code, a seed and generates a
// BIP351 notification payload that can then be embedded in an OP_RETURN.

use std::str::FromStr;

use bip351::*;
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::Network;

fn main() -> std::io::Result<()> {
    let secp = bitcoin::secp256k1::Secp256k1::new();

    let payment_code = prompt("Enter the recipient's payment code").unwrap();
    let payment_code = PaymentCode::from_str(&payment_code).expect("Invalid payment code");

    let sender_seed = prompt("Enter the sender's hex-encoded BIP39 seed").unwrap();
    let sender_seed: Vec<u8> = FromHex::from_hex(&sender_seed).expect("Not a hex-encoded seed");

    let network = prompt("Enter 0 for mainnet or 1 for testnet").unwrap();
    let network = match network.as_str() {
        "0" => Network::Bitcoin,
        "1" => Network::Testnet,
        _ => panic!("unknown network"),
    };

    let recipient_index = prompt("Enter a numerical recipient index").unwrap();
    let recipient_index: u32 = recipient_index
        .parse()
        .expect("Not a valid unsigned integer");

    let sender = Sender::from_seed(&secp, &sender_seed, network, 0).unwrap();

    println!("The recipient supports the following address types:");
    let accepted_addresses: Vec<_> = payment_code.address_types().iter().collect();
    for (index, addr_type) in accepted_addresses.iter().enumerate() {
        println!("({}): {:?}", index, addr_type);
    }

    let ordinal = prompt("Pick the number next to the address type you want to use").unwrap();
    let addr_type = accepted_addresses
        .into_iter()
        .nth(ordinal.parse().expect("Not a valid integer"))
        .expect("Index out of range")
        .clone();

    let (txout, _) = sender
        .notify(&secp, &payment_code, recipient_index, addr_type)
        .unwrap();
    let payload = txout.script_pubkey.as_bytes()[2..].to_hex();
    println!("The notification OP_RETURN payload is:\n{}", payload);

    Ok(())
}

/// Prints a message and asks the user to input a line.
fn prompt(prompt: &str) -> std::io::Result<String> {
    println!("{}:", prompt);
    let mut value = String::new();
    std::io::stdin().read_line(&mut value)?;
    assert_eq!(Some('\n'), value.pop());
    Ok(value)
}
