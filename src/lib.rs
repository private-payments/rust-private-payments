use std::collections::HashSet;

use bech32::{FromBase32, ToBase32};
use bitcoin::secp256k1::{self, Secp256k1};
use bitcoin::util::bip32;
use bitcoin::{bech32, Address, Network, PrivateKey, PublicKey, Script, TxOut};

pub use bitcoin;

const PURPOSE: bip32::ChildNumber = bip32::ChildNumber::Hardened { index: 351 };

const NOTIFICATION_PREFIX: &[u8] = b"PP";

/// Address types supported by the standard.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[repr(u8)]
pub enum AddressType {
    P2pkh = 0,
    P2wpkh,
    P2tr,
}

impl AddressType {
    /// Bit flag value of this address type.
    pub fn flag(&self) -> u16 {
        1 << (self.clone() as u8)
    }

    /// All valid address types.
    pub fn values() -> &'static [Self; 3] {
        &[AddressType::P2pkh, AddressType::P2wpkh, AddressType::P2tr]
    }

    /// Construct an address from address type and pubkey.
    pub fn to_address<C: secp256k1::Verification>(
        &self,
        secp: &Secp256k1<C>,
        pubkey: &PublicKey,
        network: Network,
    ) -> Address {
        match self {
            AddressType::P2pkh => Address::p2pkh(&pubkey, network),
            AddressType::P2wpkh => Address::p2wpkh(&pubkey, network).unwrap(), // always compressed => no panic
            AddressType::P2tr => Address::p2tr(secp, pubkey.inner.into(), None, network),
        }
    }
}

/// A struct that a sender of funds uses in combination with a recipient's `PaymentCode` in order
/// to send notifications and calculate payment addresses. This is invariant with regard to
/// recipient and needs to be constructed only once per account (unique per BIP32 seed + account).
#[derive(Debug, Clone)]
pub struct Sender(bip32::ExtendedPrivKey);

impl Sender {
    /// Construct a sender side from a BIP32 seed.
    pub fn from_seed<C: secp256k1::Signing>(
        secp: &Secp256k1<C>,
        seed: &[u8],
        network: Network,
        account: u32,
    ) -> Result<Self, Error> {
        let master = bip32::ExtendedPrivKey::new_master(network, seed)?;
        let path: bip32::DerivationPath = vec![
            PURPOSE,
            bip32::ChildNumber::Hardened { index: 0 },
            bip32::ChildNumber::Hardened { index: account },
        ]
        .into();
        let n = master.derive_priv(secp, &path)?;

        Ok(Self(n))
    }

    /// Construct a notification for a payment code. The txout is an `OP_RETURN` consuming 0 sats.
    /// The returned `SenderCommitment` is used for subsequent interaction with the payment code.
    ///
    /// `recipient_index` must be unique for each recipient as it uniquely defines the relationship
    /// between a sender and a recipient.
    #[allow(non_snake_case)]
    pub fn notify(
        &self,
        secp: &Secp256k1<secp256k1::All>,
        payment_code: &PaymentCode,
        recipient_index: u32,
        address_type: AddressType,
    ) -> Result<(TxOut, SenderCommitment), Error> {
        let n_x = self
            .0
            .ckd_priv(
                secp,
                bip32::ChildNumber::Normal {
                    index: recipient_index,
                },
            )?
            .to_priv();
        let N_x = n_x.public_key(secp);

        let secret_point = secret_point(secp, &n_x, &payment_code.pubkey)?;
        let notification_code = notification_code(&secret_point);
        let address_type_byte = match payment_code.address_types.contains(&address_type) {
            true => Ok(address_type as u8),
            false => Err(Error::UnsupportedAddressType(address_type)),
        }?;

        let payload = [
            NOTIFICATION_PREFIX,
            &notification_code[0..4],
            &N_x.to_bytes(),
            &[address_type_byte],
        ]
        .concat();

        let txout = TxOut {
            script_pubkey: Script::new_op_return(&payload),
            value: 0,
        };

        let commitment = SenderCommitment {
            sender_key: n_x,
            recipient_key: payment_code.pubkey.clone(),
            address_type,
        };

        Ok((txout, commitment))
    }

    /// Generate an address for a recipient that has already been notified.
    #[allow(non_snake_case)]
    pub fn address(
        &self,
        secp: &Secp256k1<secp256k1::All>,
        commitment: &SenderCommitment,
        addr_index: u64,
    ) -> Result<Address, Error> {
        let secret_point = secret_point(secp, &commitment.sender_key, &commitment.recipient_key)?;
        let shared_secret = shared_secret(&secret_point, addr_index);
        let s = PrivateKey::from_slice(&shared_secret, self.network())?;
        let sG = PublicKey::from_private_key(secp, &s);
        let P_C = PublicKey::new(commitment.recipient_key.inner.combine(&sG.inner)?);
        let address = commitment
            .address_type
            .to_address(secp, &P_C, self.network());
        Ok(address)
    }

    /// Get the network used by this sender.
    pub fn network(&self) -> Network {
        self.0.network
    }
}

/// Represents a post-notification relationship between a sender and a recipient from the sender
/// side. A sender uses this to interact with a payment code after creating a notification.
#[derive(Debug, Clone)]
pub struct SenderCommitment {
    /// The sender private key *n_x* specific to a particular relationship.
    sender_key: PrivateKey,
    /// The recipient public key *P* specific to a payment code.
    recipient_key: PublicKey,
    /// The chosen address type for this commitment.
    address_type: AddressType,
}

/// A struct that a recipient uses to generate a payment code and process notifications. This is
/// invariant with regard to sender and needs to be constructed only once (unique per BIP32 seed).
#[derive(Debug, Clone)]
#[allow(non_snake_case)]
pub struct Recipient {
    /// The private key *p* associated with a recipient (payment code).
    p: PrivateKey,
    /// The public key *P* associated with *p*.
    P: PublicKey,
    /// The network this recipient operates on.
    network: Network,
    /// All address types that the recipient can process.
    address_types: HashSet<AddressType>,
}

impl Recipient {
    /// Create a recipient side from a BIP32 seed.
    pub fn from_seed<C: secp256k1::Signing>(
        secp: &Secp256k1<C>,
        seed: &[u8],
        network: Network,
        account: u32,
        address_types: HashSet<AddressType>,
    ) -> Result<Self, Error> {
        let master = bip32::ExtendedPrivKey::new_master(network, seed)?;
        let path: bip32::DerivationPath = vec![
            PURPOSE,
            bip32::ChildNumber::Hardened { index: 0 },
            bip32::ChildNumber::Hardened { index: account },
        ]
        .into();
        let p = master.derive_priv(secp, &path)?.to_priv();

        Ok(Self {
            p,
            P: PublicKey::from_private_key(secp, &p),
            network,
            address_types,
        })
    }

    /// Processes a scriptpubkey and tries to find a notification in it. If the notification
    /// isn't meant for this recipient, `None` is returned. Otherwise, the sender's public key,
    /// along with the sender's chosen address type, is returned. Note that this has a 1 in ~4.3
    /// billion chance of detecting a spurious notification.
    pub fn detect_notification(
        &self,
        secp: &secp256k1::Secp256k1<secp256k1::All>,
        script: &Script,
    ) -> Option<RecipientCommitment> {
        if !script.is_op_return() || script.as_bytes().get(1) != Some(&40) {
            return None;
        }

        let data = &script.as_bytes().get(2..)?;
        let notification_code = data.get(2..6)?;
        let sender_key = data.get(6..6 + 33)?;
        let address_type = AddressType::values()
            .get(*data.get(39)? as usize)?
            .to_owned();

        let sender_key = PublicKey::from_slice(sender_key).ok()?;
        let secret_point = secret_point(secp, &self.p, &sender_key).ok()?;
        let our_notification_code = sha2(&secret_point);

        our_notification_code
            .starts_with(notification_code)
            .then(|| RecipientCommitment {
                sender_key,
                address_type,
            })
    }

    /// Returns the payment code for this recipient.
    pub fn payment_code(&self) -> PaymentCode {
        PaymentCode {
            pubkey: self.P.clone(),
            network: self.network,
            address_types: self.address_types.clone(),
        }
    }

    /// Returns the private key for a sender-recipient connection at index `c`.
    #[allow(non_snake_case)]
    pub fn key_info(
        &self,
        secp: &secp256k1::Secp256k1<secp256k1::All>,
        commitment: &RecipientCommitment,
        address_index: u64,
    ) -> Result<(Address, PublicKey, PrivateKey), Error> {
        let secret_point = secret_point(secp, &self.p, &commitment.sender_key)?;
        let shared_secret = shared_secret(&secret_point, address_index);
        let s = PrivateKey::from_slice(&shared_secret, self.network)?;
        let p_c = self.p.inner.add_tweak(&s.inner.into())?;
        let p_c = PrivateKey::new(p_c, self.network);
        let P_c = PublicKey::from_private_key(secp, &p_c);
        let A_c = commitment.address_type.to_address(secp, &P_c, self.network);

        Ok((A_c, P_c, p_c))
    }
}

/// Represents a connection between a sender and a recipient from the recipient side. A recipient uses
/// this to generate addresses and their associated private keys for a particular sender.
#[derive(Debug, Clone)]
pub struct RecipientCommitment {
    /// The sender public key *N_x* specific to a particular relationship.
    sender_key: PublicKey,
    /// The chosen address type for this commitment.
    address_type: AddressType,
}

impl RecipientCommitment {
    pub fn address_type(&self) -> &AddressType {
        &self.address_type
    }
}

/// A payment code that a recipient shares with the world in order to receive payments.
#[derive(Debug, PartialEq, Eq)]
pub struct PaymentCode {
    /// The public key *P*.
    pubkey: PublicKey,
    /// The network this recipient operates on.
    network: Network,
    /// All address types that the recipient can process.
    address_types: HashSet<AddressType>,
}

impl PaymentCode {
    /// Returns address types supported by this code.
    pub fn address_types(&self) -> &HashSet<AddressType> {
        &self.address_types
    }
}

impl std::fmt::Display for PaymentCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hrp = network_to_hrp(&self.network);
        let address_types = self
            .address_types
            .iter()
            .fold(0_u16, |acc, addr| acc | addr.flag());
        let mut data = Vec::new();
        data.extend_from_slice(&address_types.to_be_bytes());
        data.extend_from_slice(self.pubkey.to_bytes().as_slice());

        bitcoin::bech32::encode_to_fmt(f, hrp, data.to_base32(), bitcoin::bech32::Variant::Bech32m)
            .unwrap()
    }
}

impl std::str::FromStr for PaymentCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (hrp, data, _) = bitcoin::bech32::decode(s)?;
        let data: Vec<u8> = Vec::from_base32(&data)?;
        let address_types = u16::from_be_bytes(
            data.get(0..2)
                .unwrap_or_default()
                .try_into()
                .map_err(|_| Error::NetworkMismatch)?,
        );

        let pubkey = PublicKey::from_slice(data.get(2..35).unwrap_or_default())?;
        let network = hrp_to_network(&hrp)?;
        let address_types = AddressType::values()
            .iter()
            .filter_map(|a| (address_types & a.flag() != 0).then(|| a.to_owned()))
            .collect();

        Ok(Self {
            pubkey,
            network,
            address_types,
        })
    }
}

/// Perform ECDH between a public key and a private key.
fn secret_point(
    secp: &secp256k1::Secp256k1<secp256k1::All>,
    private_key: &PrivateKey,
    public_key: &PublicKey,
) -> Result<[u8; 33], secp256k1::Error> {
    let tweaked = public_key
        .inner
        .mul_tweak(&secp, &private_key.inner.into())?;
    Ok(tweaked.serialize().try_into().unwrap()) // cannot panic, all keys are compressed
}

/// Calculate a shared secret using a secret point and address index.
fn shared_secret(secret_point: &[u8; 33], c: u64) -> [u8; 32] {
    use bitcoin::hashes::{Hash, HashEngine};
    let mut engine = bitcoin::hashes::sha256::HashEngine::default();
    engine.input(secret_point);
    engine.input(&c.to_be_bytes());
    bitcoin::hashes::sha256::Hash::from_engine(engine).into_inner()
}

/// Calculate 32-byte notification code using a secret point.
fn notification_code(secret_point: &[u8; 33]) -> [u8; 32] {
    sha2(secret_point)
}

/// Compute a SHA256 hash of some bytes.
fn sha2(data: &[u8]) -> [u8; 32] {
    use bitcoin::hashes::Hash;
    bitcoin::hashes::sha256::Hash::hash(data).into_inner()
}

/// Convert the human-readable part of a payment code to a canonical network.
fn hrp_to_network(hrp: &str) -> Result<Network, Error> {
    match hrp {
        "pay" => Ok(Network::Bitcoin),
        "payt" => Ok(Network::Testnet),
        _ => Err(Error::NetworkMismatch),
    }
}

/// Convert a canonical network to a human-readable part of a payment code.
fn network_to_hrp(network: &Network) -> &str {
    match network {
        Network::Bitcoin => "pay",
        _ => "payt",
    }
}

#[derive(Debug)]
pub enum Error {
    /// The address type is not supported by the payment code.
    UnsupportedAddressType(AddressType),
    /// Unrecognized network or network mismatch.
    NetworkMismatch,
    /// Generic BIP32 error
    Bip32(bip32::Error),
    /// Payment code encoding error.
    Encoding(bech32::Error),
    /// Key error.
    InvalidKey(bitcoin::util::key::Error),
    /// Curve operation error.
    Ecc(secp256k1::Error),
}

impl From<bip32::Error> for Error {
    fn from(error: bip32::Error) -> Self {
        Self::Bip32(error)
    }
}

impl From<bech32::Error> for Error {
    fn from(error: bech32::Error) -> Self {
        Self::Encoding(error)
    }
}

impl From<secp256k1::Error> for Error {
    fn from(error: secp256k1::Error) -> Self {
        Self::Ecc(error)
    }
}

impl From<bitcoin::util::key::Error> for Error {
    fn from(error: bitcoin::util::key::Error) -> Self {
        Self::InvalidKey(error)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::hex::ToHex;

    use super::*;

    #[test]
    fn verify_sender() {
        let sender = sender();
        // also known as `n`
        assert_eq!("xprv9zNFGn56Wm1s89ycTCg4hB615ehu6ZvNL4mxUEAL28pNhBAb6SZgLdsgmQd1ECgAiCjy6XxTTRyBdPAhH1oMfLhv2bSwfiCYhL9s9ahEehf", sender.0.to_string());
    }

    #[test]
    fn verify_recipient() {
        let recipient = recipient();
        assert_eq!(
            "26c610e7d0ed4395be3f0664073d66b0a3442b49e1ec13faf2dd9b7d3c335441",
            recipient.p.inner.secret_bytes().to_hex()
        );

        assert_eq!(
            "0302be8bff520f35fae3439f245c52afb9085a7bf62d099c1f5e9e1b15a7e2121a",
            recipient.P.inner.to_hex()
        );

        assert_eq!(
            "pay1qqpsxq4730l4yre4lt3588eyt3f2lwggtfalvtgfns04a8smzkn7yys6xv2gs8",
            recipient.payment_code().to_string()
        );
    }

    #[test]
    fn notifications_and_transacting() {
        let sender = sender();
        let recipient = recipient();
        let payment_code = recipient.payment_code();

        let (notification, sender_commitment) = sender
            .notify(&Secp256k1::new(), &payment_code, 0, AddressType::P2wpkh)
            .unwrap();

        assert_eq!("OP_RETURN OP_PUSHBYTES_40 505049cb55bb02e3217349724307eed5514b53b1f53f0802672a9913d9bbb76afecc86be23f46401", notification.script_pubkey.asm());

        assert_eq!(AddressType::P2wpkh, sender_commitment.address_type);

        assert_eq!(
            "be9518016ec15762877de7d2ce7367a2087cf5682e72bbffa89535d73bb42f40",
            sender_commitment.sender_key.inner.secret_bytes().to_hex()
        );

        assert_eq!(
            "0302be8bff520f35fae3439f245c52afb9085a7bf62d099c1f5e9e1b15a7e2121a",
            sender_commitment.recipient_key.inner.to_hex()
        );

        let addr_0_by_sender = sender
            .address(&Secp256k1::new(), &sender_commitment, 0)
            .unwrap();

        assert_eq!(
            "bc1qw7ld5h9tj2ruwxqvetznjfq9g5jyp0gjhrs30w",
            addr_0_by_sender.to_string()
        );

        let recipient_commitment = recipient
            .detect_notification(&Secp256k1::new(), &notification.script_pubkey)
            .unwrap();

        assert_eq!(
            "02e3217349724307eed5514b53b1f53f0802672a9913d9bbb76afecc86be23f464",
            recipient_commitment.sender_key.inner.to_hex()
        );

        let (r_addr, _r_pubkey, r_privkey) = recipient
            .key_info(&Secp256k1::new(), &recipient_commitment, 0)
            .unwrap();

        assert_eq!(
            "84846fe6b592fd7531af88a58ccc92a88faa1c8bbdbe3de5810d3acebc7d6d33",
            r_privkey.inner.secret_bytes().to_hex()
        );

        assert_eq!(r_addr, addr_0_by_sender);
    }

    #[test]
    fn payment_code_string_ops() {
        let code = recipient().payment_code();

        assert_eq!(
            "pay1qqpsxq4730l4yre4lt3588eyt3f2lwggtfalvtgfns04a8smzkn7yys6xv2gs8",
            code.to_string()
        );

        let parsed: PaymentCode =
            "pay1qqpsxq4730l4yre4lt3588eyt3f2lwggtfalvtgfns04a8smzkn7yys6xv2gs8"
                .parse()
                .unwrap();

        assert_eq!(code, parsed);
    }

    fn sender() -> Sender {
        Sender::from_seed(&Secp256k1::new(), &[0xFE], Network::Bitcoin, 0).unwrap()
    }

    fn recipient() -> Recipient {
        Recipient::from_seed(
            &Secp256k1::new(),
            &[0xFF],
            Network::Bitcoin,
            0,
            [AddressType::P2pkh, AddressType::P2wpkh]
                .into_iter()
                .collect(),
        )
        .unwrap()
    }
}
