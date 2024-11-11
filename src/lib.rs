use std::str::FromStr;

// src/lib.rs
use bitcoin::bip32::{DerivationPath, Error, Xpriv, Xpub};
use bitcoin::key::Parity;
use bitcoin::secp256k1::{schnorr::Signature, Keypair, Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::XOnlyPublicKey;
use lazy_static::lazy_static;
use sha2::{Digest, Sha256};

lazy_static! {
    static ref DERIVATION_PATH: DerivationPath =
        DerivationPath::from_str("m/86/0/0/0/0").expect("Invalid derivation path");
}

pub fn derive_internal_public_key(master_public_key: &Xpub) -> Result<Xpub, bitcoin::bip32::Error> {
    let secp = Secp256k1::new();
    let internal_pubkey = master_public_key.derive_pub(&secp, &*DERIVATION_PATH)?;
    Ok(internal_pubkey)
}

pub fn compute_tweak(internal_public_key: &Xpub, nonce: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(internal_public_key.public_key.serialize());
    hasher.update(nonce);
    let result = hasher.finalize();
    let mut tweak = [0u8; 32];
    tweak.copy_from_slice(&result);
    tweak
}

pub fn generate_taproot_output_key(
    internal_public_key: &PublicKey,
    tweak: &[u8; 32],
) -> Result<(XOnlyPublicKey, Parity), Error> {
    let secp = Secp256k1::new();
    let tweak_secret = SecretKey::from_slice(tweak)?;
    let tweaked_key = internal_public_key
        .x_only_public_key()
        .0
        .add_tweak(&secp, &tweak_secret.into())?;
    Ok(tweaked_key)
}

pub fn generate_tweaked_keypair(
    keypair: &Keypair,
    tweak: &[u8; 32],
) -> Result<Keypair, bitcoin::secp256k1::Error> {
    let secp = Secp256k1::new();
    let tweak_secret = SecretKey::from_slice(tweak)?;
    keypair.add_xonly_tweak(&secp, &tweak_secret.into())
}

pub fn sign(private_key: &Xpriv, tweak: &[u8; 32], message: &Message) -> Result<Signature, Error> {
    let secp = Secp256k1::new();

    // Derive internal private key
    let internal_private_key = private_key.derive_priv(&secp, &*DERIVATION_PATH)?;

    // Create and tweak keypair
    let keypair =
        bitcoin::secp256k1::Keypair::from_secret_key(&secp, &internal_private_key.private_key);
    let tweaked_keypair = generate_tweaked_keypair(&keypair, tweak)?;

    // Sign
    Ok(secp.sign_schnorr(message, &tweaked_keypair))
}

pub fn verify(
    public_key: &PublicKey,
    tweak: &[u8; 32],
    message: &Message,
    signature: &Signature,
) -> Result<(), Error> {
    let secp = Secp256k1::new();

    // Generate taproot output key
    let (taproot_key, _parity) = generate_taproot_output_key(public_key, tweak)?;

    // Verify
    secp.verify_schnorr(signature, message, &taproot_key)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::bip32::Xpriv;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{Address, Network};
    use starknet::core::types::FieldElement;

    #[test]
    fn test_taproot_key_generation_and_signing() {
        // th0rgal.stark sepolia
        let starknet_deposit_address: FieldElement = FieldElement::from_hex_be(
            "0x0403c80a49f16Ed8Ecf751f4B3Ad62CC8f85EbEB2d40DC3B4377a089b438995D",
        )
        .unwrap();

        // Generate bridge keys
        let secp = Secp256k1::new();
        let master_private_key = Xpriv::new_master(Network::Bitcoin, &[1u8; 32]).unwrap();
        let master_public_key = Xpub::from_priv(&secp, &master_private_key);
        let internal_key = derive_internal_public_key(&master_public_key).unwrap();

        // Derive tweak for th0rgal.stark
        let nonce: [u8; 32] = starknet_deposit_address.to_bytes_be();
        let tweak = compute_tweak(&internal_key, &nonce);

        // Generate taproot output key and address
        let (taproot_key, _parity) =
            generate_taproot_output_key(&internal_key.public_key, &tweak).unwrap();
        let deposit_address = Address::p2tr(&secp, taproot_key, None, Network::Bitcoin);

        assert_eq!(
            deposit_address.to_string(),
            "bc1ph3u5auuv279qqppk70xrl7ry7y7xsgve0ke0k8kadwsmq7lhprpq5pca6t"
        );

        // Sign and verify a message
        let message = b"Hello, Taproot!";
        let message_hash = Sha256::digest(message);
        let message = Message::from_digest_slice(&message_hash).unwrap();

        let signature = sign(&master_private_key, &tweak, &message).unwrap();
        assert!(verify(&internal_key.public_key, &tweak, &message, &signature).is_ok());
    }
}
