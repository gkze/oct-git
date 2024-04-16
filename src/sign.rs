// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::{Read, Write};

use card_backend_pcsc::PcscBackend;
use openpgp_card::ocard::KeyType;
use openpgp_card_rpgp::CardSlot;
use pgp::packet::{SignatureConfig, SignatureType, SignatureVersion, Subpacket, SubpacketData};
use pgp::types::{KeyVersion, SecretKeyTrait};
use pgp::{ArmorOptions, Deserializable, Signature, SignedSecretKey, StandaloneSignature};

use crate::cli;
use crate::notify::notify_and_eprint;

fn verify_pin_from_backend(
    tx: &mut openpgp_card::Card<openpgp_card::state::Transaction>,
    ident: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Ok(Some(pin)) = openpgp_card_state::get_pin(ident) {
        if tx.card().verify_pw1_sign(pin.as_bytes()).is_err() {
            // We drop the PIN from the state backend, to avoid exhausting
            // the retry counter and locking up the User PIN.
            let res = openpgp_card_state::drop_pin(ident);

            if res.is_ok() {
                notify_and_eprint(&format!("ERROR: The stored User PIN for OpenPGP card '{}' seems wrong or blocked! Dropped it from storage.",
                                          &ident));
            } else {
                notify_and_eprint(&format!("ERROR: The stored User PIN for OpenPGP card '{}' seems wrong or blocked! In addition, dropping it from storage failed.",
                                          &ident));
            }

            Err(std::io::Error::other("Bad stored User PIN.").into())
        } else {
            Ok(())
        }
    } else {
        notify_and_eprint(&format!(
            "ERROR: No User PIN is stored in openpgp_card_state for OpenPGP card '{}'.",
            &ident
        ));

        Err(std::io::Error::other("No User PIN configured.").into())
    }
}

/// Compare the fingerprint `card_fp` from a card with a key identifier passed in by git.
/// The `git` key identifier can be either a Fingerprint or an (8 byte) Key ID.
///
/// The git identifier may specify the fingerprint or key id of primary key that is not a signing
/// key. The card may not contain that (presumably: certification) key at all.
///
/// The identifier stored in git must reflect the signing key that should be used for signing.
fn match_id(card_fp: &[u8], git: &[u8]) -> bool {
    const FP_V4_LEN: usize = 20;
    const KEYID_LEN: usize = 8;

    match (card_fp.len(), git.len()) {
        (FP_V4_LEN, FP_V4_LEN) => card_fp == git,
        (FP_V4_LEN, KEYID_LEN) => &card_fp[FP_V4_LEN - KEYID_LEN..] == git, // match `git` as a v4 key id
        _ => false,
    }
}

/// `key` identifies the key to be used for signing.
///
/// It can contain a reference to a key in two different formats:
/// 1. a Fingerprint or Key ID, in hexdecimal notation, optionally prefixed with `0x`.
/// 2. The format "`file::<path>`" points to a TSK that contains private key material to be used for
///    signing (this mode is currently only intended for testing, and doesn't support
///    password-protected keys).
///
/// Note: We expect git to pass the Fingerprint or Key ID of the signing key, in `key`.
/// If the primary key doesn't serve as the data signing key, then we expect to receive the
/// identity of the signing subkey in `key`.
///
/// (We don't currently handle the full Certificate of the signing key, so we can't look up signing
/// subkeys by primary fingerprint.)
pub fn sign(
    data: impl Read,
    mut stdout: impl Write,
    mut stderr: impl Write,
    key: &str,
    armor: cli::Armor,
) -> Result<(), Box<dyn std::error::Error>> {
    // TODO: Optionally lookup the signer certificate from the cert-d store?
    let signature = if let Some(file_name) = key.strip_prefix("file::") {
        // We're using a software key to perform the signing operation
        let signer = SignedSecretKey::from_bytes(std::fs::File::open(file_name)?)?;

        // FIXME: implicitly signs with the primary key
        calculate_signature(signer, data)?
    } else {
        // We're trying to use an OpenPGP card to perform the signing operation

        // Fingerprint or Key ID of the signing key (provided by git)
        let signing_key = if let Some(hex_fpr) = key.strip_prefix("0x") {
            hex::decode(hex_fpr)?
        } else {
            hex::decode(key)?
        };

        let mut signature = None;

        for card in PcscBackend::cards(None)? {
            let card = card?;
            let mut card = openpgp_card::Card::new(card)?;
            let mut tx = card.transaction()?;

            if let Some(fpr) = tx.fingerprint(KeyType::Signing)? {
                // Does this card contain the signing key that git is asking us to use?
                if match_id(fpr.as_bytes(), &signing_key) {
                    // Verify the User PIN (implicitly obtained via openpgp_card_state)
                    let ident = tx.application_identifier()?.ident();
                    verify_pin_from_backend(&mut tx, &ident)?;

                    // A signer based on the card
                    let cs = CardSlot::init_from_card(&mut tx, KeyType::Signing, &|| {
                        notify_and_eprint("touch confirmation required")
                    })?;

                    signature = Some(calculate_signature(cs, data)?);
                    break;
                }
            }
        }

        match signature {
            None => {
                notify_and_eprint(&format!("Found no OpenPGP card for signing key {:?}.", key));
                return Err(std::io::Error::other("No suitable card found.").into());
            }
            Some(s) => s,
        }
    };

    match armor {
        cli::Armor::Armor => StandaloneSignature { signature }
            .to_armored_writer(&mut stdout, ArmorOptions::default())?,
        cli::Armor::NoArmor => pgp::packet::write_packet(&mut stdout, &signature)?,
    }

    // https://github.com/git/git/blob/11c821f2f2a31e70fb5cc449f9a29401c333aad2/gpg-interface.c#L994
    writeln!(stderr, "\n[GNUPG:] SIG_CREATED ")?;

    Ok(())
}

/// Set up a signature packet, hash `data`, and make a cryptographic signature with `signer`
fn calculate_signature(
    signer: impl SecretKeyTrait,
    data: impl Read,
) -> Result<Signature, Box<dyn std::error::Error>> {
    let sig_config = SignatureConfig::new_v4(
        SignatureVersion::V4,
        SignatureType::Binary,
        signer.algorithm(),
        signer.hash_alg(),
        vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(
                std::time::SystemTime::now().into(),
            )),
            Subpacket::regular(SubpacketData::Issuer(signer.key_id())),
            Subpacket::regular(SubpacketData::IssuerFingerprint(
                KeyVersion::V4,
                signer.fingerprint().into(),
            )),
        ],
        vec![],
    );

    let mut hasher = sig_config.hash_alg.new_hasher()?;

    sig_config.hash_data_to_sign(&mut *hasher, data)?;
    let len = sig_config.hash_signature_data(&mut *hasher)?;
    hasher.update(&sig_config.trailer(len)?);

    let hash = &hasher.finish()[..];

    let signed_hash_value = [hash[0], hash[1]];
    let raw_sig = signer.create_signature(String::new, sig_config.hash_alg, hash)?;

    let signature = Signature::from_config(sig_config, signed_hash_value, raw_sig);

    Ok(signature)
}
