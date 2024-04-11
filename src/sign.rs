// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::{Read, Write};

use card_backend_pcsc::PcscBackend;
use openpgp_card::ocard::KeyType;
use openpgp_card_rpgp::CardSlot;
use pgp::crypto::hash::HashAlgorithm;
use pgp::packet::{SignatureConfig, SignatureType, SignatureVersion, Subpacket, SubpacketData};
use pgp::types::{KeyVersion, SecretKeyTrait};
use pgp::{ArmorOptions, Deserializable, Signature, SignedSecretKey, StandaloneSignature};

use crate::cli;

fn match_id(card: &[u8], git: &[u8]) -> bool {
    match (card.len(), git.len()) {
        (20, 20) => card == git,
        (20, 8) => &card[12..] == git, // match as v4 key id
        _ => false,
    }
}

pub fn sign(
    stdin: impl Read,
    mut stdout: impl Write,
    mut stderr: impl Write,
    key: &String,
    armor: cli::Armor,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let signature = if let Some(file_name) = key.strip_prefix("file::") {
        let signer = SignedSecretKey::from_bytes(std::fs::File::open(file_name)?)?;
        complete_signing(signer, stdin)?
    } else {
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
            let ard = tx.card().application_related_data()?;
            let fprs = ard.fingerprints()?;
            if let Some(fpr) = fprs.signature() {
                if match_id(fpr.as_bytes(), &signing_key) {
                    let ident = ard.application_id()?.ident();
                    if let Ok(Some(pin)) = openpgp_card_state::get_pin(&ident) {
                        if tx.card().verify_pw1_sign(pin.as_bytes()).is_err() {
                            // We drop the PIN from the state backend, to avoid exhausting
                            // the retry counter and locking up the User PIN.
                            let res = openpgp_card_state::drop_pin(&ident);

                            if res.is_ok() {
                                writeln!(stderr,
                                         "ERROR: The stored User PIN for OpenPGP card '{}' seems wrong or blocked! Dropped it from storage.",
                                         &ident)?;
                            } else {
                                writeln!(stderr,
                                         "ERROR: The stored User PIN for OpenPGP card '{}' seems wrong or blocked! In addition, dropping it from storage failed.",
                                         &ident)?;
                            }
                        }
                    } else {
                        return Err(std::io::Error::other("No signing PIN configured.").into());
                    }

                    let cs = CardSlot::init_from_card(&mut tx, KeyType::Signing, &|| {
                        eprintln!("touch confirmation required")
                    })?;

                    signature = Some(complete_signing(cs, stdin)?);
                    break;
                }
            }
        }

        signature.unwrap_or_else(|| {
            panic!(
                "No cards attached provide signing for selected key {:?}.",
                key
            )
        })
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

fn complete_signing(
    signer: impl SecretKeyTrait,
    stdin: impl Read,
) -> Result<Signature, Box<dyn std::error::Error>> {
    let signature = SignatureConfig::new_v4(
        SignatureVersion::V4,
        SignatureType::Binary,
        signer.algorithm(),
        HashAlgorithm::SHA2_256,
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

    let mut hasher = signature.hash_alg.new_hasher()?;

    signature.hash_data_to_sign(&mut *hasher, stdin)?;
    let len = signature.hash_signature_data(&mut *hasher)?;
    hasher.update(&signature.trailer(len)?);

    let hash = &hasher.finish()[..];

    let signed_hash_value = [hash[0], hash[1]];
    let raw_sig = signer.create_signature(String::new, HashAlgorithm::SHA2_256, hash)?;

    let signature = Signature::from_config(signature, signed_hash_value, raw_sig);

    Ok(signature)
}
