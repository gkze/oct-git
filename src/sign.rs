// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::{Read, Write};
use std::path::PathBuf;

use card_backend_pcsc::PcscBackend;
use openpgp_card::ocard::KeyType;
use openpgp_card_rpgp::CardSlot;
use pgp::packet::{SignatureConfig, SignatureType, SignatureVersion, Subpacket, SubpacketData};
use pgp::types::{KeyVersion, SecretKeyTrait};
use pgp::{ArmorOptions, Deserializable, Signature, SignedSecretKey, StandaloneSignature};
use rpgpie::key::checked::CheckedCertificate;

use crate::notify::notify_and_eprint;
use crate::Armor;

/// Attempt to present the User PIN to the card, for signing
fn verify_pin_from_backend(
    tx: &mut openpgp_card::Card<openpgp_card::state::Transaction>,
    ident: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Ok(Some(pin)) = openpgp_card_state::get_pin(ident) {
        if tx
            .card()
            .verify_pw1_sign(pin.as_bytes().to_vec().into())
            .is_err()
        {
            // We drop the PIN from the state backend to avoid exhausting the retry counter
            // (and locking up the User PIN).
            log::info!("Dropping User PIN for {} from openpgp_card_state", ident);
            let res = openpgp_card_state::drop_pin(ident);

            match res {
                Ok(()) => notify_and_eprint(&format!(
                    "Card {} rejected stored User PIN, dropped PIN from storage.",
                    &ident
                )),
                Err(e) => notify_and_eprint(&format!(
                    "Card {} rejected stored User PIN, and dropping PIN from storage failed: {}.",
                    &ident, e
                )),
            }
            Err(std::io::Error::other("Bad stored User PIN.").into())
        } else {
            Ok(())
        }
    } else {
        notify_and_eprint(&format!(
            "Missing User PIN for {}. Run 'oct-git --store-card-pin' to fix.",
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
    log::debug!(
        "matching card slot {:02x?} and requested ID {:02x?}",
        card_fp,
        git
    );

    const FP_V4_LEN: usize = 20;
    const KEYID_LEN: usize = 8;

    match (card_fp.len(), git.len()) {
        (FP_V4_LEN, FP_V4_LEN) => card_fp == git,
        (FP_V4_LEN, KEYID_LEN) => &card_fp[FP_V4_LEN - KEYID_LEN..] == git, // match `git` as a v4 key id
        _ => false,
    }
}

/// Try to look up the git-provided signer_id from the certificate store.
/// If it yields a result, get all of its signing capable subkey fingerprints (if any).
///
/// If no fingerprint can be found via that store, this returns the original `signer_id` in
/// Vec<u8> notation, so that the following code can try finding this exact fingerprint in a card
/// signing key slots.
fn lookup_signer_id_in_store(
    signer_id: &str,
    cert_store_path: Option<&PathBuf>,
) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    // Look up candidates for the signer certificate from the cert-d store
    let Some(store) = crate::open_store(cert_store_path).ok() else {
        // No store: we'll stop pursuing lookup

        return Ok(vec![hex::decode(signer_id)?]);
    };

    let mut signer_certs = match signer_id.len() {
        40 => store.search_by_fingerprint(signer_id).ok(),
        16 => store.search_by_key_id(signer_id).ok(),
        _ => None,
    };

    // if we didn't find any candidate Certificates in the local store, ask koo
    if let Some(certs) = &signer_certs {
        if certs.is_empty() {
            // try polling from KOO ...
            let koo = store.poll(&[signer_id.to_string()])?;

            // ... and store results in certd, if any
            for c in &koo {
                store.insert(c)?;
            }

            signer_certs = Some(koo);
        }
    }

    // we will only consider the certificate if we got exactly one.
    let signer_cert = signer_certs
        .and_then(move |mut s| match s.len() {
            0 => {
                // maybe log?
                None
            }
            1 => Some(s.pop().unwrap()),
            _ => {
                eprintln!("Warning: Found more than one certificate for signer id {} in the local certificate store", signer_id);
                eprintln!("Please specify a unique fingerprint in the git configuration");

                None
            }
        });

    let signer_ids = match signer_cert {
        None => vec![hex::decode(signer_id)?],
        Some(c) => {
            let ccert = CheckedCertificate::from(&c);

            let signer_fps: Vec<_> = ccert
                .valid_signing_capable_component_keys_at(&std::time::SystemTime::now().into())
                .iter()
                .map(|sv| sv.as_componentkey().fingerprint())
                .collect();

            if !signer_fps.is_empty() {
                signer_fps
            } else {
                vec![hex::decode(signer_id)?]
            }
        }
    };

    Ok(signer_ids)
}

/// `id` identifies the key to be used for signing.
///
/// It can contain a reference to a key in two different formats (as provided by git):
/// 1. a Fingerprint or Key ID, in hexadecimal notation, optionally prefixed with `0x`.
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
    mut out: impl Write,
    mut err: impl Write,
    mut signer_id: &str,
    armor: Armor,
    cert_store_path: Option<&PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("called for signer_id: {:02x?}", signer_id);

    let signature = if let Some(file_name) = signer_id.strip_prefix("file::") {
        // We're using a software key to perform the signing operation
        let signer = SignedSecretKey::from_bytes(std::fs::File::open(file_name)?)?;

        // FIXME: this call implicitly signs with the primary key
        calculate_signature(signer, data)?
    } else {
        // We're trying to use an OpenPGP card to perform the signing operation

        // strip "0x" prefix, if any
        if signer_id.starts_with("0x") {
            signer_id = &signer_id[2..];
        }

        let signer_ids = lookup_signer_id_in_store(signer_id, cert_store_path)?;

        log::info!("looking for card with signer_id(s): {:02x?}", signer_ids);

        // Have we seen a card with the key that git asks for?
        let mut matching_card = false;

        let mut signature = None;

        for card in PcscBackend::cards(None)? {
            let card = card?;
            let mut card = openpgp_card::Card::new(card)?;
            let mut tx = card.transaction()?;

            if let Some(card_sig_fp) = tx.fingerprint(KeyType::Signing)? {
                // Does this card contain a signing key that matches what git is asking us to use?
                if signer_ids
                    .iter()
                    .any(|id| match_id(card_sig_fp.as_bytes(), id))
                {
                    matching_card = true;

                    // Verify the User PIN (implicitly obtained via openpgp_card_state)
                    let ident = tx.application_identifier()?.ident();
                    verify_pin_from_backend(&mut tx, &ident)?;

                    // A signer based on the card
                    let cs = CardSlot::init_from_card(&mut tx, KeyType::Signing, &|| {
                        notify_and_eprint("Touch confirmation required.")
                    })?;

                    signature = Some(calculate_signature(cs, data)?);
                    break;
                }
            }
        }

        if !matching_card {
            notify_and_eprint(&format!("No OpenPGP card found for key {:?}.", signer_id));
            return Err(std::io::Error::other("No suitable card found.").into());
        }

        match signature {
            None => {
                notify_and_eprint(&format!(
                    "Failed to create a signature for {:?}.",
                    signer_id
                ));
                return Err(std::io::Error::other("Failed to create a signature.").into());
            }
            Some(s) => s,
        }
    };

    match armor {
        Armor::Armor => StandaloneSignature { signature }
            .to_armored_writer(&mut out, ArmorOptions::default())?,
        Armor::NoArmor => pgp::packet::write_packet(&mut out, &signature)?,
    }

    // https://github.com/git/git/blob/11c821f2f2a31e70fb5cc449f9a29401c333aad2/gpg-interface.c#L994
    writeln!(err, "\n[GNUPG:] SIG_CREATED ")?;

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
