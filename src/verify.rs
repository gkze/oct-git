// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::{Read, Write};
use std::path::PathBuf;

use chrono::DateTime;
use hex::ToHex;
use pgp::packet::{Signature, SignatureConfig};
use pgp::types::{KeyDetails, Timestamp};
use rpgpie::certificate::{Checked, SignatureVerifier};

/// List of hex encoded (lowercase) issuer fingerprints
fn signer_fps(sc: &SignatureConfig) -> Vec<String> {
    let fingerprints = sc.issuer_fingerprint();
    fingerprints
        .iter()
        .map(|fp| fp.as_bytes())
        .map(hex::encode)
        .collect()
}

/// List of hex encoded (lowercase) issuer key ids
fn signer_key_ids(sc: &SignatureConfig) -> Vec<String> {
    let key_ids = sc.issuer_key_id();
    key_ids.iter().map(|key_id| key_id.encode_hex()).collect()
}

/// Get a human-readable identifier for the signature issuer (fp or key id)
///
/// FIXME: produce space separated list of all fingerprints and key ids?
/// (like in print_results -> re-use there)
fn yolo_signer_id(sc: &SignatureConfig) -> String {
    let fps = signer_fps(sc);
    if !fps.is_empty() {
        fps[0].clone() // FIXME: which one should we pick, if multiple?
    } else {
        let kid = signer_key_ids(sc);
        if !kid.is_empty() {
            kid[0].clone() // FIXME: which one should we pick, if multiple?
        } else {
            "[unknown signer id]".to_string()
        }
    }
}

pub fn verify(
    mut data: impl Read,
    mut out: impl Write,
    mut err: impl Write,
    sig_path: &PathBuf,
    cert_store_path: Option<&PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    log::trace!("verify start");

    let store = crate::open_store(cert_store_path)?;

    log::trace!("verify open_store");

    // Buffer the data (we might need to verify it multiple times, against different certificates)
    let mut buffer = vec![];
    std::io::copy(&mut data, &mut buffer)?;

    let sig = &rpgpie::signature::load(&mut std::fs::File::open(sig_path)?)?[0];
    let Some(conf) = sig.config() else {
        unimplemented!()
    };

    let fps_hex = signer_fps(conf);

    let sig_creation = conf.created().expect("FIXME");

    log::trace!("verify sig setup done");

    // look up certificates for the issuer(s) in the cert store
    let mut certs: Vec<Checked> = fps_hex
        .iter()
        .flat_map(|fpr| store.search_and_poll_by_fingerprint(fpr).ok())
        .flatten()
        .map(|c| Checked::new(c.clone()))
        .filter(|c| {
            !c.valid_signing_capable_component_keys_at(sig_creation)
                .is_empty()
        })
        .collect::<Vec<_>>();

    log::trace!("verify: cert store lookup by fp");

    let key_ids_hex = signer_key_ids(conf);
    if certs.is_empty() {
        // no signer certificate found in store by issuer_fingerprint, try by key_id
        certs = key_ids_hex
            .iter()
            .flat_map(|key_id| store.search_and_poll_by_key_id(key_id).ok())
            .flatten()
            .map(|c| Checked::new(c.clone()))
            .filter(|c| {
                !c.valid_signing_capable_component_keys_at(sig_creation)
                    .is_empty()
            })
            .collect::<Vec<_>>();
    }

    log::trace!("verify: cert store lookup by key id");

    let valid_sigs = certs
        .iter()
        .flat_map(|ccert| {
            log::trace!("verify: got ccert");

            ccert
                .valid_signing_capable_component_keys_at(sig_creation)
                .into_iter()
                .filter_map(|verifier| {
                    verifier
                        .verify(sig, &buffer)
                        .map(|_| (ccert.clone(), verifier))
                        .ok()
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    log::trace!("verify: validation done");

    print_results(sig, &certs, valid_sigs, &mut out, &mut err)?;

    log::trace!("verify: print done");

    Ok(())
}

/// Output information about the signature verification results.
///
/// Note: Some of the output is intended for automated processing.
fn print_results(
    sig: &Signature,
    ccerts: &[Checked],
    valid_sigs: Vec<(Checked, SignatureVerifier)>,
    mut out: impl Write,
    mut err: impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    // intellij does lookups for:
    // git log --show-signature --format="%H %G? %GS %GF"
    // (https://github.com/JetBrains/intellij-community/blob/c856f5fe2ccbee91f8c85d11f94bbaa84af3b557/plugins/git4idea/src/git4idea/log/GitCommitSignatureLoaderBase.kt#L114-L119)

    let Some(conf) = sig.config() else {
        unimplemented!()
    };

    writeln!(
        err,
        "oct-git: Signature created {}",
        conf.created()
            .map(|ts| {
                DateTime::from_timestamp(ts.as_secs() as i64, 0)
                    .expect("DateTime")
                    .to_string()
            })
            .unwrap_or("[missing creation time]".to_string())
    )?;
    writeln!(
        err,
        "oct-git:      by {:?} key {}",
        conf.pub_alg,
        yolo_signer_id(conf)
    )?;

    if ccerts.is_empty() {
        writeln!(
            err,
            "oct-git: Can't check signature: Certificate not available."
        )?;

        return Ok(());
    }

    for (ccert, verifier) in &valid_sigs {
        let verifier_fp = verifier.as_componentkey().fingerprint();

        let now = Timestamp::now();

        // Is the cert/primary revoked now?
        let cert_revoked = ccert.revoked_at(now);

        // Is the cert/primary invalid in any way now?
        let cert_invalid = !ccert.primary_valid_at(now)?;

        let (ckey_revoked, ckey_invalid) = if *ccert.fingerprint() == verifier_fp {
            // verifier was the primary
            (cert_revoked, cert_invalid)
        } else {
            // verifier was a subkey

            let status = rpgpie::model::status_summary(ccert);

            let Some(key_summary) = status
                .subkeys
                .iter()
                .find(|key| key.fingerprint == hex::encode(verifier_fp.as_bytes()))
            else {
                unimplemented!("FIXME");
            };

            let ckey_revoked = cert_revoked || key_summary.status.is_revoked();
            let ckey_invalid = cert_invalid || !key_summary.status.is_valid();

            (ckey_revoked, ckey_invalid)
        };

        fn revoked_str(rev: bool) -> &'static str {
            if rev {
                " [revoked]"
            } else {
                ""
            }
        }

        // FIXME: this is messy: we print "expired" because that's the most likely case for a
        // valid signature to have been issued by a now invalid key.
        fn invalid_str(rev: bool) -> &'static str {
            if rev {
                " [expired]"
            } else {
                ""
            }
        }
        // component key
        writeln!(
            err,
            "oct-git: Good signature by {}{}{}",
            hex::encode(verifier_fp.as_bytes()),
            revoked_str(cert_revoked | ckey_revoked),
            invalid_str(!(cert_revoked | ckey_revoked) && (cert_invalid | ckey_invalid)),
        )?;

        // certificate
        writeln!(
            err,
            "oct-git: Certificate {}{}{}",
            hex::encode(ccert.fingerprint().as_bytes()),
            revoked_str(cert_revoked),
            invalid_str(!cert_revoked && cert_invalid),
        )?;

        // primary user id
        if let Some(signed_user) = ccert.primary_user_id() {
            let user_id = String::from_utf8_lossy(signed_user.id.id());

            writeln!(err, "oct-git: Signer User ID \"{}\"", user_id)?;
            writeln!(
                out,
                "\n[GNUPG:] GOODSIG {} {}",
                hex::encode_upper(verifier.as_componentkey().legacy_key_id()),
                user_id
            )?;
        } else {
            writeln!(
                out,
                "\n[GNUPG:] GOODSIG {}",
                hex::encode_upper(verifier.as_componentkey().legacy_key_id()),
            )?;
        }

        // https://github.com/git/git/blob/11c821f2f2a31e70fb5cc449f9a29401c333aad2/gpg-interface.c#L371
        write!(
            out,
            "[GNUPG:] VALIDSIG {}",
            verifier
                .as_componentkey()
                .fingerprint()
                .as_bytes()
                .encode_hex_upper::<String>()
        )?;
    }

    if valid_sigs.is_empty() {
        writeln!(
            err,
            "oct-git: No valid signature by key {}",
            signer_fps(conf)
                .into_iter()
                .chain(signer_key_ids(conf).into_iter())
                .collect::<Vec<_>>()
                .join(" ")
        )?;
    }

    Ok(())
}
