// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::SystemTime;

use hex::ToHex;
use pgp::packet::SignatureConfig;
use pgp::Signature;
use rpgpie::key::component::{SignedComponentKey, SignedComponentKeyPub};
use rpgpie::key::{
    checked::CheckedCertificate, component::ComponentKeyPub, Certificate, SignatureVerifier,
};
use rpgpie::sig::stack::SigStack;

/// List of hex encoded (lowercase) issuer fingerprints
fn signer_fps(sc: &SignatureConfig) -> Vec<String> {
    let fingerprints = sc.issuer_fingerprint();
    fingerprints.iter().map(hex::encode).collect()
}

/// List of hex encoded (lowercase) issuer key ids
fn signer_key_ids(sc: &SignatureConfig) -> Vec<String> {
    let fingerprints = sc.issuer();
    fingerprints
        .iter()
        .map(|key_id| key_id.encode_hex())
        .collect()
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

    let sig = &rpgpie::sig::load(&mut std::fs::File::open(sig_path)?)?[0];

    let fps_hex = signer_fps(&sig.config);

    let sig_creation = sig.config.created().expect("FIXME");

    log::trace!("verify sig setup done");

    // look up certificates for the issuer(s) in the cert store
    let mut certs = fps_hex
        .iter()
        .flat_map(|fpr| store.search_by_fingerprint(fpr).ok())
        .flatten()
        .filter(|c| {
            !CheckedCertificate::from(c)
                .valid_signing_capable_component_keys_at(sig_creation)
                .is_empty()
        })
        .collect::<Vec<_>>();

    log::trace!("verify: cert store lookup by fp");

    let key_ids_hex = signer_key_ids(&sig.config);
    if certs.is_empty() {
        // no signer certificate found in store by issuer_fingerprint, try by key_id
        certs = key_ids_hex
            .iter()
            .flat_map(|key_id| store.search_by_key_id(key_id).ok())
            .flatten()
            .filter(|c| {
                !CheckedCertificate::from(c)
                    .valid_signing_capable_component_keys_at(sig_creation)
                    .is_empty()
            })
            .collect::<Vec<_>>();
    }

    log::trace!("verify: cert store lookup by key id");

    // If our store lookups didn't yield any certificate, we try to find certificates on
    // keyservers (first by fingerprint, then by key id)
    if certs.is_empty() {
        log::trace!("verify: poll from PKI by fps");

        certs = store
            .poll(&fps_hex)?
            .into_iter()
            .filter(|c| {
                !CheckedCertificate::from(c)
                    .valid_signing_capable_component_keys_at(sig_creation)
                    .is_empty()
            })
            .collect();

        log::debug!("got {} certificates from PKI by fingerprints", certs.len());

        if certs.is_empty() {
            log::trace!("verify: poll from PKI by key id");

            certs = store
                .poll(&key_ids_hex)?
                .into_iter()
                .filter(|c| {
                    !CheckedCertificate::from(c)
                        .valid_signing_capable_component_keys_at(sig_creation)
                        .is_empty()
                })
                .collect();

            log::debug!("got {} certificates from PKI by key ids", certs.len());
        }

        log::trace!("verify: pki lookups done");

        // ... persist any results, for next time
        for c in &certs {
            let _ = store.insert(c); // silently ignore errors
        }

        log::trace!("verify: store persisted");
    }

    let valid_sigs = certs
        .iter()
        .flat_map(|cert| {
            let ccert: CheckedCertificate = cert.into();

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
    certs: &[Certificate],
    valid_sigs: Vec<(CheckedCertificate, SignatureVerifier)>,
    mut out: impl Write,
    mut err: impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    // intellij does lookups for:
    // git log --show-signature --format="%H %G? %GS %GF"
    // (https://github.com/JetBrains/intellij-community/blob/c856f5fe2ccbee91f8c85d11f94bbaa84af3b557/plugins/git4idea/src/git4idea/log/GitCommitSignatureLoaderBase.kt#L114-L119)

    writeln!(
        err,
        "oct-git: Signature created {}",
        sig.config
            .created()
            .map(|dt| dt.to_string())
            .unwrap_or("[missing creation time]".to_string())
    )?;
    writeln!(
        err,
        "oct-git:      by {:?} key {}",
        sig.config.pub_alg,
        yolo_signer_id(&sig.config)
    )?;

    if certs.is_empty() {
        writeln!(
            err,
            "oct-git: Can't check signature: Certificate not available."
        )?;

        return Ok(());
    }

    for (ccert, verifier) in &valid_sigs {
        let fp = verifier.as_componentkey().fingerprint();

        let now = SystemTime::now().into();

        let cert_revoked = SignedComponentKey::Pub(ccert.primary_key().clone()).revoked(&now);

        // Is the primary invalid in any way?
        let cert_invalid = !ccert.primary_valid_at(&now)?;

        let sk: Vec<_> = std::iter::once(ccert.primary_key())
            .chain(ccert.subkeys())
            .filter(|sk| ComponentKeyPub::from(sk.clone()).fingerprint() == fp)
            .collect();

        assert_eq!(sk.len(), 1); // FIXME
        let sckp = &sk[0];
        let sck = SignedComponentKey::Pub(sckp.clone());

        let ckey_revoked = sck.revoked(&now);
        let ckey_invalid = match sckp {
            SignedComponentKeyPub::Primary(_) => cert_invalid,
            SignedComponentKeyPub::Subkey((spsk, _)) => {
                // FIXME: rpgpie needs a more convenient API for this
                let stack = SigStack::from_iter(spsk.signatures.iter());

                !stack.has_valid_binding_at(&now, spsk.key.created_at())
            }
        };

        // FIXME: ckey otherwise invalid?

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
            hex::encode(fp),
            revoked_str(cert_revoked | ckey_revoked),
            invalid_str(!(cert_revoked | ckey_revoked) && (cert_invalid | ckey_invalid)),
        )?;

        // certificate
        writeln!(
            err,
            "oct-git: Certificate {}{}{}",
            hex::encode(ComponentKeyPub::from(ccert.primary_key()).fingerprint()),
            revoked_str(cert_revoked),
            invalid_str(!cert_revoked && cert_invalid),
        )?;

        // primary user id
        if let Some(user_id) = ccert.primary_user_id() {
            writeln!(err, "oct-git: Signer User ID \"{}\"", user_id.id.id())?;
            writeln!(
                out,
                "\n[GNUPG:] GOODSIG {:X} {}",
                verifier.as_componentkey().key_id(),
                user_id.id.id()
            )?;
        } else {
            writeln!(
                out,
                "\n[GNUPG:] GOODSIG {:X}",
                verifier.as_componentkey().key_id(),
            )?;
        }

        // https://github.com/git/git/blob/11c821f2f2a31e70fb5cc449f9a29401c333aad2/gpg-interface.c#L371
        write!(
            out,
            "[GNUPG:] VALIDSIG {}",
            verifier
                .as_componentkey()
                .fingerprint()
                .encode_hex_upper::<String>()
        )?;
    }

    if valid_sigs.is_empty() {
        writeln!(
            err,
            "oct-git: No valid signature by key {}",
            signer_fps(&sig.config)
                .into_iter()
                .chain(signer_key_ids(&sig.config).into_iter())
                .collect::<Vec<_>>()
                .join(" ")
        )?;
    }

    Ok(())
}
