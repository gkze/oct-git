// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::{Read, Write};
use std::path::PathBuf;

use hex::ToHex;
use pgp::packet::SignatureConfig;
use pgp::Signature;
use rpgpie::key::{
    checked::CheckedCertificate, component::ComponentKeyPub, Certificate, SignatureVerifier,
};

use crate::pki;

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
    let store = crate::open_store(cert_store_path)?;

    // Buffer the data (we might need to verify it multiple times, against different certificates)
    let mut buffer = vec![];
    std::io::copy(&mut data, &mut buffer)?;

    let sig = &rpgpie::sig::load(&mut std::fs::File::open(sig_path)?)?[0];

    let fps_hex = signer_fps(&sig.config);

    // look up certificates for the issuer(s) in the cert store
    let mut certs = fps_hex
        .iter()
        .flat_map(|fpr| store.search_by_fingerprint(fpr).ok())
        .flatten()
        .collect::<Vec<_>>();

    let key_ids_hex = signer_key_ids(&sig.config);
    if certs.is_empty() {
        // no signer certificate found in store by issuer_fingerprint, try by key_id
        certs = key_ids_hex
            .iter()
            .flat_map(|key_id| store.search_by_key_id(key_id).ok())
            .flatten()
            .collect::<Vec<_>>();
    }

    // If our store lookups didn't yield any certificate, we try to find certificates on the koo
    // keyserver, first by fingerprint, then by key id
    if certs.is_empty() {
        certs = pki::get_keyserver_koo(&fps_hex);
        if certs.is_empty() {
            certs = pki::get_keyserver_koo(&key_ids_hex);
        }

        // ... persist any results, for next time
        for c in &certs {
            let _ = store.insert(c); // silently ignore errors
        }
    }

    let valid_sigs = certs
        .iter()
        .flat_map(|cert| {
            let ccert: CheckedCertificate = cert.into();
            ccert
                .valid_signing_capable_component_keys_at(&std::time::SystemTime::now().into())
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

    print_results(sig, &certs, valid_sigs, &mut out, &mut err)?;

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
        writeln!(
            err,
            "oct-git: Good signature by {}",
            hex::encode(verifier.as_componentkey().fingerprint())
        )?;
        writeln!(
            err,
            "oct-git: Certificate {}",
            hex::encode(ComponentKeyPub::from(ccert.primary_key()).fingerprint())
        )?;

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
