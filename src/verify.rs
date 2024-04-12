// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::{Read, Write};
use std::path::PathBuf;

use hex::ToHex;
use pgp::Signature;
use rpgpie::key::{checked::CheckedCertificate, component::ComponentKeyPub, SignatureVerifier};
use rpgpie_certificate_store::Store;

use crate::pki;

pub fn verify(
    mut data: impl Read,
    mut stdout: impl Write,
    mut stderr: impl Write,
    sig_path: &PathBuf,
    cert_store_path: Option<&PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = match cert_store_path {
        None => Store::new()?,
        Some(cert_store) => Store::with_base_dir(cert_store)?,
    };

    // Buffer the data (we might need to verify it multiple times, against different certificates)
    let mut buffer = vec![];
    std::io::copy(&mut data, &mut buffer)?;

    let sig = &rpgpie::sig::load(&mut std::fs::File::open(sig_path)?)?[0];

    // // capture sigs:
    // std::fs::copy(signature, "/tmp/data.sig")?;
    // std::fs::File::create_new("/tmp/data")?.write_all(&buffer)?;

    let fingerprints = sig.config.issuer_fingerprint();

    let fps_hex = fingerprints.iter().map(hex::encode).collect::<Vec<_>>();

    // look up certificates for the issuer(s) in the cert store
    let mut certs = fps_hex
        .iter()
        .flat_map(|fpr| store.search_by_fingerprint(fpr).ok())
        .flatten()
        .collect::<Vec<_>>();

    // If our store lookup didn't yield any certificate, we try to find certificates on the koo
    // keyserver (and persist them in the store, for next time)
    if certs.is_empty() {
        certs = pki::get_keyserver_koo(&fps_hex);
        for c in &certs {
            store.insert(c)?;
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

    print_results(sig, valid_sigs, &mut stdout, &mut stderr)?;

    Ok(())
}

/// Output information about the signature verification results.
///
/// Note: Some of the output is intended for automated processing.
fn print_results(
    sig: &Signature,
    valid_sigs: Vec<(CheckedCertificate, SignatureVerifier)>,
    mut stdout: impl Write,
    mut stderr: impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    // intellij does lookups for:
    // git log --show-signature --format="%H %G? %GS %GF"
    // (https://github.com/JetBrains/intellij-community/blob/c856f5fe2ccbee91f8c85d11f94bbaa84af3b557/plugins/git4idea/src/git4idea/log/GitCommitSignatureLoaderBase.kt#L114-L119)

    for (ccert, verifier) in &valid_sigs {
        if let Some(user_id) = ccert.primary_user_id() {
            writeln!(stderr, "Signed by: {}", user_id.id.id())?;
            writeln!(
                stdout,
                "\n[GNUPG:] GOODSIG {:X} {}",
                verifier.as_componentkey().key_id(),
                user_id.id.id()
            )?;
        } else {
            writeln!(
                stdout,
                "\n[GNUPG:] GOODSIG {:X}",
                verifier.as_componentkey().key_id(),
            )?;
        }

        // https://github.com/git/git/blob/11c821f2f2a31e70fb5cc449f9a29401c333aad2/gpg-interface.c#L371
        write!(
            stdout,
            "[GNUPG:] VALIDSIG {}",
            verifier
                .as_componentkey()
                .fingerprint()
                .encode_hex_upper::<String>()
        )?;
        writeln!(
            stderr,
            "Certificate: {}",
            hex::encode(ComponentKeyPub::from(ccert.primary_key()).fingerprint())
        )?;
        writeln!(
            stderr,
            "Signing key: {}",
            hex::encode(verifier.as_componentkey().fingerprint())
        )?;
    }

    if valid_sigs.is_empty() {
        writeln!(
            stderr,
            "No valid sigs for signing key {}",
            sig.config
                .issuer_fingerprint()
                .iter()
                .map(hex::encode)
                .fold(String::new(), |a, b| a + " " + &b)
        )?;
    }

    Ok(())
}
