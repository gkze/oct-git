// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::{Read, Write};
use std::path::PathBuf;

use hex::ToHex;
use openpgp_cert_d::CertD;
use pgp::types::KeyTrait;
use rpgpie::key::checked::CheckedCertificate;
use rpgpie::key::component::SignedComponentKeyPub;
use rpgpie_certificate_store::Store;

pub(crate) fn verify(
    mut stdin: impl Read,
    mut stdout: impl Write,
    mut stderr: impl Write,
    signature: &PathBuf,
    cert_store: &Option<PathBuf>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let store = if let Some(cert_store) = cert_store {
        Store::with_base_dir(cert_store)?
    } else {
        Store::new()?
    };
    let mut buffer = vec![];
    std::io::copy(&mut stdin, &mut buffer)?;
    let sig = &rpgpie::sig::load(&mut std::fs::File::open(signature)?)?[0];
    //capture sigs:
    //std::fs::copy(signature, "/tmp/data.sig")?;
    //std::fs::File::create_new("/tmp/data")?.write_all(&buffer)?;

    let fingerprints = sig.config.issuer_fingerprint();
    let fingerprints = fingerprints.iter().map(hex::encode).collect::<Vec<_>>();
    let mut certs = fingerprints
        .iter()
        .flat_map(|fpr| store.search_by_fingerprint(fpr).ok())
        .flatten()
        .collect::<Vec<_>>();
    if certs.is_empty() {
        let store = if let Some(cert_store) = cert_store {
            CertD::with_base_dir(cert_store)?
        } else {
            CertD::new()?
        };
        for fingerprint in fingerprints {
            eprintln!("https://keys.openpgp.org/pks/lookup?op=get&options=mr&search={fingerprint}");
            if let Ok(response) = reqwest::blocking::get(format!(
                "https://keys.openpgp.org/pks/lookup?op=get&options=mr&search={fingerprint}"
            )) {
                if let Ok(text) = response.text() {
                    if let Ok(loaded_certs) =
                        rpgpie::key::Certificate::load(&mut std::io::Cursor::new(text.as_bytes()))
                    {
                        for cert in loaded_certs {
                            let mut w = vec![];
                            rpgpie::key::Certificate::save(&vec![cert.clone()], false, &mut w)?;
                            store.insert_data(&w, false, |old, _new| {
                                Ok(openpgp_cert_d::MergeResult::DataRef(old))
                            })?;
                            certs.push(cert);
                        }
                    }
                }
            }
        }
    }
    let valid_sigs = certs
        .iter()
        .flat_map(|cert| {
            let key: CheckedCertificate = cert.into();
            key.valid_signing_capable_component_keys_at(&std::time::SystemTime::now().into())
                .into_iter()
                .filter_map(|verifier| {
                    verifier
                        .verify(sig, &buffer)
                        .map(|_| (key.clone(), verifier, sig.clone()))
                        .ok()
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    for (key, verifier, _sig) in &valid_sigs {
        if let Some(user_id) = key.primary_user_id() {
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
            if let SignedComponentKeyPub::Primary((primary, _)) = key.primary_key() {
                hex::encode(primary.fingerprint())
            } else {
                "unknown".into()
            }
        )?;
        writeln!(
            stderr,
            "Signing key: {}",
            hex::encode(verifier.as_componentkey().fingerprint())
        )?;
    }
    //eprintln!("VLD: {valid_sigs:?}");

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
