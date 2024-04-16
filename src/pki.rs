// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use rpgpie::key::Certificate;

const KOO_SEARCH: &str = "https://keys.openpgp.org/pks/lookup?op=get&options=mr&search=";

/// Get Certificates for a set of fingerprints from keys.openpgp.org
pub(crate) fn get_keyserver_koo(fingerprints: &[String]) -> Vec<Certificate> {
    let mut certs = vec![];

    for fingerprint in fingerprints {
        let search = format!("{KOO_SEARCH}{fingerprint}");
        log::info!("get_keyserver_koo: {search}");

        if let Ok(response) = reqwest::blocking::get(search) {
            if let Ok(text) = response.text() {
                if let Ok(mut loaded_certs) =
                    Certificate::load(&mut std::io::Cursor::new(text.as_bytes()))
                {
                    certs.append(&mut loaded_certs);
                }
            }
        }
    }

    certs
}
