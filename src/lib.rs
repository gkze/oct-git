// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

mod card;
mod notify;
mod sign;
mod verify;

use std::path::PathBuf;

pub use card::set_pin;
use rpgpie::key::Certificate;
use rpgpie_certificate_store::Store;
pub use sign::sign;
pub use verify::verify;

#[derive(Copy, Clone)]
pub enum Armor {
    NoArmor,
    Armor,
}

pub(crate) fn open_store(
    cert_store_path: Option<&PathBuf>,
) -> Result<Store, rpgpie_certificate_store::Error> {
    match cert_store_path {
        None => Ok(Store::new()?),
        Some(cert_store) => Ok(Store::with_base_dir(cert_store)?),
    }
}

/// Import a certificate into a cert-d store.
pub fn import_cert(
    cert_file: &PathBuf,
    cert_store_path: Option<&PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = open_store(cert_store_path)?;

    // FIXME: we could make this more robust
    let certs = Certificate::load(&mut std::fs::File::open(cert_file)?)?;
    for cert in certs {
        store.insert(&cert)?;
    }

    Ok(())
}
