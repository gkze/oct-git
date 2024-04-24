// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

mod card;
pub mod cli;
mod notify;
mod pki;
mod sign;
mod verify;

use std::path::PathBuf;

pub use card::set_pin;
use rpgpie_certificate_store::Store;
pub use sign::sign;
pub use verify::verify;

pub(crate) fn open_store(
    cert_store_path: Option<&PathBuf>,
) -> Result<Store, rpgpie_certificate_store::Error> {
    match cert_store_path {
        None => Ok(Store::new()?),
        Some(cert_store) => Ok(Store::with_base_dir(cert_store)?),
    }
}
