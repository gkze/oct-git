// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::convert::TryFrom;
use std::path::PathBuf;

use clap::Parser;

/// A model of the subset of the gpg CLI interface that we're supporting, to be called by git.
#[derive(Parser, Debug, Default)]
pub struct Args {
    #[clap(long)]
    pub verify: Option<PathBuf>,

    #[clap(long, short = 'b')]
    pub detach_sign: bool,

    #[clap(long, short = 's')]
    pub sign: bool,

    #[clap(long, short = 'a')]
    pub armor: bool,

    #[clap(long, short = 'u')]
    pub user_id: Option<String>,

    #[clap(long)]
    pub keyid_format: Option<String>,

    #[clap(long)]
    pub status_fd: Option<String>,

    pub file_to_verify: Option<String>,

    /// Path to cert-d storage (used for signature verification).
    /// If None, use the user's default (shared) PGP certificate directory.
    ///
    /// Also see <https://datatracker.ietf.org/doc/draft-nwjw-openpgp-cert-d/>
    #[clap(short, long, env = "PGP_CERT_D")]
    pub cert_store: Option<PathBuf>,
}

#[derive(Copy, Clone)]
pub enum Armor {
    NoArmor,
    Armor,
}

pub enum Mode {
    Verify {
        signature: PathBuf,
        cert_store: Option<PathBuf>,
    },
    Sign(String, Armor),
}

impl TryFrom<Args> for Mode {
    type Error = String;

    fn try_from(value: Args) -> Result<Self, Self::Error> {
        if let Some(signature) = value.verify {
            if Some("-".into()) == value.file_to_verify {
                Ok(Mode::Verify {
                    signature,
                    cert_store: value.cert_store,
                })
            } else {
                Err("Verification of files other than stdin is unsupported. Use -".into())
            }
        } else if value.detach_sign {
            if let Some(user_id) = value.user_id {
                Ok(Mode::Sign(
                    user_id,
                    if value.armor {
                        Armor::Armor
                    } else {
                        Armor::NoArmor
                    },
                ))
            } else {
                Err("The -u parameter is required. Please provide a hex-encoded signing subkey fingerprint with no spaces".into())
            }
        } else if value.sign {
            Err("Inline signing is not supported. Use --detach-sign".into())
        } else {
            Err("Unknown operation: only verify and detach-sign are supported.".into())
        }
    }
}
