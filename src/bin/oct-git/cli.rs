// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::convert::TryFrom;
use std::path::PathBuf;

use clap::Parser;
use openpgp_card_tool_git::Armor;

/// A model of the subset of the gpg CLI interface that we're supporting.
/// This CLI is mainly intended to be called by Git.
///
/// However, some functionality is end user-facing, to help users set up oct-git.
/// In particular "store_card_pin" and "import".
#[derive(Parser, Debug, Default)]
pub struct Args {
    /// Verify a detached signature.
    ///
    /// The signed data must be provided via STDIN.
    ///
    /// Verification uses the local "Shared OpenPGP Certificate Directory"
    /// (openpgp-cert-d) to obtain signer certificates. If a signer certificate
    /// can't be found in the local openpgp-cert-d, oct-git attempts to obtain
    /// the certificate from OpenPGP PKI (such as keyservers).
    #[clap(long, value_names = ["SIGNATURE_FILE"])]
    pub verify: Option<PathBuf>,

    /// Create a detached signature.
    #[clap(long, short = 'b')]
    pub detach_sign: bool,

    /// This parameter only exists to redirect users to use `detach_sign` instead.
    #[clap(long, short = 's', hide = true)]
    pub sign: bool,

    /// Specifies if generated signatures should be ASCII armored.
    #[clap(long, short = 'a')]
    pub armor: bool,

    /// Identifies the signing key that should be used.
    ///
    /// Accepts signing subkey fingerprints, certificate fingerprints (or key IDs,
    /// as a fallback).
    #[clap(long, short = 'u', value_names = ["SIGNING_KEY_FINGERPRINT"])]
    pub user_id: Option<String>,

    /// Git passes this parameter, so we need to accept it.
    /// oct-git ignores this input and acts hardcoded to "long".
    ///
    /// Also see: https://github.com/git/git/blob/master/gpg-interface.c#L49
    #[clap(long, hide = true)]
    pub keyid_format: Option<String>,

    /// Git passes this parameter, so we need to accept it.
    /// oct-git ignores this input and acts hardcoded to "1".
    ///
    /// Also see: https://github.com/git/git/blob/master/gpg-interface.c#L360
    #[clap(long, hide = true)]
    pub status_fd: Option<String>,

    pub file_to_verify: Option<String>,

    /// Path to cert-d storage (used for signature verification).
    ///
    /// If None, use the user's default "Shared OpenPGP Certificate
    /// Directory" (openpgp-cert-d).
    ///
    /// Also see <https://datatracker.ietf.org/doc/draft-nwjw-openpgp-cert-d/>
    #[clap(short, long, env = "PGP_CERT_D", value_names = ["STORE_PATH"])]
    pub cert_store: Option<PathBuf>,

    /// Store the User PIN for OpenPGP card(s) on your system.
    ///
    /// The PIN is stored via the openpgp-card-state subsystem, see
    /// https://crates.io/crates/openpgp-card-state for more details.
    #[clap(long)]
    pub store_card_pin: bool,

    /// Import an OpenPGP certificate (public key) from a file.
    ///
    /// This adds the certificate to the default "Shared OpenPGP Certificate
    /// Directory" (openpgp-cert-d) on your system.
    #[clap(long, value_names = ["CERTIFICATE_FILE"])]
    pub import: Option<PathBuf>,
}

pub enum Mode {
    Verify {
        signature: PathBuf,
        cert_store: Option<PathBuf>,
    },
    Sign {
        id: String,
        armor: Armor,
        cert_store: Option<PathBuf>,
    },
    StoreCardPin,
    Import {
        cert_file: PathBuf,
        cert_store: Option<PathBuf>,
    },
    None,
}

impl TryFrom<Args> for Mode {
    type Error = String;

    fn try_from(value: Args) -> Result<Self, Self::Error> {
        if value.store_card_pin {
            Ok(Mode::StoreCardPin)
        } else if let Some(cert) = value.import {
            Ok(Mode::Import {
                cert_file: cert,
                cert_store: value.cert_store,
            })
        } else if let Some(signature) = value.verify {
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
                Ok(Mode::Sign {
                    id: user_id,
                    armor: if value.armor {
                        Armor::Armor
                    } else {
                        Armor::NoArmor
                    },
                    cert_store: value.cert_store,
                })
            } else {
                Err("The -u parameter is required. Please provide a hex-encoded signing subkey fingerprint with no spaces".into())
            }
        } else if value.sign {
            Err("Inline signing is not supported. Use --detach-sign".into())
        } else {
            // no (recognized) parameters
            Ok(Mode::None)
        }
    }
}
