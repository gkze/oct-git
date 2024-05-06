// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::{stderr, stdin, stdout};

use clap::Parser;
use openpgp_card_tool_git::{import_cert, set_pin, sign, verify};

mod cli;
use cli::*;

fn help_text() -> String {
    const OCT_GIT_FALLBACK_NAME: &str = "<path to oct-git>";

    let oct_git_path = match std::env::current_exe() {
        Ok(exe_path) => exe_path
            .to_str()
            .unwrap_or(OCT_GIT_FALLBACK_NAME)
            .to_string(),
        Err(_e) => OCT_GIT_FALLBACK_NAME.to_string(),
    };

    format!(
        "Welcome to oct-git, a modern Rust-based Git signing tool for OpenPGP cards! 🎉

To get started:

1) Persist your card's User PIN with:

  $ oct-git --store-card-pin

For more about User PIN handling, see
https://crates.io/crates/openpgp-card-state

2) Configure Git to use oct-git for signing:

  $ git config --global gpg.program {}
  $ git config --global user.signingkey <fingerprint>

One way to find out your signing key fingerprint is to query your
OpenPGP card, with:

  $ oct status

(Note that the fingerprint must be provided to git without spaces. Also,
please double-check that the signing key on your card is valid for data
signatures, not just for certifications)

For more information, see https://crates.io/crates/openpgp-card-tool-git",
        oct_git_path
    )
}

fn main() {
    env_logger::builder().format_timestamp_micros().init();
    let help_text = help_text();

    let args = Args::parse();

    let res = match Mode::try_from(args) {
        Ok(Mode::Verify {
            signature,
            cert_store,
        }) => verify(stdin(), stdout(), stderr(), &signature, cert_store.as_ref()),
        Ok(Mode::Sign {
            id,
            armor,
            cert_store,
        }) => sign(stdin(), stdout(), stderr(), &id, armor, cert_store.as_ref()),
        Ok(Mode::StoreCardPin) => set_pin(),
        Ok(Mode::Import {
            cert_file,
            cert_store,
        }) => import_cert(&cert_file, cert_store.as_ref()),
        Ok(Mode::None) => {
            // Show a brief introduction
            eprintln!("{help_text}");
            Ok(())
        }
        Err(e) => {
            eprintln!("CLI error: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = res {
        eprintln!("Command failed: {e}");
        std::process::exit(1);
    }
}
