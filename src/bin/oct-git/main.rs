// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::{stderr, stdin, stdout};

use clap::Parser;
use openpgp_card_tool_git::{set_pin, sign, verify};

mod cli;
use cli::*;

const INTRO: &str = "Welcome to oct-git, a modern Rust-based Git signing tool for OpenPGP cards! 🎉

To get started:

1) Persist your card's User PIN with:

  $ oct-git --store-card-pin

For more about User PIN handling, see
https://crates.io/crates/openpgp-card-state

2) Configure Git to use oct-git for signing:

  $ git config --global gpg.program <path to oct-git>
  $ git config --global user.signingkey <fingerprint>

For more information, see https://crates.io/crates/openpgp-card-tool-git";

fn main() {
    env_logger::init();

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
        Ok(Mode::None) => {
            // Show a brief introduction
            eprintln!("{INTRO}");
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
