// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::{stderr, stdin, stdout};

use clap::Parser;
use openpgp_card_tool_git::cli::{Args, Mode};
use openpgp_card_tool_git::{sign, verify};

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
