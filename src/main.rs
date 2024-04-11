// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::{stderr, stdin, stdout};

use clap::Parser;
use monkeybagel::{cli, sign, verify};

fn main() {
    let args = cli::Args::parse();

    let mode = match cli::Mode::try_from(args) {
        Ok(mode) => mode,
        Err(e) => {
            eprintln!("CLI error: {e}");
            std::process::exit(1);
        }
    };

    let res = match &mode {
        cli::Mode::Verify {
            signature,
            cert_store,
        } => verify(stdin(), stdout(), stderr(), signature, cert_store),
        cli::Mode::Sign(key, armor) => sign(stdin(), stdout(), stderr(), key, *armor),
    };

    if let Err(e) = res {
        eprintln!("Command failed: {e}");
        std::process::exit(1);
    }
}
