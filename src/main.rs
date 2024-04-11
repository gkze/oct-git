// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::{stderr, stdin, stdout};

use clap::Parser;
use monkeybagel::cli::{Args, Mode};
use monkeybagel::{sign, verify};

fn main() {
    let args = Args::parse();

    let res = match Mode::try_from(args) {
        Ok(Mode::Verify {
            signature,
            cert_store,
        }) => verify(stdin(), stdout(), stderr(), &signature, &cert_store),
        Ok(Mode::Sign(key, armor)) => sign(stdin(), stdout(), stderr(), &key, armor),
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
