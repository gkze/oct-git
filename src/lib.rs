// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::{Read, Write};

pub mod cli;
mod sign;
mod verify;

pub fn run(
    args: cli::Args,
    stdin: impl Read,
    stdout: impl Write,
    stderr: impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let mode: cli::Mode = args.try_into()?;

    match &mode {
        cli::Mode::Verify {
            signature,
            cert_store,
        } => verify::verify(stdin, stdout, stderr, signature, cert_store),
        cli::Mode::Sign(key, armor) => sign::sign(stdin, stdout, stderr, key, *armor),
    }
}
