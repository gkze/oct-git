// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::Parser;
use monkeybagel::{cli::Args, run};

fn main() {
    let args = Args::parse();
    if let Err(e) = run(
        args,
        std::io::stdin(),
        std::io::stdout().lock(),
        std::io::stderr().lock(),
    ) {
        eprintln!("Lieutenant error: {e}");
        std::process::exit(1);
    }
}
