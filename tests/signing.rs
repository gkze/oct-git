// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-License-Identifier: MIT OR Apache-2.0

use openpgp_card_tool_git::{sign, Armor};
use pgp::composed::{Deserializable, SignedPublicKey, StandaloneSignature};
use testresult::TestResult;

#[test]
fn signing_key() -> TestResult {
    env_logger::init();

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let data = "test";

    if let Err(e) = {
        sign(
            data.as_bytes(),
            &mut stdout,
            &mut stderr,
            "file::tests/signing-key.pgp",
            Armor::Armor,
            None,
        )
    } {
        eprintln!("An error occurred: {}", e);
        eprintln!("stderr: {}", String::from_utf8_lossy(&stderr));
        println!("stdout: {}", String::from_utf8_lossy(&stdout));
        Err(e.into())
    } else {
        let verification_key = SignedPublicKey::from_file("tests/signing-key.pub.pgp")?;
        let signature = StandaloneSignature::from_armor_single(std::io::Cursor::new(stdout))?.0;
        signature
            .signature
            .verify(&verification_key, data.as_bytes())?;
        Ok(())
    }
}
