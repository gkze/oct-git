// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use card_backend_pcsc::PcscBackend;

/// Iterate over all connected cards. Query for User PINs for any card that doesn't have a User PIN
/// persisted in openpgp-card-state. Store any User PINs that the OpenPGP card accepts as valid.
pub fn set_pin() -> Result<(), Box<dyn std::error::Error>> {
    for card in PcscBackend::cards(None)? {
        let card = card?;
        let mut card = openpgp_card::Card::new(card)?;
        let mut tx = card.transaction()?;

        // Get the ident for this card
        let ident = tx.application_identifier()?.ident();

        println!("Found OpenPGP card {}", ident);

        if let Ok(Some(pin)) = openpgp_card_state::get_pin(&ident) {
            if tx.card().verify_pw1_sign(pin.as_bytes()).is_err() {
                // Drop the PIN from the state backend to avoid exhausting the retry counter
                // (and locking up the User PIN).
                openpgp_card_state::drop_pin(&ident)?;

                println!("  An invalid User PIN has been dropped from openpgp-card-state");

                if let Err(e) = get_and_store_pin(&mut tx, &ident) {
                    eprintln!("  Failed to set a new User PIN for the card: {}", e);
                }
            } else {
                println!("  A valid User PIN is available via openpgp-card-state");
            }
        } else {
            println!("  No User PIN is stored in openpgp-card-state");

            if let Err(e) = get_and_store_pin(&mut tx, &ident) {
                eprintln!("  Failed to store a new User PIN: {}", e);
            }
        }

        println!();
    }

    Ok(())
}

fn get_and_store_pin(
    tx: &mut openpgp_card::Card<openpgp_card::state::Transaction<'_>>,
    ident: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let pin = rpassword::prompt_password("  Enter User PIN to store (or <Enter> to skip): ")?;

    // Only continue processing this card if the user entered a non-empty value
    if !pin.is_empty() {
        // Present the PIN to the card
        tx.card().verify_pw1_sign(pin.as_bytes())?;

        // The card liked this User PIN, persist it via openpgp_card_state
        openpgp_card_state::set_pin(ident, &pin, None)?;

        println!("  User PIN has been stored in openpgp-card-state");
    } else {
        println!("  Skipped");
    }

    Ok(())
}
