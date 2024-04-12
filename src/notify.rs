// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Notification title
const NAME: &str = env!("CARGO_CRATE_NAME");

#[cfg(feature = "notify")]
pub(crate) fn notify(msg: &str) {
    if let Err(e) = notify_rust::Notification::new()
        .summary(NAME)
        .body(msg)
        .timeout(std::time::Duration::from_secs(15))
        .show()
    {
        eprintln!("Failure in notify_rust: {:?}", e);
    }
}

#[cfg(not(feature = "notify"))]
pub(crate) fn notify(_: &str) {}

pub(crate) fn notify_and_eprint(msg: &str) {
    eprintln!("{msg}");
    notify(msg);
}
