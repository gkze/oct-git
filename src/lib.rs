// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

pub mod cli;
mod notify;
mod pki;
mod sign;
mod verify;

pub use sign::sign;
pub use verify::verify;
