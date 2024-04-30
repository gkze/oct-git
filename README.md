<!--
SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# OpenPGP card tool for Git signing and verification

This project provides the `oct-git` "OpenPGP card tool for Git".

`oct-git` generates (and verifies) OpenPGP signatures in the context of the [Git](https://en.wikipedia.org/wiki/Git) distributed version control system. It serves as a replacement to the `gpg` program, for use with Git.

## Why

This tool is a stand-alone, "no-moving-parts" solution, written in pure Rust, using the [rPGP](https://crates.io/crates/pgp) OpenPGP library.
It aims for simplicity, requires no long-running processes[^pcsc], and doesn't keep a permanent connection to OpenPGP card hardware devices.

[^pcsc]: On Linux, the  `pcscd` system service is required, while on Windows and Mac, a PC/SC subsystem doesn't need to be installed (it is a part of the core system and available by default).

By contrast, other tools that deal with OpenPGP tend to be complex, have many moving parts (including multiple processes, some of them long-running). 

## Setup

`oct-git` is designed specifically for use with the Git version control system, as a helper to perform OpenPGP signing and verification.
Users will typically not interact directly with `oct-git`, after an initial one-time setup.

### Configuring Git to use oct-git

To use `oct-git`, Git must be configured appropriately.

Most importantly, the binary that `git` calls for OpenPGP functionality must be configured:

```sh
git config --global gpg.program <path to oct-git>
```

Additionally, the OpenPGP key that `git` should use for signing must be configured.
This value can be set to the OpenPGP fingerprint of the signing component key, or the primary fingerprint of the key:

```sh
git config --global user.signingkey <fingerprint>
```

Once this basic setup is done, `git` can be instructed to sign every commit by default: 

```sh
git config --global commit.gpgsign true
```

And/or to sign every Git tag by default:

```sh
git config --global tag.gpgsign true
```

### User PINs: Configuring access to OpenPGP card devices

OpenPGP card devices require a User PIN to authorize private key operations (in the case of this tool: creating cryptographic signatures for git commits).

Access to OpenPGP card User PINs is handled indirectly, using the shared [openpgp-card-state](https://crates.io/crates/openpgp-card-state) infrastructure.

If you have already stored the User PIN for your card in openpgp-card-state, it can be used from `oct-git` immediately.
Otherwise, you can store the User PIN using `oct-git`, like this:

```
$ oct-git --store-card-pin
Found OpenPGP card 0000:01234567
  No User PIN is stored in openpgp-card-state
  Enter User PIN to store (or <Enter> to skip):
  User PIN has been stored in openpgp-card-state
```

The User PIN storage process in `oct-git` is interactive. For each connected OpenPGP card device, it checks if a valid PIN is already available in `openpgp-card-state`. If not, the user is prompted for the User PIN of that card.

## Signing

Signing requires that the User PIN for any OpenPGP card device has been configured via [openpgp-card-state](https://crates.io/crates/openpgp-card-state) (also see above).

## Verification

Verification of signatures automatically uses public keys from the local [openpgp-cert-d](https://crates.io/crates/openpgp-cert-d) "shared OpenPGP Certificate Directory".

If a public key is not present in the local openpgp-cert-d store, it is automatically downloaded from [keys.openpgp.org](https://keys.openpgp.org/) (the query does a lookup by signing key fingerprint).

### Limitation: verification "trust level"

`oct-git` currently doesn't display a "trust level" for signature verification. The "trust" concept in question is based on the *Web of Trust*, and requires configuration of "trust roots", as well as signature chains on which to perform "Web of Trust" evaluations.

This functionality [will be added in the future](https://codeberg.org/openpgp-card/tool-git/issues/2).

Until then, `oct-git` displays signatures with the "Unverified" trust level, since we don't currently have a basis for emitting more specific information.

This output means that the signature is cryptographically correct, and the fingerprint of the issuer is shown. However, no chain of trust to the signer is known.

## Internals

### Basic detached signing

```sh
oct-git -u SIGNING_KEY_FPR --detach-sign < Cargo.toml > Cargo.toml.sig
```

The `SIGNING_KEY_FPR` parameter must be set to the fingerprint of the *signing* subkey (not the certificate) in a hex-encoded format with *no* spaces (`0x` prefix is optional and removed during comparisons).

The fingerprint may be retrieved using `oct status` command.

### Signature verification

```sh
oct-git --verify Cargo.toml.sig - < Cargo.toml
```

# Funding

This project has been funded in part through [NGI Assure](https://nlnet.nl/assure), a fund established by [NLnet](https://nlnet.nl) with financial support from the European Commission's [Next Generation Internet](https://ngi.eu) program.

[<img src="https://nlnet.nl/image/logos/NGIAssure_tag.svg" alt="NGI Assure Logo" width="100px" />](https://nlnet.nl/assure)

---

🐒️🥯️
