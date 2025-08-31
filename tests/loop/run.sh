#!/bin/bash
set -euxo pipefail

# expect algorithm parameter for OCT
ALGO=$1

IDENT=0000:00000000

## --------------------------------------------------------------------------
##  set up a card, configure git to use oct-git, add signer's cert to cert-d
## --------------------------------------------------------------------------

OCT=oct

# build project
cargo build --release
OCT_GIT=$(pwd)/target/release/oct-git

# initialize card
$OCT admin -c "$IDENT" -P /dev/fd/3 generate -u "<alice@example.org>" -p /dev/fd/4 --output alice.cert "$ALGO" 3<<<12345678 4<<<123456
FP=$($OCT status | grep -A 1 "Signature key" | grep Fingerprint | sed "s/  Fingerprint: //" | sed s/\ //g)

$OCT status

# configure git
git config --global user.email "alice@example.com"
git config --global user.name "Alice"

git config --global gpg.program "$OCT_GIT"
git config --global user.signingkey "$FP"
git config --global commit.gpgsign true

# import alice.cert into cert-d
FP_LOWER=$(echo "$FP" | tr '[:upper:]' '[:lower:]')
one="${FP_LOWER:0:2}"
two="${FP_LOWER:2:40}"

mkdir -p ~/.local/share/pgp.cert.d/"$one"
cp alice.cert ~/.local/share/pgp.cert.d/"$one"/"$two"

# openpgp-card-state configuration
mkdir -p ~/.config/openpgp-card-state
cp tests/loop/config.toml ~/.config/openpgp-card-state


## -----------------
##  run signer loop
## -----------------

tests/loop/loop.sh
