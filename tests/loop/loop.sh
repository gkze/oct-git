#!/bin/bash
set -euo pipefail

# number of commits we'll make after the initial commit
COUNT=99

TESTDIR=$(mktemp -d)
cd "$TESTDIR"

# set up project, add a file and make an initial commit
git init
touch README
git add README
git commit -m "initial"

# make "COUNT" additional commits
for i in $(seq 1 $COUNT);
do
    echo -n "1" >> README
    git commit -a -m "commit"
#    echo "$i"
done

echo

# count valid signatures in the project
SIGNATURES=$(git log --show-signature | grep -c "Signing key: ")

if [ "$SIGNATURES" == "$((COUNT+1))" ]; then
    echo "Found the expected number of signed commits: $SIGNATURES"
else
    echo "ERROR: unexpected number of signatures: $SIGNATURES" && exit 1
fi
