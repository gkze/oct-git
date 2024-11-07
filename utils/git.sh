#!/bin/sh
# SPDX-FileCopyrightText: Robin Krahl <robin.krahl@ireas.org>
# SPDX-License-Identifier: CC0-1.0

root=`dirname "$0"`

export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0=gpg.program
export GIT_CONFIG_VALUE_0="$root/oct-git.sh"

exec git $@
