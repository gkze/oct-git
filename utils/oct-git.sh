#!/bin/sh
# SPDX-FileCopyrightText: Robin Krahl <robin.krahl@ireas.org>
# SPDX-License-Identifier: CC0-1.0
root=`dirname "$0"`
exec cargo run --manifest-path "$root/../Cargo.toml" --quiet -- $@
