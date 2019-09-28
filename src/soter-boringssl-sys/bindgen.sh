#!/bin/bash

# Copyright 2018 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

set -e

if [ $# -ne 3 ]; then
    echo "Usage: $0 <major> <minor> <patch>" >&2
    exit 1
fi

MAJOR="$1"
MINOR="$2"
PATCH="$3"

# Only include the symbols we want. It's important that we take the minimum dependency
# on BoringSSL since we're not Google and if they decide to introduce breaking changes
# then we'd better not be affected by them. Instead of whitelisting broad classes of
# symbols, explicitly whitelist the exact list what we depend on.

# When https://github.com/rust-lang-nursery/rust-bindgen/issues/1375 is resolved,
# bindgen should be able to handle prefixed symbols natively and we would not need
# most of this file.

# Split the whitelist into function names and other symbols, in order to use the
# former for a consistency check of the postprocessing step which adds the
# #[link_name...] attributes.
WHITELIST_FUNCS="$(awk  'BEGIN { first = 1 }  /[()]{2}$/ {if (!first) printf "|"; first = 0; printf "%s", substr($0, 0, length($0) - 2)}' whitelist.txt)"
WHITELIST_OTHERS="$(awk 'BEGIN { first = 1 } /[^()]{2}$/ {if (!first) printf "|"; first = 0; printf "%s", $0}' whitelist.txt)"
WHITELIST="(${WHITELIST_FUNCS}|${WHITELIST_OTHERS})"

# Currently, we don't pass --target since none of the symbols we're linking against
# are architecture-specific (TODO: are any of them word-size-specific?).
# If this ever becomes a problem, then the thing to do is to split the generated
# code into different files for different platforms (like boringssl_x86_64.rs,
# boringssl_arm64.rs, etc.) and conditionally compile them depending on target.
bindgen bindgen.h \
    --whitelist-function "$WHITELIST" \
    --whitelist-type "$WHITELIST" \
    --output src/lib.rs \
    -- \
    -I ./boringssl/include

TMP="$(mktemp)"

# Prepend copyright comment, #[allow] for various warnings we don't care about,
# and a line telling Rust to link against our libcrypto.
(cat <<'EOF'
// Copyright 2019 themis.rs maintainers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Raw FFI bindings to Soter's BoringSSL.

#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
// Some symbols are only used with certain features enabled, so we need
// to suppress the unused warning when those features aren't enabled.
#![allow(unused)]

EOF

# Do this on a separate line because we need string interpolation, but we can't
# use string interpolation in the preceding 'cat' command, or else the !
# characters would be interpreted.
echo "#[link(name = \"soter_crypto_${MAJOR}_${MINOR}_${PATCH}\")] extern {}"
echo

cat src/lib.rs) \
| rustfmt \
| (
# Postprocess the generated bindings, adding the "#[link_name ...]"
# attribute to exported functions. Since the function sites are matched
# lexically, check the consistency of matches against the list of function
# names defined above. An error will be returned if a) a matched function
# is not in the whitelist, b) a name from the whitelist wasn't matched
# in the input, or c) a name was matched more than once (which should
# never happen).
awk -v "vers=${MAJOR}_${MINOR}_${PATCH}_" -v "funcs=${WHITELIST_FUNCS}" '
BEGIN {
    split(funcs, fa, "[|]")
    for (fn in fa)
        f[fa[fn]]
}
/extern "C" {/ {
    print
    getline
    if ($0 ~ "#[[]link_name")
        getline
    if ($0 ~ "pub fn") {
        fn = $3
        sub("[(].*", "", fn)
        if (!(fn in f)) {
            print "fatal: fn not in whitelist: " fn | "cat >&2"
            exit 1
        } else
            f[fn]++
        print "    #[link_name = \"__SOTER_BORINGSSL_" vers fn "\"]"
    }
}
{ print }
END {
    for (fn in f)
        if (f[fn] != 1) {
            print "fatal: fn match count = " f[fn] + 0 ", should be 1: " fn | "cat >&2"
            exit 1
        }
}') > "$TMP"
mv "$TMP" src/lib.rs
