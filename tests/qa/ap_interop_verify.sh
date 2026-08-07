#!/usr/bin/env bash
# Independently verify a Keycast-produced RSA-SHA256 signature with openssl.
# Catches SPKI-vs-PKCS1 PEM and PKCS1v15-vs-PSS algorithm mistakes that a
# same-library round-trip cannot.
set -euo pipefail

cd "$(dirname "$0")/../.."   # repo root

cargo test -p keycast_core -- emit_interop_vector --include-ignored

# Locate the emitted vector (cargo may place it under workspace or crate target).
DIR=$(dirname "$(find . -path '*ap_interop/pub.pem' -print -quit)")
if [ -z "$DIR" ]; then echo "FAIL: interop vector not found"; exit 1; fi
echo "Using vector dir: $DIR"

openssl dgst -sha256 -verify "$DIR/pub.pem" -signature "$DIR/sig.bin" "$DIR/msg.bin"
# Expected output: "Verified OK"
