#!/usr/bin/env bash
# Regenerate the TLS fixtures for runner/tests/bridge_tls.rs. Test-only material:
# every key here is committed on purpose and must never be used for anything else.
#
#   ca        — the trust anchor banking pins (10 years)
#   server    — what the bridge listener presents; SAN localhost/concierge/127.0.0.1 (5 years)
#   client    — a money-plane identity signed by `ca`, for the mTLS tests (5 years)
#   other-ca  — an unrelated CA, so a peer trusting or presenting the wrong root is refused
#   other-client — signed by `other-ca`; presented to an mTLS listener it must be refused
set -euo pipefail
cd "$(dirname "$0")"

gen_key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"; }

ca() {
	local name="$1" cn="$2"
	gen_key "$name.key"
	openssl req -x509 -new -key "$name.key" -days 3650 -subj "/CN=$cn" \
		-addext "basicConstraints=critical,CA:TRUE" \
		-addext "keyUsage=critical,keyCertSign,cRLSign" \
		-out "$name.pem"
}

leaf() {
	local name="$1" cn="$2" ca="$3" ext="$4"
	gen_key "$name.key"
	openssl req -new -key "$name.key" -subj "/CN=$cn" -out "$name.csr"
	openssl x509 -req -in "$name.csr" -CA "$ca.pem" -CAkey "$ca.key" -CAcreateserial \
		-days 1825 -extfile <(printf '%s\n' "$ext") -out "$name.pem"
	rm -f "$name.csr" "$ca.srl"
}

ca ca "concierge bridge test CA"
ca other-ca "unrelated test CA"

leaf server concierge ca $'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,DNS:concierge,IP:127.0.0.1'
leaf client piggybank ca $'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth'
leaf other-client impostor other-ca $'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth'

# The CA keys exist only to sign the leaves above; nothing in the tests needs them.
rm -f ca.key other-ca.key
