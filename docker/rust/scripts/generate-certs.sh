#!/bin/bash
# NextGCore TLS Certificate Generation Script (G36)
#
# Kept for existing callers. The dev SBI PKI has ONE generator,
# docker/rust/certs/generate-dev-certs.sh: it issues each NF the TS 33.310
# §6.1.3c.3 profile (URI SAN urn:uuid:<nfInstanceId> plus RFC 9310 NFTypes,
# from docker/rust/certs/nf-identities.txt) that the NRF binds registration
# to (#1611, #1617). This script used to issue its own, different profile
# (DNS SANs only, no extendedKeyUsage).
#
# Usage:
#   ./generate-certs.sh                    # Generate all certs in docker/rust/certs/
#                                          # (resolved from this script, not the cwd)
#   ./generate-certs.sh /custom/output/dir # Generate in custom directory

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$SCRIPT_DIR/../certs/generate-dev-certs.sh" --out "${1:-$SCRIPT_DIR/../certs}"
