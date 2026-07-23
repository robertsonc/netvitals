#!/usr/bin/env bash
#
# sign_release.sh — produce a SIGNED Network Vitals release.
#
# Run this on a TRUSTED, OFFLINE machine that holds the release private key. The private
# key must NEVER be committed. The app ships only the matching PUBLIC key (embedded as
# UPDATE_PUBKEY in netquality.py) and refuses any update whose manifest signature does not
# verify against it (fail closed). See docs/UPDATE_SECURITY.md.
#
# Usage:
#   tools/sign_release.sh <version> <path/to/netquality.py> <private-key.pem> [outdir]
#
# Produces in <outdir> (default: ./release):
#   netquality.py        the artifact clients download
#   manifest.json        {version, artifact, sha256}   (canonical, no trailing newline)
#   manifest.json.sig    RSA-2048 / SHA-256 PKCS#1 v1.5 detached signature over manifest.json
#
# Publish all three as the GitHub release assets at the pinned UPDATE_URL location.
#
set -euo pipefail

if [ "$#" -lt 3 ]; then
  echo "usage: $0 <version> <path/to/netquality.py> <private-key.pem> [outdir]" >&2
  exit 2
fi

VERSION="$1"
ARTIFACT="$2"
KEY="$3"
OUT="${4:-release}"

command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }
[ -f "$ARTIFACT" ] || { echo "artifact not found: $ARTIFACT" >&2; exit 1; }
[ -f "$KEY" ] || { echo "private key not found: $KEY" >&2; exit 1; }

# Sanity: the version being signed must match the artifact's __version__.
FILE_VER=$(grep -oE '^__version__[[:space:]]*=[[:space:]]*"[^"]+"' "$ARTIFACT" | head -1 | sed 's/.*"\(.*\)".*/\1/')
if [ "$FILE_VER" != "$VERSION" ]; then
  echo "refusing: --version=$VERSION but the artifact declares __version__=$FILE_VER" >&2
  exit 1
fi

mkdir -p "$OUT"
cp "$ARTIFACT" "$OUT/netquality.py"

SHA=$(openssl dgst -sha256 -r "$OUT/netquality.py" | awk '{print $1}')

# Canonical manifest: fixed key order, no trailing newline, so the signed bytes are stable.
printf '{"version":"%s","artifact":"netquality.py","sha256":"%s"}' "$VERSION" "$SHA" > "$OUT/manifest.json"

openssl dgst -sha256 -sign "$KEY" -out "$OUT/manifest.json.sig" "$OUT/manifest.json"

echo "Signed release written to $OUT/"
echo "  version : $VERSION"
echo "  sha256  : $SHA"
echo "  files   : netquality.py  manifest.json  manifest.json.sig"
echo
echo "Verify locally before publishing:"
echo "  openssl dgst -sha256 -verify <(openssl rsa -in $KEY -pubout 2>/dev/null) \\"
echo "    -signature $OUT/manifest.json.sig $OUT/manifest.json"
