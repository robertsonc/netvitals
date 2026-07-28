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
# If the private key is passphrase-protected (it should be), openssl prompts for it here.
# After signing, the result is verified against the matching public key - the sibling
# *_pub.pem next to the private key, or $NV_RELEASE_PUB.
#
# Unattended signing: set NV_RELEASE_PASSIN to an openssl pass-phrase source and no prompt
# is issued, so this runs where there is no TTY (an agent session, a batch of releases).
# The value is passed straight to openssl -passin; see openssl-passphrase-options(1).
#
#   NV_RELEASE_PASSIN=file:/path/to/passfile   tools/sign_release.sh ...   # preferred
#   NV_RELEASE_PASSIN=env:MY_VAR               tools/sign_release.sh ...
#
# Prefer file: with a mode-600 file. Do NOT use pass:LITERAL - the passphrase lands in this
# script's environment AND in openssl's argv, where any local user can read it out of ps.
# Whatever the source, the passphrase is then only as protected as the account it lives on:
# an encrypted key guards against theft of the key file, not against code running as you.
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

# Optional unattended pass-phrase source (see the header). Fail early with a useful message
# rather than letting openssl fall through to a prompt that has no TTY to talk to.
PASSIN="${NV_RELEASE_PASSIN:-}"
if [ -n "$PASSIN" ]; then
  case "$PASSIN" in
    file:*)
      PASSFILE="${PASSIN#file:}"
      [ -r "$PASSFILE" ] || { echo "NV_RELEASE_PASSIN: cannot read $PASSFILE" >&2; exit 1; }
      [ -s "$PASSFILE" ] || { echo "NV_RELEASE_PASSIN: $PASSFILE is empty" >&2; exit 1; }
      # Not fatal - the key is still encrypted - but a pass-phrase file the whole box can
      # read defeats the point of encrypting it.
      MODE=$(stat -c '%a' "$PASSFILE" 2>/dev/null || stat -f '%Lp' "$PASSFILE" 2>/dev/null || echo "")
      case "$MODE" in
        ''|[0-7]00) ;;                                  # unknown, or owner-only
        *) echo "warning: $PASSFILE is mode $MODE, readable beyond its owner; expected 600" >&2 ;;
      esac
      ;;
    env:*)
      VARNAME="${PASSIN#env:}"
      [ -n "${!VARNAME:-}" ] || { echo "NV_RELEASE_PASSIN: \$$VARNAME is unset or empty" >&2; exit 1; }
      ;;
    pass:*)
      echo "warning: NV_RELEASE_PASSIN=pass:... exposes the pass phrase in ps; prefer file:" >&2
      ;;
    *)
      echo "NV_RELEASE_PASSIN: unsupported source '${PASSIN%%:*}:' (use file: or env:)" >&2
      exit 1
      ;;
  esac
fi

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

# Two spellings rather than an array, so this keeps working under `set -u` on bash 3.2
# (macOS), where expanding an empty array is an error.
sign_manifest() {
  if [ -n "$PASSIN" ]; then
    openssl dgst -sha256 -passin "$PASSIN" -sign "$KEY" -out "$OUT/manifest.json.sig" "$OUT/manifest.json"
  else
    openssl dgst -sha256 -sign "$KEY" -out "$OUT/manifest.json.sig" "$OUT/manifest.json"
  fi
}

# openssl truncates -out before it loads the key, so a failure here (wrong pass phrase,
# unreadable key) leaves an empty manifest.json.sig behind. Discard it: "no Verified OK
# means no signature file" is the invariant callers rely on.
if ! sign_manifest; then
  rm -f "$OUT/manifest.json.sig"
  echo "refusing: signing failed - wrong pass phrase or unusable key (nothing written)" >&2
  exit 1
fi

# Verify what we just produced, before anyone publishes it. Prefer a public key FILE: it
# needs no passphrase, and checking against the same key material that is embedded in the
# app is the property that actually matters. Default to the sibling *_pub.pem next to the
# private key; override with NV_RELEASE_PUB.
PUB="${NV_RELEASE_PUB:-${KEY%priv.pem}pub.pem}"
if [ -f "$PUB" ]; then
  if ! openssl dgst -sha256 -verify "$PUB" -signature "$OUT/manifest.json.sig" "$OUT/manifest.json"; then
    rm -f "$OUT/manifest.json.sig"
    echo "refusing: signature does not verify against $PUB (signature discarded)" >&2
    exit 1
  fi
  echo "  verified against $PUB"
else
  echo "note: no public key at $PUB, skipping the self-check. Verify manually:" >&2
  echo "  openssl dgst -sha256 -verify <(openssl rsa -in $KEY -pubout 2>/dev/null) \\" >&2
  echo "    -signature $OUT/manifest.json.sig $OUT/manifest.json" >&2
fi

echo
echo "Signed release written to $OUT/"
echo "  version : $VERSION"
echo "  sha256  : $SHA"
echo "  files   : netquality.py  manifest.json  manifest.json.sig"
echo
echo "Publish all three as the GitHub release assets for v$VERSION."
