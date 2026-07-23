# Update security

Network Vitals can replace its own `netquality.py` in place (`--update`, the GUI's
"Install and restart", `update.bat`). That makes the update path a **code-execution
channel**: a compromised update runs as the user on every machine that updates. This
document describes how that channel is hardened so it **fails closed**.

## What changed

The previous updater fetched the **raw, mutable tip of `main`** over `urllib` and, before
overwriting itself, checked only: TLS cert (host auth), an https→http downgrade guard,
`compile()` success, a `"MAGIC"`/`"Network Vitals"` substring, and `remote_version >
local_version`. **None of those authenticate the code** — any well-formed file (valid
Python + the two strings + a higher version) passed every gate and executed. The source
was also overridable at runtime via `--update-url`, so anyone who could edit the shortcut
pointed the updater at their own valid-TLS host.

Now releases are **signed offline** and verified before anything is written.

## The model

The app embeds a **public key** (`UPDATE_PUBKEY` in `netquality.py`) and verifies every
update against it. A release is three files, published at the pinned `UPDATE_URL` location
(the GitHub release):

| file | contents |
|---|---|
| `netquality.py` | the artifact clients install |
| `manifest.json` | canonical `{"version","artifact","sha256"}` (no trailing newline) |
| `manifest.json.sig` | RSA-2048 / SHA-256 PKCS#1 v1.5 **detached signature over `manifest.json`** |

### Update flow (every step fails closed)

1. Fetch `manifest.json` + `manifest.json.sig` from `UPDATE_URL` (the Windows
   certificate-store fallback for TLS-inspecting proxies is preserved; the https→http
   downgrade is refused; responses are size-bounded).
2. **Verify the signature** over the exact manifest bytes with the embedded public key
   (strict PKCS#1 v1.5, full-block compare). Invalid/missing ⇒ **refuse**.
3. Enforce **monotonic version** (no signed-but-old rollback).
4. Fetch the artifact and check its **SHA-256** against the (signed) manifest ⇒ otherwise
   refuse. As corruption-only sanity checks (never trust), it must also `compile()` and
   contain the app's magic strings.
5. Install atomically: write `.new`, keep the current file as `.bak`, `os.replace`.
6. **Re-verify the on-disk bytes** before relaunch — closes the fetch→exec TOCTOU.

`--update-url` is still accepted (a fork can repoint it), but the signature is **always**
required against the built-in key, so a foreign URL cannot serve accepted code without the
matching private key. If no public key is configured, the updater **refuses**.

### Verifier

Verification is **pure Python standard library** (no third-party crypto): RSA verification
is modular exponentiation with the public exponent, and PKCS#1 v1.5 signature verification
is a strict comparison against the fully reconstructed padded block. It interoperates with
`openssl dgst -sha256 -sign` output (proven by `tests/test_update.py`).

## Signing a release

On the trusted machine that holds the private key:

```
tools/sign_release.sh <version> path/to/netquality.py ~/.config/netvitals/netvitals_release_priv.pem release/
```

openssl prompts for the key passphrase. The script then verifies its own signature against
the matching public key (the sibling `*_pub.pem`, or `$NV_RELEASE_PUB`) and discards the
signature if it does not check out. Publish `release/netquality.py`,
`release/manifest.json`, and `release/manifest.json.sig` as the GitHub release assets for
that version — the pinned `UPDATE_URL` resolves to the *latest* release, so a release is
only live for clients once all three assets are attached.

## Key management

- **Generate** a release keypair once, on a trusted machine, passphrase-protected:
  ```
  mkdir -p ~/.config/netvitals && chmod 700 ~/.config/netvitals
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -aes-256-cbc \
    -out ~/.config/netvitals/netvitals_release_priv.pem
  chmod 600 ~/.config/netvitals/netvitals_release_priv.pem
  openssl rsa -in ~/.config/netvitals/netvitals_release_priv.pem \
    -pubout -out ~/.config/netvitals/netvitals_release_pub.pem
  ```
  Keep the key **outside the repo** — `.gitignore` also blocks `*.pem` as a backstop, but
  the real protection is that it never lives in the working tree. Back up the private key
  and its passphrase separately (password manager / offline media): losing either means you
  can no longer ship an update that existing installs will accept, and the only recovery is
  re-installing every client by hand.
- **Embed** the public key: paste the contents of `netvitals_release_pub.pem` into
  `UPDATE_PUBKEY` in `netquality.py`. The public key is safe to commit; **the private key
  must never be committed.**
- **Rotation / compromise.** Clients trust exactly the key compiled into the copy they are
  running, so a new key only reaches them via an update signed with the *old* one. To
  rotate: embed the new public key, sign that release with the old private key, let it roll
  out, and only then sign with the new key. If the private key leaks there is no revocation
  path in this design — anyone holding it can sign an update every client will execute, so
  treat a leak as requiring a manually distributed build.
- **Verifying what a client will trust**, without the private key:
  ```
  openssl dgst -sha256 -verify ~/.config/netvitals/netvitals_release_pub.pem \
    -signature release/manifest.json.sig release/manifest.json
  ```
