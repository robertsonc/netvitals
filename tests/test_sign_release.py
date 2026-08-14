"""Behaviour tests for tools/sign_release.sh.

The script produces the bytes clients verify, and the agentic release flow drives
it unattended, so its failure modes matter as much as its happy path - especially
"a failed signing must not leave a signature behind", which callers rely on.

Everything runs against a throwaway 2048-bit key generated per class; the real
release key is never involved. The artifact is a stub - the script only reads
`^__version__` out of it.

Skipped on Windows: the script is bash and the release runbooks call for a POSIX
signing host. On macOS the suite additionally runs it under /bin/bash, which is
3.2 there - the version the script's "two spellings rather than an array" comment
exists for.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO, "tools", "sign_release.sh")
PASSPHRASE = "correct horse battery staple"

# Every subprocess is bounded. A pass-phrase source the script fails to reject can
# reach openssl and block on a prompt forever (`stdin:` does exactly that), and a
# hung CI job is worse than a failing one.
TIMEOUT = 60


def _openssl(*args, **kw):
    kw.setdefault("timeout", TIMEOUT)
    return subprocess.run(("openssl",) + args, capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, **kw)


@unittest.skipIf(sys.platform == "win32", "sign_release.sh is bash; signing hosts are POSIX")
@unittest.skipUnless(shutil.which("openssl"), "openssl not available")
@unittest.skipUnless(os.path.exists(SCRIPT), "tools/sign_release.sh not present")
class SignReleaseTest(unittest.TestCase):
    """One throwaway keypair for the whole class - keygen is the slow part."""

    bash = "bash"

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="nv-sign-test-")
        cls.key = os.path.join(cls.tmp, "test_priv.pem")
        cls.pub = os.path.join(cls.tmp, "test_pub.pem")   # sibling name the script derives
        r = _openssl("genrsa", "-aes256", "-passout", f"pass:{PASSPHRASE}",
                     "-out", cls.key, "2048")
        assert r.returncode == 0, r.stderr
        r = _openssl("rsa", "-in", cls.key, "-passin", f"pass:{PASSPHRASE}",
                     "-pubout", "-out", cls.pub)
        assert r.returncode == 0, r.stderr

        # A second, unrelated keypair - for the "self-verify catches a mismatched
        # public key" case.
        cls.other_key = os.path.join(cls.tmp, "other_priv.pem")
        cls.other_pub = os.path.join(cls.tmp, "other_pub.pem")
        _openssl("genrsa", "-out", cls.other_key, "2048")
        _openssl("rsa", "-in", cls.other_key, "-pubout", "-out", cls.other_pub)

        cls.passfile = os.path.join(cls.tmp, "passfile")
        cls._write(cls.passfile, PASSPHRASE + "\n", 0o600)
        cls.loose = os.path.join(cls.tmp, "loose")
        cls._write(cls.loose, PASSPHRASE + "\n", 0o644)
        cls.wrong = os.path.join(cls.tmp, "wrong")
        cls._write(cls.wrong, "not the passphrase\n", 0o600)
        cls.empty = os.path.join(cls.tmp, "empty")
        cls._write(cls.empty, "", 0o600)

        cls.artifact = os.path.join(cls.tmp, "netquality.py")
        cls._write(cls.artifact, '__version__ = "9.9.9"\nprint("stub")\n', 0o644)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @staticmethod
    def _write(path, text, mode):
        with open(path, "w") as fh:
            fh.write(text)
        os.chmod(path, mode)

    def sign(self, version="9.9.9", passin=None, key=None, artifact=None,
             outdir=None, extra_env=None, args=None):
        """Run the script; returns (CompletedProcess, outdir)."""
        out = outdir or tempfile.mkdtemp(dir=self.tmp)
        env = dict(os.environ)
        env.pop("NV_RELEASE_PASSIN", None)
        env.pop("NV_RELEASE_PUB", None)
        if passin is not None:
            env["NV_RELEASE_PASSIN"] = passin
        if extra_env:
            env.update(extra_env)
        argv = args if args is not None else [
            version, artifact or self.artifact, key or self.key, out]
        try:
            r = subprocess.run([self.bash, SCRIPT] + argv,
                               capture_output=True, text=True, env=env, cwd=REPO,
                               stdin=subprocess.DEVNULL, timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            self.fail(f"sign_release.sh hung for {TIMEOUT}s (passin={passin!r}) - "
                      f"a pass-phrase source that reaches openssl unvalidated can "
                      f"block on a prompt")
        return r, out

    # --- happy paths -----------------------------------------------------

    def test_signs_with_file_passin(self):
        r, out = self.sign(passin=f"file:{self.passfile}")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Verified OK", r.stdout + r.stderr)
        for name in ("netquality.py", "manifest.json", "manifest.json.sig"):
            self.assertTrue(os.path.exists(os.path.join(out, name)), name)

    def test_signs_with_env_passin(self):
        r, out = self.sign(passin="env:NV_TEST_PASS",
                           extra_env={"NV_TEST_PASS": PASSPHRASE})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(os.path.join(out, "manifest.json.sig")))

    def test_manifest_is_canonical(self):
        """Fixed key order, no trailing newline - the signed bytes must be stable."""
        _, out = self.sign(passin=f"file:{self.passfile}")
        with open(os.path.join(out, "manifest.json"), "rb") as fh:
            raw = fh.read()
        self.assertFalse(raw.endswith(b"\n"))
        self.assertTrue(raw.startswith(b'{"version":"9.9.9","artifact":"netquality.py"'))
        self.assertEqual(json.loads(raw)["version"], "9.9.9")

    def test_manifest_sha256_matches_artifact(self):
        import hashlib
        _, out = self.sign(passin=f"file:{self.passfile}")
        with open(os.path.join(out, "netquality.py"), "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        with open(os.path.join(out, "manifest.json")) as fh:
            self.assertEqual(json.load(fh)["sha256"], digest)

    def test_signature_verifies_against_public_key(self):
        _, out = self.sign(passin=f"file:{self.passfile}")
        r = _openssl("dgst", "-sha256", "-verify", self.pub,
                     "-signature", os.path.join(out, "manifest.json.sig"),
                     os.path.join(out, "manifest.json"))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_signing_is_deterministic(self):
        """RSA PKCS#1 v1.5 - the same inputs must reproduce the same signature."""
        _, a = self.sign(passin=f"file:{self.passfile}")
        _, b = self.sign(passin=f"file:{self.passfile}")
        with open(os.path.join(a, "manifest.json.sig"), "rb") as fh:
            sig_a = fh.read()
        with open(os.path.join(b, "manifest.json.sig"), "rb") as fh:
            sig_b = fh.read()
        self.assertEqual(sig_a, sig_b)

    # --- pass-phrase source validation -----------------------------------

    def test_no_passin_does_not_hang(self):
        """Unset, openssl prompts; with no TTY that must fail, not block."""
        r, out = self.sign(passin=None)
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(os.path.exists(os.path.join(out, "manifest.json.sig")))

    def test_missing_passfile_is_named(self):
        r, _ = self.sign(passin="file:/nonexistent/passfile")
        self.assertEqual(r.returncode, 1)
        self.assertIn("cannot read", r.stderr)

    def test_empty_passfile_is_named(self):
        r, _ = self.sign(passin=f"file:{self.empty}")
        self.assertEqual(r.returncode, 1)
        self.assertIn("is empty", r.stderr)

    def test_unset_env_var_is_named(self):
        r, _ = self.sign(passin="env:NV_DEFINITELY_UNSET")
        self.assertEqual(r.returncode, 1)
        self.assertIn("unset or empty", r.stderr)

    def test_unsupported_scheme_is_rejected(self):
        r, _ = self.sign(passin="stdin:")
        self.assertEqual(r.returncode, 1)
        self.assertIn("unsupported source", r.stderr)

    def test_loose_passfile_warns_but_signs(self):
        r, out = self.sign(passin=f"file:{self.loose}")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("readable beyond its owner", r.stderr)
        self.assertTrue(os.path.exists(os.path.join(out, "manifest.json.sig")))

    def test_tight_passfile_does_not_warn(self):
        r, _ = self.sign(passin=f"file:{self.passfile}")
        self.assertNotIn("readable beyond its owner", r.stderr)

    # --- failure must not leave a signature behind -----------------------

    def test_wrong_passphrase_discards_signature(self):
        """openssl truncates -out before loading the key; the script must clean up.
        Callers rely on: no "Verified OK" means no signature file."""
        r, out = self.sign(passin=f"file:{self.wrong}")
        self.assertEqual(r.returncode, 1)
        self.assertIn("signing failed", r.stderr)
        self.assertFalse(os.path.exists(os.path.join(out, "manifest.json.sig")))

    def test_mismatched_public_key_discards_signature(self):
        """The self-verify step is the last gate before anyone publishes."""
        r, out = self.sign(passin=f"file:{self.passfile}",
                           extra_env={"NV_RELEASE_PUB": self.other_pub})
        self.assertEqual(r.returncode, 1)
        self.assertIn("does not verify", r.stderr)
        self.assertFalse(os.path.exists(os.path.join(out, "manifest.json.sig")))

    # --- argument and input guards ---------------------------------------

    def test_version_mismatch_refuses(self):
        r, out = self.sign(version="1.2.3")
        # Refused before any signing is attempted.
        self.assertEqual(r.returncode, 1)
        self.assertIn("refusing", r.stderr)
        self.assertFalse(os.path.exists(os.path.join(out, "manifest.json.sig")))

    def test_missing_artifact_refuses(self):
        r, _ = self.sign(passin=f"file:{self.passfile}",
                         artifact=os.path.join(self.tmp, "nope.py"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("artifact not found", r.stderr)

    def test_missing_key_refuses(self):
        r, _ = self.sign(passin=f"file:{self.passfile}",
                         key=os.path.join(self.tmp, "nope.pem"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("private key not found", r.stderr)

    def test_too_few_args_exits_2(self):
        r, _ = self.sign(args=["9.9.9"])
        self.assertEqual(r.returncode, 2)
        self.assertIn("usage:", r.stderr)


@unittest.skipUnless(sys.platform == "darwin", "bash 3.2 is the macOS system shell")
@unittest.skipUnless(os.path.exists("/bin/bash"), "/bin/bash not present")
class SignReleaseBash32Test(SignReleaseTest):
    """Re-run everything under /bin/bash.

    On macOS that is 3.2, where `set -u` makes expanding an empty array an error -
    the reason the script spells the two openssl invocations out longhand instead.
    """

    bash = "/bin/bash"


if __name__ == "__main__":
    unittest.main()
