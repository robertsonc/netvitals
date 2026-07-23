"""Tests for the hardened self-update in netquality.py — pure-stdlib RSA verify
(interoperating with openssl), manifest validation, version monotonicity, and
fail-closed install. Uses an ephemeral key and temp targets; the real netquality.py is
never touched."""
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netquality as nq  # noqa: E402

HAVE_OPENSSL = shutil.which("openssl") is not None
ARTIFACT_BODY = b'# Network Vitals\nMAGIC = 0x4E515632\n__version__ = "%s"\n'


def _canonical_manifest(version, sha256):
    return ('{"version":"%s","artifact":"netquality.py","sha256":"%s"}'
            % (version, sha256)).encode()


@unittest.skipUnless(HAVE_OPENSSL, "openssl not available")
class TestSignedUpdate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="nv-update-")
        cls.priv = os.path.join(cls.dir, "priv.pem")
        pub = os.path.join(cls.dir, "pub.pem")
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA",
                        "-pkeyopt", "rsa_keygen_bits:2048", "-out", cls.priv],
                       check=True, capture_output=True)
        subprocess.run(["openssl", "rsa", "-in", cls.priv, "-pubout", "-out", pub],
                       check=True, capture_output=True)
        with open(pub, encoding="utf-8") as fh:
            cls.pubkey = fh.read()
        cls._saved_key = nq.UPDATE_PUBKEY
        nq.UPDATE_PUBKEY = cls.pubkey          # verify against our ephemeral key

    @classmethod
    def tearDownClass(cls):
        nq.UPDATE_PUBKEY = cls._saved_key
        shutil.rmtree(cls.dir, ignore_errors=True)

    def _sign(self, data):
        msgf = os.path.join(self.dir, "m.bin")
        sigf = os.path.join(self.dir, "m.sig")
        with open(msgf, "wb") as fh:
            fh.write(data)
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", self.priv, "-out", sigf, msgf],
                       check=True, capture_output=True)
        with open(sigf, "rb") as fh:
            return fh.read()

    def _release(self, version, corrupt_sig=False, wrong_sha=False):
        rel = tempfile.mkdtemp(prefix="nv-rel-", dir=self.dir)
        art = ARTIFACT_BODY % version.encode()
        with open(os.path.join(rel, "netquality.py"), "wb") as fh:
            fh.write(art)
        sha = "0" * 64 if wrong_sha else hashlib.sha256(art).hexdigest()
        manifest = _canonical_manifest(version, sha)
        with open(os.path.join(rel, "manifest.json"), "wb") as fh:
            fh.write(manifest)
        sig = self._sign(manifest)
        if corrupt_sig:
            sig = sig[:-1] + bytes([sig[-1] ^ 0xFF])
        with open(os.path.join(rel, "manifest.json.sig"), "wb") as fh:
            fh.write(sig)
        return "file://" + os.path.join(rel, "manifest.json"), art

    def test_verify_roundtrip(self):
        msg = b"network vitals payload"
        sig = self._sign(msg)
        self.assertTrue(nq.verify_rsa_sha256(self.pubkey, msg, sig))
        self.assertFalse(nq.verify_rsa_sha256(self.pubkey, msg + b"!", sig))
        self.assertFalse(nq.verify_rsa_sha256(self.pubkey, msg, sig[:-1] + bytes([sig[-1] ^ 1])))

    def test_check_update_newer(self):
        url, _ = self._release("99.9.9")
        m = nq.check_update(url)
        self.assertIsNotNone(m)
        self.assertEqual(m["version"], "99.9.9")

    def test_check_update_not_newer_returns_none(self):
        url, _ = self._release("0.0.1")
        self.assertIsNone(nq.check_update(url))

    def test_bad_signature_fails_closed(self):
        url, _ = self._release("99.9.9", corrupt_sig=True)
        with self.assertRaises(RuntimeError):
            nq.check_update(url)

    def test_no_pubkey_fails_closed(self):
        url, _ = self._release("99.9.9")
        saved = nq.UPDATE_PUBKEY
        nq.UPDATE_PUBKEY = ""
        try:
            with self.assertRaises(RuntimeError):
                nq.check_update(url)
        finally:
            nq.UPDATE_PUBKEY = saved

    def test_install_happy_path(self):
        url, art = self._release("99.9.9")
        m = nq.check_update(url)
        target = os.path.join(self.dir, "installed.py")
        with open(target, "wb") as fh:
            fh.write(b"# old version\n")
        out = nq.download_and_install(m, url, target=target)
        self.assertEqual(out, target)
        with open(target, "rb") as fh:
            self.assertEqual(fh.read(), art)
        self.assertTrue(os.path.exists(target + ".bak"))

    def test_install_sha_mismatch_fails_closed(self):
        url, _ = self._release("99.9.9", wrong_sha=True)
        m = nq.check_update(url)              # signature is valid over the (wrong-sha) manifest
        target = os.path.join(self.dir, "keep.py")
        with open(target, "wb") as fh:
            fh.write(b"# keep me\n")
        with self.assertRaises(RuntimeError):
            nq.download_and_install(m, url, target=target)
        with open(target, "rb") as fh:
            self.assertEqual(fh.read(), b"# keep me\n")   # untouched


class TestManifestParsing(unittest.TestCase):
    def test_valid(self):
        m = nq._parse_manifest(_canonical_manifest("1.2.3", "a" * 64))
        self.assertEqual(m["version"], "1.2.3")

    def test_missing_field(self):
        with self.assertRaises(RuntimeError):
            nq._parse_manifest(b'{"version":"1.0.0","artifact":"netquality.py"}')

    def test_bad_sha(self):
        with self.assertRaises(RuntimeError):
            nq._parse_manifest(_canonical_manifest("1.0.0", "xyz"))

    def test_wrong_artifact(self):
        with self.assertRaises(RuntimeError):
            nq._parse_manifest(b'{"version":"1.0.0","artifact":"evil.py","sha256":"%s"}'
                               % (b"a" * 64))

    def test_version_tuple(self):
        self.assertEqual(nq._ver_tuple("1.6.2"), (1, 6, 2))
        self.assertIsNone(nq._ver_tuple("none"))
        self.assertLess(nq._ver_tuple("1.6.2"), nq._ver_tuple("1.7.0"))


if __name__ == "__main__":
    unittest.main()
