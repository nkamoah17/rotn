# -*- coding: utf-8 -*-
"""Tests for the pure-stdlib Ed25519 signer/verifier (:mod:`rot.ed25519`).

The requirement (GAP 3): a **zero-dependency** Ed25519 implementation so
``pip install rotn`` signs and verifies real asymmetric attestations out of
the box -- no ``cryptography`` package.  These tests pin the contract:

  * **RFC 8032 vectors** -- the three published test vectors are reproduced
    byte-for-byte (public key from seed, signature, and verification), which
    proves the field/curve math is correct;
  * **API** -- key generation, seed determinism, sign determinism, and
    rejection of a wrong key / tampered message / tampered signature /
    invalid public key;
  * **PEM (RFC 8410)** -- private/public keys round-trip in the standard
    PEM forms, so a key from OpenSSL / ``cryptography`` / ROTN is
    interchangeable;
  * **zero-dependency** -- the module never imports ``cryptography``.

Run: python tests/test_ed25519.py
"""

import inspect
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.ed25519 as ed  # noqa: E402


def _h(hexstr):
    """Decode a lowercase hex string to bytes."""
    return bytes.fromhex(hexstr)


# RFC 8032, section 7.1 -- the three published Ed25519 test vectors.
_RFC8032 = [
    {
        "seed": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "public": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "message": "",
        "signature": "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    },
    {
        "seed": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "public": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "message": "72",
        "signature": "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    },
    {
        "seed": "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "public": "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "message": "af82",
        "signature": "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    },
]


class Rfc8032VectorTests(unittest.TestCase):
    """The RFC 8032 published vectors must be reproduced byte-for-byte."""

    def test_public_key_from_seed(self):
        for i, vec in enumerate(_RFC8032):
            seed = _h(vec["seed"])
            self.assertEqual(
                ed.public_key_from_seed(seed).hex(), vec["public"],
                "vector %d: public key mismatch" % (i + 1))

    def test_sign_matches_rfc(self):
        for i, vec in enumerate(_RFC8032):
            seed = _h(vec["seed"])
            message = _h(vec["message"])
            sig = ed.sign(seed, message)
            self.assertEqual(
                sig.hex(), vec["signature"],
                "vector %d: signature mismatch" % (i + 1))

    def test_verify_accepts_rfc(self):
        for i, vec in enumerate(_RFC8032):
            point = _h(vec["public"])
            sig = _h(vec["signature"])
            message = _h(vec["message"])
            ed.verify(point, sig, message)  # must NOT raise


class ApiTests(unittest.TestCase):
    """The public API: key generation, determinism, and rejection."""

    def test_generate_keypair_shape(self):
        seed, point = ed.generate_keypair()
        self.assertEqual(len(seed), 32)
        self.assertEqual(len(point), 32)
        self.assertTrue(ed.is_valid_public_key(point))

    def test_keypair_from_seed_deterministic(self):
        seed = _h(_RFC8032[0]["seed"])
        s1, p1 = ed.keypair_from_seed(seed)
        s2, p2 = ed.keypair_from_seed(seed)
        self.assertEqual(s1, s2)
        self.assertEqual(p1, p2)
        self.assertEqual(p1, ed.public_key_from_seed(seed))

    def test_sign_is_deterministic(self):
        seed = _h(_RFC8032[0]["seed"])
        msg = b"determinism check"
        self.assertEqual(ed.sign(seed, msg), ed.sign(seed, msg))

    def test_verify_round_trip(self):
        seed = _h(_RFC8032[0]["seed"])
        point = ed.public_key_from_seed(seed)
        msg = b"hello ROTN"
        sig = ed.sign(seed, msg)
        ed.verify(point, sig, msg)  # must NOT raise

    def test_reject_wrong_key(self):
        seed = _h(_RFC8032[0]["seed"])
        other_point = ed.public_key_from_seed(_h(_RFC8032[1]["seed"]))
        msg = b"hello ROTN"
        sig = ed.sign(seed, msg)
        with self.assertRaises(Exception):
            ed.verify(other_point, sig, msg)

    def test_reject_tampered_message(self):
        seed = _h(_RFC8032[0]["seed"])
        point = ed.public_key_from_seed(seed)
        sig = ed.sign(seed, b"hello ROTN")
        with self.assertRaises(Exception):
            ed.verify(point, sig, b"hello ROTN!")

    def test_reject_tampered_signature(self):
        seed = _h(_RFC8032[0]["seed"])
        point = ed.public_key_from_seed(seed)
        sig = bytearray(ed.sign(seed, b"hello ROTN"))
        sig[0] ^= 0xFF
        with self.assertRaises(Exception):
            ed.verify(point, bytes(sig), b"hello ROTN")

    def test_invalid_public_key_rejected(self):
        seed = _h(_RFC8032[0]["seed"])
        bad_point = b"\x00" * 32  # not a valid curve point
        with self.assertRaises(Exception):
            ed.verify(bad_point, ed.sign(seed, b"x"), b"x")


class PemTests(unittest.TestCase):
    """PEM (RFC 8410) round-trips -- interchangeable with OpenSSL / cryptography."""

    def test_private_key_pem_round_trip(self):
        seed = _h(_RFC8032[0]["seed"])
        pem = ed.private_key_pem(seed)
        self.assertIn("BEGIN", pem)
        self.assertEqual(ed.load_private_key_pem(pem), seed)
        self.assertTrue(ed.is_ed25519_pem(pem))

    def test_public_key_pem_round_trip(self):
        point = _h(_RFC8032[0]["public"])
        pem = ed.public_key_pem(point)
        self.assertIn("BEGIN PUBLIC KEY", pem)
        self.assertEqual(ed.load_public_key_pem(pem), point)

    def test_sign_with_loaded_pem_key(self):
        seed = _h(_RFC8032[0]["seed"])
        message = _h(_RFC8032[0]["message"])
        priv_pem = ed.private_key_pem(seed)
        pub_pem = ed.public_key_pem(ed.public_key_from_seed(seed))
        seed2 = ed.load_private_key_pem(priv_pem)
        point2 = ed.load_public_key_pem(pub_pem)
        sig = ed.sign(seed2, message)
        self.assertEqual(sig.hex(), _RFC8032[0]["signature"])
        ed.verify(point2, sig, message)  # must NOT raise

    def test_is_ed25519_pem_rejects_garbage(self):
        self.assertFalse(ed.is_ed25519_pem("not a pem"))
        self.assertFalse(
            ed.is_ed25519_pem("-----BEGIN RSA PRIVATE KEY-----\n"))


class ZeroDependencyTests(unittest.TestCase):
    """The zero-dependency claim: ``cryptography`` is never imported.

    (The module may *mention* the package in a docstring, but it must not
    import it -- that is the actual dependency.)
    """

    def test_no_cryptography_import(self):
        import ast
        tree = ast.parse(inspect.getsource(ed))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    imported.add(a.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imported.add(node.module)
        self.assertFalse(
            any(name.startswith("cryptography") for name in imported),
            "rot.ed25519 imports: %s" % sorted(imported))


if __name__ == "__main__":
    unittest.main(verbosity=2)