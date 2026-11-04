# -*- coding: utf-8 -*-
"""rot.ed25519 -- Ed25519 signatures (RFC 8032) in **pure stdlib**.

Zero external dependencies (``hashlib`` + ``base64`` + big-integer
arithmetic), so ``pip install rotn`` signs and verifies real asymmetric
signatures out of the box -- no ``cryptography`` package, no optional
install, no degraded content-hash-only fallback.

What this is
------------
A self-contained implementation of Ed25519 (the Edwards-curve variant
``-x^2 + y^2 = 1 + d*x^2*y^2`` over ``GF(2^255 - 19)``) exactly as
specified in RFC 8032:

  * deterministic signing (RFC 8032 section 5.1.4) -- the signature is a
    pure function of the 32-byte seed and the message (no nonce
    randomness, no timestamps), which is what makes ROTN's attestations
    re-issuable byte-for-byte;
  * 64-byte signatures ``(R || S)``, 32-byte public keys, 32-byte seeds;
  * the verification equation ``[S]B = R + [k]A`` (section 5.1.6).

The math is plain big-integer point arithmetic in projective coordinates
(the standard complete addition formula).  It is a reference
implementation, not a constant-time one: for this product the private key
is the owner's own signing key on the owner's own machine (the signature
attests content, it does not protect a secret in a hostile process), and
correctness -- pinned by the RFC 8032 test vectors in
``tests/test_ed25519.py`` -- is the requirement.

PEM (RFC 8410)
--------------
Keys round-trip in the standard PEM forms, so a key made by OpenSSL, the
``cryptography`` package, or ROTN itself is interchangeable:

  * private key: PKCS#8 (``-----BEGIN PRIVATE KEY-----`` or
    ``-----BEGIN ED25519 PRIVATE KEY-----``) -- the 32-byte seed;
  * public key:  SPKI  (``-----BEGIN PUBLIC KEY-----``) -- the 32-byte
    encoded point.

The decoder is a minimal generic DER walker, so it accepts the
AlgorithmIdentifier regardless of the PKCS#8 ``version`` value (OpenSSL
writes 3, RFC 5958 tools write 0 or 1) and with or without the optional
``NULL`` parameters.

Relationship to ``cryptography``
--------------------------------
``cryptography`` remains an *optional fast path* in
:mod:`rot.attestation` (C-level signing); Ed25519 is deterministic, so
both paths produce **byte-identical** signatures and the choice never
changes the artifact.  This module is the zero-dependency default.

API (bytes in, bytes out)
-------------------------
    generate_keypair()            -> (seed, public_key)
    keypair_from_seed(seed)       -> (seed, public_key)
    public_key_from_seed(seed)    -> public_key (32 bytes)
    sign(seed, message)           -> signature (64 bytes)
    verify(public_key, signature, message)   # raises ValueError on failure
    is_valid_public_key(point)    -> bool

    private_key_pem(seed)         -> "-----BEGIN PRIVATE KEY-----..."
    public_key_pem(point)         -> "-----BEGIN PUBLIC KEY-----..."
    load_private_key_pem(pem)     -> seed (32 bytes)
    load_public_key_pem(pem)      -> point (32 bytes)
    is_ed25519_pem(pem)           -> bool

Pure stdlib, Python 3.6 compatible.
"""

import base64
import hashlib
import textwrap

__all__ = [
    "generate_keypair",
    "keypair_from_seed",
    "public_key_from_seed",
    "sign",
    "verify",
    "is_valid_public_key",
    "private_key_pem",
    "public_key_pem",
    "load_private_key_pem",
    "load_public_key_pem",
    "is_ed25519_pem",
]

# ---------------------------------------------------------------------------
# the field, the curve, the group (RFC 8032 section 5)
# ---------------------------------------------------------------------------

#: The prime: p = 2^255 - 19.
_P = (1 << 255) - 19

#: The curve constant d = -121665 * 121666^-1 mod p.
_D = (-121665 * pow(121666, _P - 2, _P)) % _P

#: The (prime) order of the base point:
#: L = 2^252 + 27742317777372353535851937790883648493.
_L = (1 << 252) + 27742317777372353535851937790883648493

#: sqrt(-1) mod p = 2^((p-1)/4) (used to test quadratic residuosity).
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _inv(a):
    """Modular inverse of ``a`` mod p (Fermat; p is prime)."""
    return pow(a % _P, _P - 2, _P)


def _recover_x(y, sign):
    """Recover the x-coordinate for a given y and sign bit (RFC 8032
    section 5.1.3).  Returns the field element (the root with the given
    parity), or None when ``y`` has no valid x (not on the curve)."""
    if y >= _P:
        return None
    x2 = ((y * y - 1) * _inv(_D * y * y + 1)) % _P
    if x2 == 0:
        if sign:
            return None
        return 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = (x * _SQRT_M1) % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


#: The base point G = (g_x, g_y) with g_y = 4/5 and g_x its even square
#: root (RFC 8032 section 5.1.5: ``g_y = 4/5; g_x = recover_x(g_y, 0)``).
_BASE_Y = (4 * pow(5, _P - 2, _P)) % _P
_BASE_X = _recover_x(_BASE_Y, 0)
_BASE = (_BASE_X, _BASE_Y, 1, (_BASE_X * _BASE_Y) % _P)


def _point_add(p, q):
    """Complete addition on the twisted Edwards curve (extended coords).

    Points are 4-tuples ``(X, Y, Z, T)`` with affine ``x = X/Z``,
    ``y = Y/Z`` and ``x*y = T/Z``.  The formula is the RFC 8032
    section 6 reference ``point_add`` (complete -- valid for all inputs,
    including the identity and points at the degenerate positions).
    """
    a = ((q[1] - q[0]) * (p[1] - p[0])) % _P
    b = ((q[1] + q[0]) * (p[1] + p[0])) % _P
    c = (2 * p[3] * q[3] * _D) % _P
    d = (2 * p[2] * q[2]) % _P
    e = (b - a) % _P
    f = (d - c) % _P
    g = (d + c) % _P
    h = (b + a) % _P
    return ((e * f) % _P, (g * h) % _P, (f * g) % _P, (e * h) % _P)


def _point_mul(s, p):
    """Scalar multiplication ``[s]P`` (double-and-add, left to right)."""
    q = (0, 1, 1, 0)  # the identity (0, 1)
    while s > 0:
        if (s & 1) == 1:
            q = _point_add(q, p)
        p = _point_add(p, p)
        s >>= 1
    return q


def _point_compress(p):
    """Compress a point to its 256-bit encoding: ``y`` with the sign bit
    of ``x`` in bit 255 (a Python int, little-endian when written)."""
    zinv = _inv(p[2])
    x = (p[0] * zinv) % _P
    y = (p[1] * zinv) % _P
    return (y | ((x & 1) << 255))


def _point_decompress(s):
    """Expand a 32-byte encoding to a projective point (raises ValueError
    when the encoding is not a valid point)."""
    if len(s) != 32:
        raise ValueError("invalid Ed25519 point (expected 32 bytes)")
    v = int.from_bytes(s, "little")
    y = v & ((1 << 255) - 1)
    xbit = (v >> 255) & 1
    y2 = (y * y) % _P
    # x^2 = (y^2 - 1) / (d*y^2 + 1)   (from -x^2 + y^2 = 1 + d*x^2*y^2)
    xx = ((y2 - 1) * _inv(_D * y2 + 1)) % _P
    if xx == 0:
        if xbit:
            raise ValueError("invalid Ed25519 point (x = 0 with odd sign bit)")
        return (0, y % _P, 1, 0)
    # Square root mod p (p = 5 mod 8): r^2 = a  <=>  r = a^((p+3)/8) or
    # r = a^((p+3)/8) * sqrt(-1).
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x) % _P != xx:
        x = (x * _SQRT_M1) % _P
        if (x * x) % _P != xx:
            raise ValueError("invalid Ed25519 point (no x for this y)")
    if (x & 1) != xbit:
        x = _P - x
    return (x, y % _P, 1, (x * (y % _P)) % _P)


# ---------------------------------------------------------------------------
# keys + signatures (RFC 8032 section 5.1)
# ---------------------------------------------------------------------------

def _clamp(seed):
    """The clamped scalar ``a`` (RFC 8032 section 5.1.1) and the 32-byte
    signing prefix: ``a = 8 * h[32..63]`` of ``h = SHA-512(seed)``.

    Bits 0-2 cleared, bit 255 cleared, bit 254 set (a = 2^254 + sum of
    bits 3..253).
    """
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= ~7               # clear the low three bits
    a &= (1 << 255) - 1   # clear the top bit
    a |= (1 << 254)       # set the second-highest bit
    return a, h[32:64]


def keypair_from_seed(seed):
    """Derive the keypair from a 32-byte seed.

    Returns ``(seed, public_key)`` -- the public key is the 32-byte
    encoding of ``[a]B`` where ``a`` is the clamped seed (deterministic;
    the same seed always yields the same key).
    """
    seed = bytes(seed)
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes (got %d)" % (len(seed),))
    a, _prefix = _clamp(seed)
    return seed, _point_compress(_point_mul(a, _BASE)).to_bytes(32, "little")


def public_key_from_seed(seed):
    """The 32-byte public key for a 32-byte seed (the keypair, minus the
    seed)."""
    return keypair_from_seed(seed)[1]


def generate_keypair():
    """Generate a fresh keypair from ``os.urandom(32)``.

    Returns ``(seed, public_key)``.  The seed is the private key (keep it
    secret); the public key may be embedded in artifacts.
    """
    import os
    seed = os.urandom(32)
    return keypair_from_seed(seed)


def sign(seed, message):
    """Sign ``message`` with the 32-byte seed (RFC 8032 section 5.1.4).

    Deterministic: the 64-byte signature is a pure function of the seed
    and the message -- ``R = [r]B`` with ``r = SHA-512(prefix || M) mod
    L``, ``S = (r + k*a) mod L``.  No randomness, no clock.
    """
    a, prefix = _clamp(bytes(seed))
    r = int.from_bytes(
        hashlib.sha512(prefix + bytes(message)).digest(), "little") % _L
    r_enc = _point_compress(_point_mul(r, _BASE)).to_bytes(32, "little")
    a_enc = _point_compress(_point_mul(a, _BASE)).to_bytes(32, "little")
    k = int.from_bytes(
        hashlib.sha512(r_enc + a_enc + bytes(message)).digest(),
        "little") % _L
    s = (r + k * a) % _L
    return r_enc + s.to_bytes(32, "little")


def verify(public_key, signature, message):
    """Verify a 64-byte signature over ``message`` against the 32-byte
    public key (RFC 8032 section 5.1.6: ``[S]B = R + [k]A``).

    Raises ``ValueError`` when the signature is invalid (bad lengths, an
    out-of-range ``S``, an invalid point encoding, or equation failure).
    """
    if len(public_key) != 32:
        raise ValueError("invalid public key (expected 32 bytes)")
    if len(signature) != 64:
        raise ValueError("invalid signature (expected 64 bytes)")
    r_enc = signature[:32]
    s = int.from_bytes(signature[32:64], "little")
    if s >= _L:
        raise ValueError("invalid signature (S out of range)")
    r_point = _point_decompress(r_enc)
    a_point = _point_decompress(bytes(public_key))
    k = int.from_bytes(
        hashlib.sha512(r_enc + bytes(public_key) + bytes(message)).digest(),
        "little") % _L
    left = _point_compress(_point_mul(s, _BASE))
    right = _point_compress(_point_add(r_point, _point_mul(k, a_point)))
    if left != right:
        raise ValueError("signature verification failed")


def is_valid_public_key(point):
    """True when ``point`` (32 bytes) decodes to a point on the curve."""
    try:
        _point_decompress(bytes(point))
        return True
    except Exception:
        return False



# ---------------------------------------------------------------------------
# PEM (RFC 8410): PKCS#8 private keys, SPKI public keys
# ---------------------------------------------------------------------------

#: The Ed25519 object identifier 1.3.101.112, DER content bytes (2b 65 70).
_OID_ED25519 = bytes((0x2b, 0x65, 0x70))


def _b64pem(label, der):
    """Encode ``der`` as a PEM block with the given label (64-char lines)."""
    body = "\n".join(textwrap.wrap(base64.b64encode(der).decode("ascii"), 64))
    return "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (label, body, label)


def _pem_der(pem, labels):
    """Extract the base64 body of the first PEM block whose label is in
    ``labels`` and decode it (raises ValueError when absent/malformed)."""
    if not isinstance(pem, str):
        raise ValueError("PEM must be text (str)")
    text = pem.strip()
    for label in labels:
        begin = "-----BEGIN %s-----" % label
        end = "-----END %s-----" % label
        i = text.find(begin)
        if i == -1:
            continue
        j = text.find(end, i)
        if j == -1:
            raise ValueError("PEM block is not terminated (%s)" % end)
        b64 = "".join(text[i + len(begin):j].split())
        try:
            return base64.b64decode(b64, validate=True)
        except Exception as exc:
            raise ValueError("PEM base64 is malformed: %s" % (exc,))
    raise ValueError("no %s PEM block found" % " / ".join(labels))


def _der_next(data, i):
    """Parse one DER TLV at offset ``i``; return ``(tag, content, next_i)``."""
    if i >= len(data):
        raise ValueError("truncated DER")
    tag = data[i]
    i += 1
    if i >= len(data):
        raise ValueError("truncated DER")
    length = data[i]
    i += 1
    if length & 0x80:
        n = length & 0x7f
        if n == 0 or n > 4:
            raise ValueError("bad DER length octet")
        if i + n > len(data):
            raise ValueError("truncated DER")
        length = int.from_bytes(data[i:i + n], "big")
        i += n
    if i + length > len(data):
        raise ValueError("truncated DER")
    return tag, data[i:i + length], i + length


def _der_seq_fields(content):
    """The top-level ``(tag, content)`` fields of a DER SEQUENCE body."""
    fields = []
    i = 0
    while i < len(content):
        tag, body, i = _der_next(content, i)
        fields.append((tag, body))
    return fields


def private_key_pem(seed):
    """The PKCS#8 PEM for a 32-byte Ed25519 seed (RFC 8410).

    ``-----BEGIN PRIVATE KEY-----`` (the same DER body as OpenSSL's
    ``-----BEGIN ED25519 PRIVATE KEY-----``).
    """
    seed = bytes(seed)
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes (got %d)" % (len(seed),))
    inner = b"\x04\x20" + seed                        # OCTET STRING (32)
    priv = b"\x04" + bytes((len(inner),)) + inner     # OCTET STRING { seed }
    alg = b"\x30\x05\x06\x03" + _OID_ED25519          # SEQUENCE { OID }
    version = b"\x02\x01\x03"                          # INTEGER (OpenSSL v3)
    body = version + alg + priv
    return _b64pem("PRIVATE KEY", b"\x30" + bytes((len(body),)) + body)


def public_key_pem(point):
    """The SPKI PEM for a 32-byte Ed25519 public key (RFC 8410).

    ``-----BEGIN PUBLIC KEY-----`` (the standard SubjectPublicKeyInfo).
    """
    point = bytes(point)
    if len(point) != 32:
        raise ValueError("public key must be 32 bytes (got %d)" % (len(point),))
    bits = b"\x03\x21\x00" + point                    # BIT STRING (unused 0)
    alg = b"\x30\x05\x06\x03" + _OID_ED25519
    body = alg + bits
    return _b64pem("PUBLIC KEY", b"\x30" + bytes((len(body),)) + body)


def load_private_key_pem(pem):
    """Extract the 32-byte Ed25519 seed from a PEM private key.

    Accepts PKCS#8 (``BEGIN PRIVATE KEY``) and the OpenSSL
    ``BEGIN ED25519 PRIVATE KEY`` form; the AlgorithmIdentifier must be the
    Ed25519 OID 1.3.101.112.  Raises ``ValueError`` for anything else
    (garbage, wrong key type, wrong length) -- callers use that to tell
    Ed25519 keys from EC keys.
    """
    der = _pem_der(pem, ("PRIVATE KEY", "ED25519 PRIVATE KEY"))
    tag, content, _ = _der_next(der, 0)
    if tag != 0x30:
        raise ValueError("not a DER SEQUENCE (not a PKCS#8 private key)")
    algo = None
    priv = None
    for tag_i, body in _der_seq_fields(content):
        if tag_i == 0x30 and algo is None:
            algo = body
        elif tag_i == 0x04:
            priv = body
    if priv is None:
        raise ValueError("not a PKCS#8 private key (no privateKey field)")
    itag, inner, _ = _der_next(priv, 0)
    if itag != 0x04 or len(inner) != 32:
        raise ValueError("not an Ed25519 private key (seed is not 32 bytes)")
    if algo is not None and _OID_ED25519 not in algo:
        raise ValueError("not an Ed25519 key (unknown algorithm identifier)")
    return inner


def load_public_key_pem(pem):
    """Extract the 32-byte Ed25519 point from an SPKI PEM public key
    (``BEGIN PUBLIC KEY``).  Raises ``ValueError`` for anything else."""
    der = _pem_der(pem, ("PUBLIC KEY",))
    tag, content, _ = _der_next(der, 0)
    if tag != 0x30:
        raise ValueError("not a DER SEQUENCE (not an SPKI public key)")
    bits = None
    for tag_i, body in _der_seq_fields(content):
        if tag_i == 0x03:
            bits = body
    if bits is None or len(bits) != 33 or bits[0] != 0:
        raise ValueError(
            "not an Ed25519 public key (BIT STRING is not 32 bytes)")
    return bits[1:]


def is_ed25519_pem(pem):
    """True when ``pem`` is a PEM Ed25519 **private** key (a 32-byte seed
    under the Ed25519 OID).  False for anything else (public keys, EC
    keys, garbage)."""
    try:
        load_private_key_pem(pem)
        return True
    except Exception:
        return False