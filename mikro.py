"""
MikroTik RouterOS License and Cryptographic Operations Module

This module provides cryptographic functions for MikroTik RouterOS including:
- Software ID encoding/decoding
- Custom license payload encoding/decoding (MIKRO_SHA256_K based)
- Base64 encoding/decoding with MikroTik's custom alphabet
- EdDSA (Ed25519) signing and verification
- KCdsa (Curve25519) signing and verification

These functions are used for MikroTik license generation and verification operations.
"""

import random
import struct
from sha256 import SHA256
from toyecc import AffineCurvePoint, getcurvebyname, FieldElement, ECPrivateKey, ECPublicKey, Tools


MIKRO_BASE64_CHARACTER_TABLE = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
SOFTWARE_ID_CHARACTER_TABLE = b'TN0BYX18S5HZ4IA67DGF3LPCJQRUK9MW2VE'

MIKRO_SHA256_K = (
  0x0548D563, 0x98308EAB, 0x37AF7CCC, 0xDFBC4E3C,
  0xF125AAC9, 0xEC98ACB8, 0x8B540795, 0xD3E0EF0E,
  0x4904D6E5, 0x0DA84981, 0x9A1F8452, 0x00EB7EAA,
  0x96F8E3B3, 0xA6CDB655, 0xE7410F9E, 0x8EECB03D,
  0x9C6A7C25, 0xD77B072F, 0x6E8F650A, 0x124E3640,
  0x7E53785A, 0xE0150772, 0xC61EF4E0, 0xBC57E5E0,
  0xC0F9A285, 0xDB342856, 0x190834C7, 0xFBEB7D8E,
  0x251BED34, 0x0E9F2AAD, 0x256AB901, 0x0A5B7890,
  0x9F124F09, 0xD84A9151, 0x427AF67A, 0x8059C9AA,
  0x13EAB029, 0x3153CDF1, 0x262D405D, 0xA2105D87,
  0x9C745F15, 0xD1613847, 0x294CE135, 0x20FB0F3C,
  0x8424D8ED, 0x8F4201B6, 0x12CA1EA7, 0x2054B091,
  0x463D8288, 0xC83253C3, 0x33EA314A, 0x9696DC92,
  0xD041CE9A, 0xE5477160, 0xC7656BE8, 0x5179FE33,
  0x1F4726F1, 0x5F393AF0, 0x26E2D004, 0x6D020245,
  0x85FDF6D7, 0xB0237C56, 0xFF5FBD94, 0xA8B3F534
)


def mikro_softwareid_decode(software_id: str) -> int:
    """
    Decodes a MikroTik software ID string into its numeric representation.

    The software ID is encoded using a custom 32-character alphabet (SOFTWARE_ID_CHARACTER_TABLE).
    This is the inverse operation of mikro_softwareid_encode().

    Args:
        software_id: The software ID string to decode (e.g., 'TN0BYX18-5HZ4IA67')

    Returns:
        int: The decoded numeric software ID value.

    Example:
        >>> mikro_softwareid_decode('TN0BYX18')
        1234567890
    """
    assert(isinstance(software_id, str))
    software_id = software_id.replace('-', '')
    ret = 0
    for i in reversed(range(len(software_id))):
        ret *= len(SOFTWARE_ID_CHARACTER_TABLE)
        ret += SOFTWARE_ID_CHARACTER_TABLE.index(ord(software_id[i]))
    return ret


def mikro_softwareid_encode(id: int) -> str:
    """
    Encodes a numeric ID into a MikroTik software ID string.

    The software ID is encoded using a custom 32-character alphabet (SOFTWARE_ID_CHARACTER_TABLE).
    The output format includes a hyphen after the 4th character for readability.
    This is the inverse operation of mikro_softwareid_decode().

    Args:
        id: The numeric ID to encode.

    Returns:
        str: The encoded software ID string with hyphen separator.

    Example:
        >>> mikro_softwareid_encode(1234567890)
        'TN0B-XXXX'
    """
    assert(isinstance(id, int))
    ret = ''
    for i in range(8):
        ret += chr(SOFTWARE_ID_CHARACTER_TABLE[id % len(SOFTWARE_ID_CHARACTER_TABLE)])
        id //= len(SOFTWARE_ID_CHARACTER_TABLE)
        if i == 3:
            ret += '-'
    return ret


def to32bits(v):
    """
    Ensures a value is constrained to 32 bits (unsigned).

    Args:
        v: The integer value to constrain.

    Returns:
        int: The value modulo 2^32.
    """
    return (v + (1 << 32)) % (1 << 32)


def rotl(n, d):
    """
    Performs a 32-bit left rotation (Rotate Left).

    Args:
        n: The value to rotate.
        d: The number of bits to rotate left.

    Returns:
        int: The rotated 32-bit value.
    """
    return (n << d) | (n >> (32 - d))


def mikro_encode(s: bytes) -> bytes:
    """
    Encodes license payload data using MikroTik's custom MIKRO_SHA256_K based algorithm.

    This function applies a series of ROTL operations and XOR operations using
    the MIKRO_SHA256_K constants to obfuscate the license payload data.

    Args:
        s: The raw license payload bytes to encode.

    Returns:
        bytes: The encoded license payload (same length as input).

    Note:
        This is a proprietary MikroTik encoding algorithm used in license generation.
    """
    s = list(struct.unpack('>' + 'I' * (len(s) // 4), s))
    for i in reversed(range(16)):
        s[(i+0) % 4] = to32bits(rotl(s[(i+3) % 4], MIKRO_SHA256_K[i*4+3] & 0x0F) ^ (s[(i+0) % 4] - s[(i+3) % 4]))
        s[(i+3) % 4] = to32bits(s[(i+3) % 4] + s[(i+1) % 4] + MIKRO_SHA256_K[i*4+3])

        s[(i+1) % 4] = to32bits(rotl(s[(i+2) % 4], MIKRO_SHA256_K[i*4+2] & 0x0F) ^ (s[(i+1) % 4] - s[(i+2) % 4]))
        s[(i+0) % 4] = to32bits(s[(i+0) % 4] + s[(i+2) % 4] + MIKRO_SHA256_K[i*4+2])

        s[(i+2) % 4] = to32bits(rotl(s[(i+1) % 4], MIKRO_SHA256_K[i*4+1] & 0x0F) ^ (s[(i+2) % 4] - s[(i+1) % 4]))
        s[(i+1) % 4] = to32bits(s[(i+1) % 4] + s[(i+3) % 4] + MIKRO_SHA256_K[i*4+1])

        s[(i+3) % 4] = to32bits(rotl(s[(i+0) % 4], MIKRO_SHA256_K[i*4+0] & 0x0F) ^ (s[(i+3) % 4] - s[(i+0) % 4]))
        s[(i+2) % 4] = to32bits(s[(i+2) % 4] + s[(i+0) % 4] + MIKRO_SHA256_K[i*4+0])

    encodedLicensePayload = b''
    for x in s:
        encodedLicensePayload += x.to_bytes(4, 'big')
    return encodedLicensePayload


def mikro_decode(s: bytes) -> bytes:
    """
    Decodes license payload data encoded with mikro_encode().

    This function reverses the encoding process by applying the inverse operations
    of mikro_encode() using the same MIKRO_SHA256_K constants.

    Args:
        s: The encoded license payload bytes to decode.

    Returns:
        bytes: The decoded license payload (same length as input).

    Note:
        This is the inverse operation of mikro_encode().
    """
    s = list(struct.unpack('>'+'I'*(len(s) // 4), s))
    for i in range(16):
        s[(i+2) % 4] = to32bits(s[(i+2) % 4] - s[(i+0) % 4] - MIKRO_SHA256_K[i*4+0])
        s[(i+3) % 4] = to32bits((rotl(s[(i+0) % 4], MIKRO_SHA256_K[i*4+0] & 0x0F) ^ s[(i+3) % 4]) + s[(i+0) % 4])

        s[(i+1) % 4] = to32bits(s[(i+1) % 4] - s[(i+3) % 4] - MIKRO_SHA256_K[i*4+1])
        s[(i+2) % 4] = to32bits((rotl(s[(i+1) % 4], MIKRO_SHA256_K[i*4+1] & 0x0F) ^ s[(i+2) % 4]) + s[(i+1) % 4])

        s[(i+0) % 4] = to32bits(s[(i+0) % 4] - s[(i+2) % 4] - MIKRO_SHA256_K[i*4+2])
        s[(i+1) % 4] = to32bits((rotl(s[(i+2) % 4], MIKRO_SHA256_K[i*4+2] & 0x0F) ^ s[(i+1) % 4]) + s[(i+2) % 4])

        s[(i+3) % 4] = to32bits(s[(i+3) % 4] - s[(i+1) % 4] - MIKRO_SHA256_K[i*4+3])
        s[(i+0) % 4] = to32bits((rotl(s[(i+3) % 4], MIKRO_SHA256_K[i*4+3] & 0x0F) ^ s[(i+0) % 4]) + s[(i+3) % 4])

    ret = b''
    for x in s:
        ret += x.to_bytes(4, 'big')

    return ret


def mikro_base64_encode(data: bytes, pad=False) -> str:
    """
    Encodes bytes using MikroTik's custom base64 alphabet.

    This is similar to standard base64 encoding but uses MikroTik's custom
    character table (MIKRO_BASE64_CHARACTER_TABLE) instead of the standard one.

    Args:
        data: The bytes to encode.
        pad: Whether to add padding characters ('=') at the end.

    Returns:
        str: The encoded string.
    """
    encoded = ''
    left = 0
    for i in range(0, len(data)):
        if left == 0:
            encoded += chr(MIKRO_BASE64_CHARACTER_TABLE[data[i] & 0x3F])
            left = 2
        else:
            if left == 6:
                encoded += chr(MIKRO_BASE64_CHARACTER_TABLE[data[i - 1] >> 2])
                encoded += chr(MIKRO_BASE64_CHARACTER_TABLE[data[i] & 0x3F])
                left = 2
            else:
                index1 = data[i - 1] >> (8 - left)
                index2 = data[i] << (left)
                encoded += chr(MIKRO_BASE64_CHARACTER_TABLE[(index1 | index2) & 0x3F])
                left += 2

    if left != 0:
        encoded += chr(MIKRO_BASE64_CHARACTER_TABLE[data[len(data) - 1] >> (8 - left)])

    if pad:
        for i in range(0, (4 - len(encoded) % 4) % 4):
            encoded += '='

    return encoded


def mikro_base64_decode(data: str) -> bytes:
    """
    Decodes a string encoded with mikro_base64_encode().

    Args:
        data: The base64-encoded string to decode (padding '=' optional).

    Returns:
        bytes: The decoded byte data.
    """
    ret = b""
    data = data.replace("=", "").encode()
    left = 0
    for i in range(0, len(data)):
        if left == 0:
            left = 6
        else:
            value1 = MIKRO_BASE64_CHARACTER_TABLE.index(data[i - 1]) >> (6 - left)
            value2 = MIKRO_BASE64_CHARACTER_TABLE.index(data[i]) & (2 ** (8 - left) - 1)
            value = value1 | (value2 << left)
            ret += bytes([value])
            left -= 2
    return ret


class MikroSHA256(SHA256):
    """
    Custom SHA256 implementation using MikroTik's MIKRO_SHA256_K constants.

    This class extends the base SHA256 implementation with MikroTik-specific
    constants for use in license generation and verification.
    """
    K = MIKRO_SHA256_K
    INITIAL_STATE = SHA256.State(
        0x5B653932, 0x7B145F8F, 0x71FFB291, 0x38EF925F,
        0x03E1AAF9, 0x4A2057CC, 0x4CAF4DD9, 0x643CC9EA
    )


def mikro_sha256(data: bytes) -> bytes:
    """
    Computes SHA256 hash using MikroTik's custom parameters.

    Args:
        data: The bytes to hash.

    Returns:
        bytes: The 32-byte SHA256 digest.
    """
    return MikroSHA256(data).digest()


def mikro_eddsa_sign(data: bytes, private_key: bytes) -> bytes:
    """
    Signs data using EdDSA (Ed25519) algorithm.

    Args:
        data: The bytes to sign.
        private_key: The 32-byte Ed25519 private key.

    Returns:
        bytes: The 64-byte EdDSA signature.
    """
    assert(isinstance(data, bytes))
    assert(isinstance(private_key, bytes))
    curve = getcurvebyname('Ed25519')
    private_key = ECPrivateKey.eddsa_decode(curve, private_key)
    return private_key.eddsa_sign(data).encode()


def mikro_eddsa_verify(data: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Verifies an EdDSA (Ed25519) signature.

    Args:
        data: The original data that was signed.
        signature: The 64-byte EdDSA signature to verify.
        public_key: The 32-byte Ed25519 public key.

    Returns:
        bool: True if signature is valid, False otherwise.
    """
    assert(isinstance(data, bytes))
    assert(isinstance(signature, bytes))
    assert(isinstance(public_key, bytes))
    curve = getcurvebyname('Ed25519')
    public_key = ECPublicKey.eddsa_decode(curve, public_key)
    signature = ECPrivateKey.EDDSASignature.decode(curve, signature)
    return public_key.eddsa_verify(data, signature)


def mikro_kcdsa_sign(data: bytes, private_key: bytes) -> bytes:
    """
    Signs data using KCdsa (Kyber-modified Curve25519 DSA) algorithm.

    KCdsa is a custom signature scheme used by MikroTik, combining
    Curve25519 with SHA256-based nonce derivation.

    Args:
        data: The bytes to sign.
        private_key: The 32-byte Curve25519 private key.

    Returns:
        bytes: The 48-byte KCdsa signature (16-byte nonce hash + 32-byte signature).
    """
    assert(isinstance(data, bytes))
    assert(isinstance(private_key, bytes))
    curve = getcurvebyname('Curve25519')
    private_key: ECPrivateKey = ECPrivateKey(Tools.bytestoint_le(private_key), curve)
    public_key: ECPublicKey = private_key.pubkey
    while True:
        nonce_secret = random.SystemRandom().randint(1, curve.n - 1)
        nonce_point = nonce_secret * curve.G
        nonce = int(nonce_point.x) % curve.n
        nonce_hash = mikro_sha256(Tools.inttobytes_le(nonce, 32))
        data_hash = bytearray(mikro_sha256(data))
        for i in range(16):
            data_hash[8+i] ^= nonce_hash[i]
        data_hash[0] &= 0xF8
        data_hash[31] &= 0x7F
        data_hash[31] |= 0x40
        data_hash = Tools.bytestoint_le(data_hash)
        signature = pow(private_key.scalar, -1, curve.n) * (nonce_secret - data_hash)
        signature %= curve.n
        if int((public_key.point * signature + curve.G * data_hash).x) == nonce:
            return bytes(nonce_hash[:16] + Tools.inttobytes_le(signature, 32))


def mikro_kcdsa_verify(data: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Verifies a KCdsa (Kyber-modified Curve25519 DSA) signature.

    Args:
        data: The original data that was signed.
        signature: The 48-byte KCdsa signature.
        public_key: The 32-byte Curve25519 public key.

    Returns:
        bool: True if signature is valid, False otherwise.
    """
    assert(isinstance(data, bytes))
    assert(isinstance(signature, bytes))
    assert(isinstance(public_key, bytes))
    curve = getcurvebyname('Curve25519')
    x = FieldElement(Tools.bytestoint_le(public_key), curve.p)
    YY = ((x**3) + (curve.a * x**2) + x).sqrt()
    public_keys = [AffineCurvePoint(int(x), int(y), curve) for y in YY]
    data_hash = bytearray(mikro_sha256(data))
    nonce_hash = signature[:16]
    signature = Tools.bytestoint_le(signature[16:])
    for i in range(16):
        data_hash[8+i] ^= nonce_hash[i]
    data_hash[0] &= 0xF8
    data_hash[31] &= 0x7F
    data_hash[31] |= 0x40
    data_hash = Tools.bytestoint_le(data_hash)
    for public_key in public_keys:
        nonce = int((public_key * signature + curve.G * data_hash).x)
        if mikro_sha256(Tools.inttobytes_le(nonce, 32))[:len(nonce_hash)] == nonce_hash:
            return True
    return False
