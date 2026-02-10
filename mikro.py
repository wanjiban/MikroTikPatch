"""
MikroTik RouterOS 许可证和加密操作模块

本模块提供 MikroTik RouterOS 的加密功能，包括：
- 软件 ID 编码/解码
- 自定义许可证载荷编码/解码（基于 MIKRO_SHA256_K）
- 使用 MikroTik 自定义字母表的 Base64 编码/解码
- EdDSA (Ed25519) 签名和验证
- KCdsa (Curve25519) 签名和验证

这些函数用于 MikroTik 许可证生成和验证操作。
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
    将 MikroTik 软件 ID 字符串解码为其数值表示。

    软件 ID 使用自定义的 32 字符字母表（SOFTWARE_ID_CHARACTER_TABLE）编码。
    这是 mikro_softwareid_encode() 的逆操作。

    参数:
        software_id: 要解码的软件 ID 字符串（例如：'TN0BYX18-5HZ4IA67'）

    返回:
        int: 解码后的数值软件 ID

    示例:
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
    将数值 ID 编码为 MikroTik 软件 ID 字符串。

    软件 ID 使用自定义的 32 字符字母表（SOFTWARE_ID_CHARACTER_TABLE）编码。
    输出格式在第 4 个字符后包含连字符以提高可读性。
    这是 mikro_softwareid_decode() 的逆操作。

    参数:
        id: 要编码的数值 ID

    返回:
        str: 编码后的软件 ID 字符串（带连字符分隔符）

    示例:
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
    确保值限制在 32 位（无符号）。

    参数:
        v: 要限制的整数值

    返回:
        int: 值模 2^32
    """
    return (v + (1 << 32)) % (1 << 32)


def rotl(n, d):
    """
    执行 32 位左循环移位（Rotate Left）。

    参数:
        n: 要移位的值
        d: 左移位数

    返回:
        int: 循环移位后的 32 位值
    """
    return (n << d) | (n >> (32 - d))


def mikro_encode(s: bytes) -> bytes:
    """
    使用 MikroTik 自定义 MIKRO_SHA256_K 算法编码许可证载荷数据。

    此函数使用 MIKRO_SHA256_K 常量应用一系列 ROTL 操作和 XOR 操作
    来混淆许可证载荷数据。

    参数:
        s: 要编码的原始许可证载荷字节

    返回:
        bytes: 编码后的许可证载荷（长度与输入相同）

    注意:
        这是 MikroTik 专有的编码算法，用于许可证生成。
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
    解码使用 mikro_encode() 编码的许可证载荷数据。

    此函数通过使用相同的 MIKRO_SHA256_K 常量应用 mikro_encode() 的逆操作
    来反转编码过程。

    参数:
        s: 要解码的编码许可证载荷字节

    返回:
        bytes: 解码后的许可证载荷（长度与输入相同）

    注意:
        这是 mikro_encode() 的逆操作。
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
    使用 MikroTik 自定义字母表编码字节。

    这类似于标准 base64 编码，但使用 MikroTik 的自定义字符表
   （MIKRO_BASE64_CHARACTER_TABLE）而非标准字符表。

    参数:
        data: 要编码的字节
        pad: 是否在末尾添加填充字符（'='）

    返回:
        str: 编码后的字符串
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
    解码使用 mikro_base64_encode() 编码的字符串。

    参数:
        data: 要解码的 base64 编码字符串（填充符 '=' 可选）

    返回:
        bytes: 解码后的字节数据
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
    使用 MikroTik 自定义 MIKRO_SHA256_K 常量的 SHA256 实现。

    此类使用 MikroTik 特定的常量扩展了基础 SHA256 实现，
    用于许可证生成和验证。
    """
    K = MIKRO_SHA256_K
    INITIAL_STATE = SHA256.State(
        0x5B653932, 0x7B145F8F, 0x71FFB291, 0x38EF925F,
        0x03E1AAF9, 0x4A2057CC, 0x4CAF4DD9, 0x643CC9EA
    )


def mikro_sha256(data: bytes) -> bytes:
    """
    使用 MikroTik 自定义参数计算 SHA256 哈希。

    参数:
        data: 要哈希的字节

    返回:
        bytes: 32 字节的 SHA256 摘要
    """
    return MikroSHA256(data).digest()


def mikro_eddsa_sign(data: bytes, private_key: bytes) -> bytes:
    """
    使用 EdDSA (Ed25519) 算法签名数据。

    参数:
        data: 要签名的字节
        private_key: 32 字节 Ed25519 私钥

    返回:
        bytes: 64 字节 EdDSA 签名
    """
    assert(isinstance(data, bytes))
    assert(isinstance(private_key, bytes))
    curve = getcurvebyname('Ed25519')
    private_key = ECPrivateKey.eddsa_decode(curve, private_key)
    return private_key.eddsa_sign(data).encode()


def mikro_eddsa_verify(data: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    验证 EdDSA (Ed25519) 签名。

    参数:
        data: 原始签名数据
        signature: 64 字节 EdDSA 签名
        public_key: 32 字节 Ed25519 公钥

    返回:
        bool: 签名有效返回 True，否则返回 False
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
    使用 KCdsa（Kyber 修改的 Curve25519 DSA）算法签名数据。

    KCdsa 是 MikroTik 使用的自定义签名方案，结合了
    Curve25519 和基于 SHA256 的随机数派生。

    参数:
        data: 要签名的字节
        private_key: 32 字节 Curve25519 私钥

    返回:
        bytes: 48 字节 KCdsa 签名（16 字节随机数哈希 + 32 字节签名）
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
    验证 KCdsa（Kyber 修改的 Curve25519 DSA）签名。

    参数:
        data: 原始签名数据
        signature: 48 字节 KCdsa 签名
        public_key: 32 字节 Curve25519 公钥

    返回:
        bool: 签名有效返回 True，否则返回 False
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
