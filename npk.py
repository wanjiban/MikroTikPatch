"""
NPK (Nova Package) 格式模块

本模块提供处理 MikroTik NPK (Nova Package) 格式的类和函数。
NPK 是 MikroTik RouterOS 用于系统包、可选包和许可证包的包格式。

本模块支持：
- 解析 NPK 文件
- 创建 NPK 文件
- 使用 KCdsa 和 EdDSA 签署 NPK 包
- 验证 NPK 包签名
- 提取和修改包内容

NPK 格式结构：
- NPK_MAGIC: 0xbad0f11e (小端)
- 包大小（不包括 8 字节头）
- 包含不同类型数据的多个部分：
  - NAME_INFO: 包名称和版本信息
  - DESCRIPTION: 包描述
  - DEPENDENCIES: 包依赖
  - FILE_CONTAINER: 压缩文件容器
  - INSTALL_SCRIPT: 安装脚本
  - UNINSTALL_SCRIPT: 卸载脚本
  - SIGNATURE: 包签名 (SHA1 + KCdsa + EdDSA)
  - ARCHITECTURE: 包架构
  - PKG_CONFLICTS: 包冲突
  - FEATURES: 包特性
  - SQUASHFS: SquashFS 文件系统镜像
  - NULL_BLOCK: 填充块
  - GIT_COMMIT: Git 提交哈希
  - CHANNEL: 发布通道（stable、testing 等）
  - HEADER: 包头
"""

import struct
import zlib
import argparse
import os
from datetime import datetime
from dataclasses import dataclass
from enum import IntEnum


class NpkPartID(IntEnum):
    """
    NPK 部分（节）ID 枚举。

    每个部分 ID 表示 NPK 包内的不同数据类型。
    """
    NAME_INFO = 0x01
    DESCRIPTION = 0x02
    DEPENDENCIES = 0x03
    FILE_CONTAINER = 0x04
    INSTALL_SCRIPT = 0x07
    UNINSTALL_SCRIPT = 0x08
    SIGNATURE = 0x09
    ARCHITECTURE = 0x10
    PKG_CONFLICTS = 0x11
    PKG_INFO = 0x12
    FEATURES = 0x13
    PKG_FEATURES = 0x14
    SQUASHFS = 0x15
    NULL_BLOCK = 0x16
    GIT_COMMIT = 0x17
    CHANNEL = 0x18
    HEADER = 0x19


@dataclass
class NpkPartItem:
    """
    表示 NPK 包中的单个部分（节）。

    属性:
        id: 标识此部分类型的 NpkPartID
        data: 此部分包含的二进制数据或对象
    """
    id: NpkPartID
    data: bytes | object


class NpkInfo:
    """
    NPK 包信息元数据的基类。

    此类处理在旧版 NPK 格式中发现的包名称和版本信息结构。
    """
    _format = '<16s4sI8s'

    def __init__(self, name: str, version: str, build_time=datetime.now(), unknow=b'\x00'*8):
        """
        使用包名称、版本和构建时间戳初始化 NpkInfo。

        参数:
            name: 包名称（最多 16 个字符）
            version: 版本字符串（例如：'7.15.1.final'）
            build_time: 包构建的日期时间（默认为当前时间）
            unknow: 未知的 8 字节字段（填充/保留）
        """
        self._name = name[:16].encode().ljust(16, b'\x00')
        self._version = self.encode_version(version)
        self._build_time = int(build_time.timestamp())
        self._unknow = unknow

    def serialize(self) -> bytes:
        """
        将 NpkInfo 结构序列化为字节以包含在 NPK 中。

        返回:
            bytes: 序列化的 32 字节 NpkInfo 结构
        """
        return struct.pack(self._format, self._name, self._version, self._build_time, self._unknow)

    @staticmethod
    def unserialize_from(data: bytes) -> 'NpkInfo':
        """
        从字节数据反序列化 NpkInfo。

        参数:
            data: 32 字节的序列化 NpkInfo 数据

        返回:
            NpkInfo: 反序列化的 NpkInfo 对象

        异常:
            AssertionError: 如果数据长度无效
        """
        assert len(data) == struct.calcsize(NpkInfo._format), 'Invalid data length'
        _name, _version, _build_time, unknow = struct.unpack_from(NpkInfo._format, data)
        return NpkInfo(_name.decode(), NpkInfo.decode_version(_version), datetime.fromtimestamp(_build_time), unknow)

    def __len__(self) -> int:
        """返回序列化 NpkInfo 结构的大小（32 字节）。"""
        return struct.calcsize(self._format)

    @property
    def name(self) -> str:
        """获取包名称，去除空字节填充。"""
        return self._name.decode().strip('\x00')

    @name.setter
    def name(self, value: str):
        """设置包名称（截断为 16 字符，空字节填充）。"""
        self._name = value[:16].encode().ljust(16, b'\x00')

    @staticmethod
    def decode_version(value: bytes) -> str:
        """
        将 4 字节版本值解码为版本字符串。

        版本格式为：major.minor.revision.build_type
        其中 build_type 可以是：alpha、beta、rc、final、test

        参数:
            value: 包含版本信息的 4 个字节

        返回:
            str: 解码后的版本字符串
        """
        revision, build, minor, major = struct.unpack_from('4B', value)
        if build == 97:
            build = 'alpha'
        elif build == 98:
            build = 'beta'
        elif build == 99:
            build = 'rc'
        elif build == 102:
            if revision & 0x80:
                build = 'test'
                revision &= 0x7f
            else:
                build = 'final'
        else:
            build = 'unknown'
        return f'{major}.{minor}.{revision}.{build}'

    @staticmethod
    def encode_version(value: str) -> bytes:
        """
        将版本字符串编码为 4 个字节。

        参数:
            value: 版本字符串（例如：'7.15.1.final'）

        返回:
            bytes: 编码后的 4 字节版本数据

        异常:
            ValueError: 如果版本字符串格式无效
        """
        s = value.split('.')
        if 4 != len(s) and s[3] in ['alpha', 'beta', 'rc', 'final', 'test']:
            raise ValueError('Invalid version string')
        major = int(s[0])
        minor = int(s[1])
        revision = int(s[2])
        if s[3] == 'alpha':
            build = 97
        elif s[3] == 'beta':
            build = 98
        elif s[3] == 'rc':
            build = 99
        elif s[3] == 'final':
            build = 102
            revision &= 0x7f
        else:
            build = 102
            revision |= 0x80
        return struct.pack('4B', revision, build, minor, major)

    @property
    def version(self) -> str:
        """获取包版本字符串。"""
        return self.decode_version(self._version)

    @version.setter
    def version(self, value: str = '7.15.1.final'):
        """设置包版本字符串。"""
        self._version = self.encode_version(value)

    @property
    def build_time(self):
        """获取包构建时间戳作为日期时间。"""
        return datetime.fromtimestamp(self._build_time)

    @build_time.setter
    def build_time(self, value: datetime):
        """从日期时间设置包构建时间戳。"""
        self._build_time = int(value.timestamp())


class NpkNameInfo(NpkInfo):
    """
    扩展的 NPK 名称信息结构。

    此类表示主 NPK 包中使用的新版 NAME_INFO 格式，
    与基础 NpkInfo 相比增加了 12 字节的未知字段。
    """
    _format = '<16s4sI12s'

    def __init__(self, name: str, version: str, build_time=datetime.now(), unknow=b'\x00'*12):
        """
        使用扩展结构初始化 NpkNameInfo。

        参数:
            name: 包名称（最多 16 个字符）
            version: 版本字符串
            build_time: 构建时间戳
            unknow: 12 字节未知/填充字段
        """
        self._name = name[:16].encode().ljust(16, b'\x00')
        self._version = self.encode_version(version)
        self._build_time = int(build_time.timestamp())
        self._unknow = unknow

    def serialize(self) -> bytes:
        """将 NpkNameInfo 序列化为 36 字节。"""
        return struct.pack(self._format, self._name, self._version, self._build_time, self._unknow)

    @staticmethod
    def unserialize_from(data: bytes) -> 'NpkNameInfo':
        """
        从字节数据反序列化 NpkNameInfo。

        参数:
            data: 36 字节的序列化 NpkNameInfo 数据

        返回:
            NpkNameInfo: 反序列化的对象
        """
        assert len(data) == struct.calcsize(NpkNameInfo._format), 'Invalid data length'
        _name, _version, _build_time, _unknow = struct.unpack_from(NpkNameInfo._format, data)
        return NpkNameInfo(_name.decode(), NpkNameInfo.decode_version(_version), datetime.fromtimestamp(_build_time), _unknow)


class NpkFileContainer:
    """
    NPK 包中的文件容器。

    文件容器包含文件条目列表，每个条目都有元数据
    （权限、时间戳等）和文件数据，全部使用 zlib 压缩。
    """
    _format = '<BB6sIBBBBIIIH'

    @dataclass
    class NpkFileItem:
        """
        表示文件容器内的单个文件条目。

        属性:
            perm: 文件权限（Unix 风格）
            type: 文件类型
            usr_or_grp: 用户或组 ID
            modify_time: 最后修改时间戳
            revision: 文件修订号
            rc: 发布候选号
            minor: 次要版本
            major: 主要版本
            create_time: 创建时间戳
            unknow: 未知字段
            name: 文件名（字节）
            data: 文件内容（字节）
        """
        perm: int
        type: int
        usr_or_grp: int
        modify_time: int
        revision: int
        rc: int
        minor: int
        major: int
        create_time: int
        unknow: int
        name: bytes
        data: bytes

    def __init__(self, items: list['NpkFileContainer.NpkFileItem'] = None):
        """
        使用可选的文件条目列表初始化文件容器。

        参数:
            items: 要包含的 NpkFileItem 对象列表
        """
        self._items = items

    def serialize(self) -> bytes:
        """
        将所有文件条目序列化为 zlib 压缩的字节流。

        每个文件条目都带有其元数据头和数据一起序列化，
        然后使用 zlib 压缩所有条目。

        返回:
            bytes: 压缩后的文件容器数据
        """
        compressed_data = b''
        compressor = zlib.compressobj()
        for item in self._items:
            data = struct.pack(self._format, item.perm, item.type, item.usr_or_grp,
                               item.modify_time, item.revision, item.rc, item.minor,
                               item.major, item.create_time, item.unknow,
                               len(item.data), len(item.name))
            data += item.name + item.data
            compressed_data += compressor.compress(data)
        return compressed_data + compressor.flush()

    @staticmethod
    def unserialize_from(data: bytes):
        """
        解压缩和解析文件容器。

        参数:
            data: 压缩后的文件容器字节

        返回:
            NpkFileContainer: 包含所有解析文件条目的新容器
        """
        items: list['NpkFileContainer.NpkFileItem'] = []
        decompressed_data = zlib.decompress(data)
        while len(decompressed_data):
            offset = struct.calcsize(NpkFileContainer._format)
            (perm, type, usr_or_grp, modify_time, revision, rc, minor, major,
             create_time, unknow, data_size, name_size) = struct.unpack_from(
                NpkFileContainer._format, decompressed_data)
            name = decompressed_data[offset:offset+name_size]
            file_data = decompressed_data[offset+name_size:offset+name_size+data_size]
            items.append(NpkFileContainer.NpkFileItem(
                perm, type, usr_or_grp, modify_time, revision, rc, minor, major,
                create_time, unknow, name, file_data))
            decompressed_data = decompressed_data[offset+name_size+data_size:]
        return NpkFileContainer(items)

    def __len__(self) -> int:
        """返回序列化容器的大小。"""
        return len(self.serialize())

    def __getitem__(self, index: int) -> 'NpkFileContainer.NpkFileItem':
        """按索引获取文件条目。"""
        return self._items[index]

    def __iter__(self):
        """迭代所有文件条目。"""
        for item in self._items:
            yield item


class Package:
    """
    表示 NPK 包的基类。

    包由包含不同类型数据的多个部分组成。
    这是主包和子包的基类。
    """
    def __init__(self) -> None:
        """初始化没有部分的空包。"""
        self._parts: list[NpkPartItem] = []

    def __iter__(self):
        """迭代包中的所有部分。"""
        for part in self._parts:
            yield part

    def __getitem__(self, id: NpkPartID) -> NpkPartItem:
        """
        按 ID 获取部分，如果不存在则创建一个空部分。

        参数:
            id: 要检索的 NpkPartID

        返回:
            NpkPartItem: 具有给定 ID 的部分
        """
        for part in self._parts:
            if part.id == id:
                return part
        part = NpkPartItem(id, b'')
        self._parts.append(part)
        return part


class NovaPackage(Package):
    """
    主 NPK (Nova Package) 文件处理器。

    此类表示完整的 NPK 包文件，可能包含：
    - 主包部分（系统元数据、签名等）
    - 子包（可选功能、模块等）

    此类支持：
    - 从磁盘加载 NPK 文件
    - 解析包结构
    - 使用 KCdsa 和 EdDSA 签署包
    - 验证包签名
    - 保存修改后的包
    """
    NPK_MAGIC = 0xbad0f11e

    def __init__(self, data: bytes = b''):
        """
        通过解析 NPK 数据初始化 NovaPackage。

        参数:
            data: 原始 NPK 文件数据（不包括 8 字节文件头）
        """
        super().__init__()
        self._packages: list[Package] = []
        offset = 0
        self._has_pkg = False
        while offset < len(data):
            part_id, part_size = struct.unpack_from('<HI', data, offset)
            offset += 6
            part_data = data[offset:offset+part_size]
            offset += part_size
            if part_id == NpkPartID.PKG_FEATURES:
                self._has_pkg = True
                self._parts.append(NpkPartItem(NpkPartID(part_id), part_data))
                continue
            if self._has_pkg:
                if part_id == NpkPartID.NAME_INFO:
                    self._packages.append(Package())
                    self._packages[-1]._parts.append(
                        NpkPartItem(NpkPartID(part_id), NpkNameInfo.unserialize_from(part_data)))
                else:
                    self._packages[-1]._parts.append(NpkPartItem(NpkPartID(part_id), part_data))
            else:
                if part_id == NpkPartID.NAME_INFO:
                    self._parts.append(NpkPartItem(NpkPartID(part_id), NpkNameInfo.unserialize_from(part_data)))
                elif part_id == NpkPartID.PKG_INFO:
                    self._parts.append(NpkPartItem(NpkPartID(part_id), NpkInfo.unserialize_from(part_data)))
                else:
                    self._parts.append(NpkPartItem(NpkPartID(part_id), part_data))

    def set_null_block(self):
        """
        在包中设置空（填充）块。

        此方法在存在时重建 SquashFS 镜像并添加空块
        以进行正确的对齐。空块对于有效的 NPK 签名是必需的。

        此方法就地修改包，添加 NULL_BLOCK 部分
        并可能重建 SquashFS 文件系统。
        """
        def rebuild_squashfs(data):
            """提取、修改和重建 SquashFS 文件系统。"""
            with open('squashfs.sfs', 'wb') as f:
                f.write(data)
            os.system('unsquashfs -d squashfs-root squashfs.sfs')
            os.system('rm squashfs.sfs')
            os.system('mksquashfs squashfs-root squashfs.sfs -comp xz -no-xattrs -b 256k')
            os.system('rm -rf squashfs-root')
            with open('squashfs.sfs', 'rb') as f:
                return f.read()

        def get_size(package, size):
            """计算包括头部在内的包总大小。"""
            for part in package._parts:
                size += 6
                size += len(part.data)
            return size

        def set_null(package, offset):
            """向包添加空块以进行正确的对齐。"""
            has_squashfs = False
            for part in package._parts:
                if part.id == NpkPartID.SQUASHFS and len(part.data) >= 4 \
                   and part.data[:4] in [b'hsqs', b'sqsh']:
                    part.data = rebuild_squashfs(part.data)
                    has_squashfs = True
            if has_squashfs:
                count = offset
                for part in package._parts:
                    count += 6
                    if part.id == NpkPartID.NULL_BLOCK:
                        break
                    count += len(part.data)
                count += 6
                pad_len = (4096 - (count % 4096)) % 4096
                package[NpkPartID.NULL_BLOCK].data = b'\x00' * pad_len

        set_null(self, 8)
        offset = get_size(self, 8)
        for package in self._packages:
            set_null(package, offset)
            offset += get_size(package, 0)

    def get_digest(self, hash_func, package: Package = None) -> bytes:
        """
        计算用于签名的包哈希摘要。

        此方法对所有包部分生成哈希（排除 HEADER
        并包括到 SIGNATURE 为止的数据）。生成的摘要用作
        KCdsa 和 EdDSA 签名的基础。

        参数:
            hash_func: 哈希函数对象（例如：hashlib.new('SHA1')）
            package: 要哈希的可选特定包（用于子包）

        返回:
            bytes: 计算出的哈希摘要
        """
        parts = package._parts if package else self._parts
        for part in parts:
            data_header = struct.pack('<HI', part.id.value, len(part.data))
            if part.id == NpkPartID.HEADER:
                continue
            else:
                hash_func.update(data_header)
                if part.id == NpkPartID.SIGNATURE:
                    break
                elif part.data:
                    if isinstance(part.data, bytes):
                        hash_func.update(part.data)
                    else:
                        hash_func.update(part.data.serialize())
        return hash_func.digest()

    def sign(self, kcdsa_private_key: bytes, eddsa_private_key: bytes):
        """
        使用 KCdsa 和 EdDSA 私钥签署包。

        此方法：
        1. 设置空块以进行正确的对齐
        2. 计算 SHA1 和 SHA256 摘要
        3. 使用 KCdsa 和 EdDSA 签署摘要
        4. 将签名存储在 SIGNATURE 部分中

        参数:
            kcdsa_private_key: 用于 KCdsa 签署的 32 字节 Curve25519 私钥
            eddsa_private_key: 用于 EdDSA 签署的 32 字节 Ed25519 私钥

        环境变量:
            BUILD_TIME: 可选的构建时间戳（Unix 时间戳）
        """
        import hashlib
        from mikro import mikro_kcdsa_sign, mikro_eddsa_sign
        build_time = os.getenv('BUILD_TIME', None)
        self.set_null_block()
        if len(self._packages) > 0:
            if build_time:
                self[NpkPartID.PKG_INFO].data._build_time = int(build_time)
            for package in self._packages:
                if len(package[NpkPartID.SIGNATURE].data) != 20+48+64:
                    package[NpkPartID.SIGNATURE].data = b'\0' * (20+48+64)
                if build_time:
                    package[NpkPartID.NAME_INFO].data._build_time = int(build_time)
                sha1_digest = self.get_digest(hashlib.new('SHA1'), package)
                sha256_digest = self.get_digest(hashlib.new('SHA256'), package)
                kcdsa_signature = mikro_kcdsa_sign(sha256_digest[:20], kcdsa_private_key)
                eddsa_signature = mikro_eddsa_sign(sha256_digest, eddsa_private_key)
                package[NpkPartID.SIGNATURE].data = sha1_digest + kcdsa_signature + eddsa_signature
        else:
            if len(self[NpkPartID.SIGNATURE].data) != 20+48+64:
                self[NpkPartID.SIGNATURE].data = b'\0' * (20+48+64)
            if build_time:
                self[NpkPartID.NAME_INFO].data._build_time = int(build_time)
            sha1_digest = self.get_digest(hashlib.new('SHA1'))
            sha256_digest = self.get_digest(hashlib.new('SHA256'))
            kcdsa_signature = mikro_kcdsa_sign(sha256_digest[:20], kcdsa_private_key)
            eddsa_signature = mikro_eddsa_sign(sha256_digest, eddsa_private_key)
            self[NpkPartID.SIGNATURE].data = sha1_digest + kcdsa_signature + eddsa_signature

    def verify(self, kcdsa_public_key: bytes, eddsa_public_key: bytes) -> bool:
        """
        验证包签名。

        此方法验证 KCdsa 和 EdDSA 签名
        以确保包使用相应的私钥签署。

        参数:
            kcdsa_public_key: 用于 KCdsa 验证的 32 字节 Curve25519 公钥
            eddsa_public_key: 用于 EdDSA 验证的 32 字节 Ed25519 公钥

        返回:
            bool: 如果所有签名有效返回 True，否则返回 False
        """
        import hashlib
        from mikro import mikro_kcdsa_verify, mikro_eddsa_verify
        if len(self._packages) > 0:
            for package in self._packages:
                sha1_digest = self.get_digest(hashlib.new('SHA1'), package)
                sha256_digest = self.get_digest(hashlib.new('SHA256'), package)
                signature = package[NpkPartID.SIGNATURE].data
                if sha1_digest != signature[:20]:
                    return False
                if not mikro_kcdsa_verify(sha256_digest[:20], signature[20:68], kcdsa_public_key):
                    return False
                if not mikro_eddsa_verify(sha256_digest, signature[68:132], eddsa_public_key):
                    return False
        else:
            sha1_digest = self.get_digest(hashlib.new('SHA1'))
            sha256_digest = self.get_digest(hashlib.new('SHA256'))
            signature = self[NpkPartID.SIGNATURE].data
            if sha1_digest != signature[:20]:
                return False
            if not mikro_kcdsa_verify(sha256_digest[:20], signature[20:68], kcdsa_public_key):
                return False
            if not mikro_eddsa_verify(sha256_digest, signature[68:132], eddsa_public_key):
                return False
        return True

    def save(self, file):
        """
        将 NovaPackage 保存到文件。

        此方法将包结构序列化并将其写入磁盘
        为 NPK 格式，带有正确的头。

        参数:
            file: 要写入的路径字符串或文件对象
        """
        size = 0
        for part in self._parts:
            size += 6 + len(part.data)
        for package in self._packages:
            for part in package:
                size += 6 + len(part.data)
        with open(file, 'wb') as f:
            f.write(struct.pack('<II', NovaPackage.NPK_MAGIC, size))
            for part in self._parts:
                f.write(struct.pack('<HI', part.id.value, len(part.data)))
                if isinstance(part.data, bytes):
                    f.write(part.data)
                else:
                    f.write(part.data.serialize())
            for package in self._packages:
                for part in package:
                    f.write(struct.pack('<HI', part.id.value, len(part.data)))
                    if isinstance(part.data, bytes):
                        f.write(part.data)
                    else:
                        f.write(part.data.serialize())

    @staticmethod
    def load(file) -> 'NovaPackage':
        """
        从文件加载 NovaPackage。

        参数:
            file: 要读取的路径字符串或文件对象

        返回:
            NovaPackage: 解析后的包对象

        异常:
            AssertionError: 如果文件不是有效的 NPK 格式
        """
        with open(file, 'rb') as f:
            data = f.read()
        assert int.from_bytes(data[:4], 'little') == NovaPackage.NPK_MAGIC, \
            'Invalid Nova Package Magic'
        assert int.from_bytes(data[4:8], 'little') == len(data) - 8, \
            'Invalid Nova Package Size'
        return NovaPackage(data[8:])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='nova 包创建器和编辑器')
    subparsers = parser.add_subparsers(dest="command")
    sign_parser = subparsers.add_parser('sign', help='签署 npk 文件')
    sign_parser.add_argument('input', type=str, help='输入文件')
    sign_parser.add_argument('output', type=str, help='输出文件')
    verify_parser = subparsers.add_parser('verify', help='验证 npk 文件')
    verify_parser.add_argument('input', type=str, help='输入文件')
    create_option_parser = subparsers.add_parser('create', help='创建 option.npk 文件')
    create_option_parser.add_argument('input', type=str, help='来自 npk 文件')
    create_option_parser.add_argument('output', type=str, help='输出文件')
    create_option_parser.add_argument('name', type=str, help='NPK 名称')
    create_option_parser.add_argument('squashfs', type=str, help='NPK squashfs 文件')
    create_option_parser.add_argument('-desc', '--description', type=str, help='NPK 描述')
    args = parser.parse_args()
    kcdsa_private_key = bytes.fromhex(os.environ['CUSTOM_LICENSE_PRIVATE_KEY'])
    eddsa_private_key = bytes.fromhex(os.environ['CUSTOM_NPK_SIGN_PRIVATE_KEY'])
    kcdsa_public_key = bytes.fromhex(os.environ['CUSTOM_LICENSE_PUBLIC_KEY'])
    eddsa_public_key = bytes.fromhex(os.environ['CUSTOM_NPK_SIGN_PUBLIC_KEY'])

    if args.command == 'sign':
        print(f'签署 {args.input}')
        npk = NovaPackage.load(args.input)
        npk.sign(kcdsa_private_key, eddsa_private_key)
        npk.save(args.output)
    elif args.command == 'verify':
        npk = NovaPackage.load(args.input)
        print(f'验证 {args.input} ', end="")
        if npk.verify(kcdsa_public_key, eddsa_public_key):
            print('有效')
            exit(0)
        else:
            print('无效')
            exit(-1)
    elif args.command == 'create':
        print(f'从 {args.input} 创建 {args.output}')
        option_npk = NovaPackage.load(args.input)
        option_npk[NpkPartID.NAME_INFO].data.name = args.name
        option_npk[NpkPartID.DESCRIPTION].data = args.description.encode() if args.description else args.name.encode()
        option_npk[NpkPartID.NULL_BLOCK].data = b''
        option_npk[NpkPartID.SQUASHFS].data = open(args.squashfs, 'rb').read()
        option_npk.sign(kcdsa_private_key, eddsa_private_key)
        option_npk.save(args.output)
        print(f'已创建 {args.output}')
    else:
        parser.print_help()
