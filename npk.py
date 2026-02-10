"""
NPK (Nova Package) Format Module

This module provides classes and functions for handling MikroTik's NPK (Nova Package) format.
NPK is the package format used by MikroTik RouterOS for system packages, optional packages,
and license packages.

The module supports:
- Parsing NPK files
- Creating NPK files
- Signing NPK packages with KCdsa and EdDSA
- Verifying NPK package signatures
- Extracting and modifying package contents

NPK Format Structure:
- NPK_MAGIC: 0xbad0f11e (little-endian)
- Package size (excluding 8-byte header)
- Multiple parts (parts) containing different types of data:
  - NAME_INFO: Package name and version information
  - DESCRIPTION: Package description
  - DEPENDENCIES: Package dependencies
  - FILE_CONTAINER: Compressed file container
  - INSTALL_SCRIPT: Installation script
  - UNINSTALL_SCRIPT: Uninstallation script
  - SIGNATURE: Package signature (SHA1 + KCdsa + EdDSA)
  - ARCHITECTURE: Package architecture
  - PKG_CONFLICTS: Package conflicts
  - FEATURES: Package features
  - SQUASHFS: SquashFS filesystem image
  - NULL_BLOCK: Padding blocks
  - GIT_COMMIT: Git commit hash
  - CHANNEL: Release channel (stable, testing, etc.)
  - HEADER: Package header
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
    Enumeration of NPK part (section) IDs.

    Each part ID represents a different type of data within an NPK package.
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
    Represents a single part (section) within an NPK package.

    Attributes:
        id: The NpkPartID identifying the type of this part.
        data: The binary data or object contained in this part.
    """
    id: NpkPartID
    data: bytes | object


class NpkInfo:
    """
    Base class for NPK package information metadata.

    This class handles the package name and version information structure
    found in older NPK format versions.
    """
    _format = '<16s4sI8s'

    def __init__(self, name: str, version: str, build_time=datetime.now(), unknow=b'\x00'*8):
        """
        Initializes NpkInfo with package name, version, and build timestamp.

        Args:
            name: Package name (max 16 characters).
            version: Version string (e.g., '7.15.1.final').
            build_time: Datetime of package build (defaults to current time).
            unknow: Unknown 8-byte field (padding/reserved).
        """
        self._name = name[:16].encode().ljust(16, b'\x00')
        self._version = self.encode_version(version)
        self._build_time = int(build_time.timestamp())
        self._unknow = unknow

    def serialize(self) -> bytes:
        """
        Serializes the NpkInfo structure to bytes for inclusion in NPK.

        Returns:
            bytes: The serialized 32-byte NpkInfo structure.
        """
        return struct.pack(self._format, self._name, self._version, self._build_time, self._unknow)

    @staticmethod
    def unserialize_from(data: bytes) -> 'NpkInfo':
        """
        Deserializes NpkInfo from byte data.

        Args:
            data: 32 bytes of serialized NpkInfo data.

        Returns:
            NpkInfo: The deserialized NpkInfo object.

        Raises:
            AssertionError: If data length is invalid.
        """
        assert len(data) == struct.calcsize(NpkInfo._format), 'Invalid data length'
        _name, _version, _build_time, unknow = struct.unpack_from(NpkInfo._format, data)
        return NpkInfo(_name.decode(), NpkInfo.decode_version(_version), datetime.fromtimestamp(_build_time), unknow)

    def __len__(self) -> int:
        """Returns the size of the serialized NpkInfo structure (32 bytes)."""
        return struct.calcsize(self._format)

    @property
    def name(self) -> str:
        """Gets the package name, stripped of null padding."""
        return self._name.decode().strip('\x00')

    @name.setter
    def name(self, value: str):
        """Sets the package name (truncated to 16 chars, null-padded)."""
        self._name = value[:16].encode().ljust(16, b'\x00')

    @staticmethod
    def decode_version(value: bytes) -> str:
        """
        Decodes a 4-byte version value into a version string.

        The version format is: major.minor.revision.build_type
        where build_type can be: alpha, beta, rc, final, test

        Args:
            value: 4 bytes containing version information.

        Returns:
            str: Decoded version string.
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
        Encodes a version string into 4 bytes.

        Args:
            value: Version string (e.g., '7.15.1.final').

        Returns:
            bytes: 4 bytes of encoded version data.

        Raises:
            ValueError: If version string format is invalid.
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
        """Gets the package version string."""
        return self.decode_version(self._version)

    @version.setter
    def version(self, value: str = '7.15.1.final'):
        """Sets the package version string."""
        self._version = self.encode_version(value)

    @property
    def build_time(self):
        """Gets the package build timestamp as datetime."""
        return datetime.fromtimestamp(self._build_time)

    @build_time.setter
    def build_time(self, value: datetime):
        """Sets the package build timestamp from datetime."""
        self._build_time = int(value.timestamp())


class NpkNameInfo(NpkInfo):
    """
    Extended NPK name information structure.

    This class represents the newer NAME_INFO format used in main NPK packages,
    with an additional 12-byte unknown field compared to the base NpkInfo.
    """
    _format = '<16s4sI12s'

    def __init__(self, name: str, version: str, build_time=datetime.now(), unknow=b'\x00'*12):
        """
        Initializes NpkNameInfo with extended structure.

        Args:
            name: Package name (max 16 characters).
            version: Version string.
            build_time: Build timestamp.
            unknow: 12-byte unknown/padding field.
        """
        self._name = name[:16].encode().ljust(16, b'\x00')
        self._version = self.encode_version(version)
        self._build_time = int(build_time.timestamp())
        self._unknow = unknow

    def serialize(self) -> bytes:
        """Serializes NpkNameInfo to 36 bytes."""
        return struct.pack(self._format, self._name, self._version, self._build_time, self._unknow)

    @staticmethod
    def unserialize_from(data: bytes) -> 'NpkNameInfo':
        """
        Deserializes NpkNameInfo from byte data.

        Args:
            data: 36 bytes of serialized NpkNameInfo data.

        Returns:
            NpkNameInfo: The deserialized object.
        """
        assert len(data) == struct.calcsize(NpkNameInfo._format), 'Invalid data length'
        _name, _version, _build_time, _unknow = struct.unpack_from(NpkNameInfo._format, data)
        return NpkNameInfo(_name.decode(), NpkNameInfo.decode_version(_version), datetime.fromtimestamp(_build_time), _unknow)


class NpkFileContainer:
    """
    Container for files within an NPK package.

    The file container holds a list of file entries, each with metadata
    (permissions, timestamps, etc.) and file data, all compressed with zlib.
    """
    _format = '<BB6sIBBBBIIIH'

    @dataclass
    class NpkFileItem:
        """
        Represents a single file entry within the file container.

        Attributes:
            perm: File permissions (Unix-style).
            type: File type.
            usr_or_grp: User or group ID.
            modify_time: Last modification timestamp.
            revision: File revision number.
            rc: Release candidate number.
            minor: Minor version.
            major: Major version.
            create_time: Creation timestamp.
            unknow: Unknown field.
            name: Filename (bytes).
            data: File contents (bytes).
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
        Initializes the file container with optional list of file items.

        Args:
            items: List of NpkFileItem objects to include.
        """
        self._items = items

    def serialize(self) -> bytes:
        """
        Serializes all file items into a zlib-compressed byte stream.

        Each file item is serialized with its metadata header and data,
        then all items are compressed together using zlib.

        Returns:
            bytes: Compressed file container data.
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
        Decompresses and parses a file container.

        Args:
            data: Compressed file container bytes.

        Returns:
            NpkFileContainer: A new container with all file items parsed.
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
        """Returns the size of the serialized container."""
        return len(self.serialize())

    def __getitem__(self, index: int) -> 'NpkFileContainer.NpkFileItem':
        """Gets a file item by index."""
        return self._items[index]

    def __iter__(self):
        """Iterates over all file items."""
        for item in self._items:
            yield item


class Package:
    """
    Base class representing an NPK package.

    A package consists of multiple parts (parts) containing different types
    of data. This is the base class for both main packages and sub-packages.
    """
    def __init__(self) -> None:
        """Initializes an empty package with no parts."""
        self._parts: list[NpkPartItem] = []

    def __iter__(self):
        """Iterates over all parts in the package."""
        for part in self._parts:
            yield part

    def __getitem__(self, id: NpkPartID) -> NpkPartItem:
        """
        Gets a part by its ID, creating an empty one if not found.

        Args:
            id: The NpkPartID to retrieve.

        Returns:
            NpkPartItem: The part with the given ID.
        """
        for part in self._parts:
            if part.id == id:
                return part
        part = NpkPartItem(id, b'')
        self._parts.append(part)
        return part


class NovaPackage(Package):
    """
    Main NPK (Nova Package) file handler.

    This class represents a complete NPK package file, which may contain:
    - Main package parts (system metadata, signatures, etc.)
    - Sub-packages (optional features, modules, etc.)

    The class supports:
    - Loading NPK files from disk
    - Parsing package structure
    - Signing packages with KCdsa and EdDSA
    - Verifying package signatures
    - Saving modified packages
    """
    NPK_MAGIC = 0xbad0f11e

    def __init__(self, data: bytes = b''):
        """
        Initializes a NovaPackage by parsing NPK data.

        Args:
            data: Raw NPK file data (excluding the 8-byte file header).
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
        Sets null (padding) blocks in the package.

        This method rebuilds SquashFS images if present and adds null blocks
        for proper alignment. Null blocks are required for valid NPK signatures.

        The method modifies the package in-place, adding NULL_BLOCK parts
        and potentially rebuilding SquashFS filesystems.
        """
        def rebuild_squashfs(data):
            """Extracts, modifies, and rebuilds a SquashFS filesystem."""
            with open('squashfs.sfs', 'wb') as f:
                f.write(data)
            os.system('unsquashfs -d squashfs-root squashfs.sfs')
            os.system('rm squashfs.sfs')
            os.system('mksquashfs squashfs-root squashfs.sfs -comp xz -no-xattrs -b 256k')
            os.system('rm -rf squashfs-root')
            with open('squashfs.sfs', 'rb') as f:
                return f.read()

        def get_size(package, size):
            """Calculates the total size of a package including headers."""
            for part in package._parts:
                size += 6
                size += len(part.data)
            return size

        def set_null(package, offset):
            """Adds null blocks to a package for proper alignment."""
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
        Computes the hash digest of a package for signing.

        This method generates a hash over all package parts (excluding HEADER
        and including data up to SIGNATURE). The resulting digest is used
        as the basis for KCdsa and EdDSA signatures.

        Args:
            hash_func: Hash function object (e.g., hashlib.new('SHA1')).
            package: Optional specific package to hash (for sub-packages).

        Returns:
            bytes: The computed hash digest.
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
        Signs the package with KCdsa and EdDSA private keys.

        This method:
        1. Sets null blocks for proper alignment
        2. Computes SHA1 and SHA256 digests
        3. Signs digests with KCdsa and EdDSA
        4. Stores signatures in the SIGNATURE part

        Args:
            kcdsa_private_key: 32-byte Curve25519 private key for KCdsa signing.
            eddsa_private_key: 32-byte Ed25519 private key for EdDSA signing.

        Environment Variables:
            BUILD_TIME: Optional build timestamp (Unix timestamp).
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
        Verifies the package signature.

        This method validates both the KCdsa and EdDSA signatures
        to ensure the package was signed with the corresponding private keys.

        Args:
            kcdsa_public_key: 32-byte Curve25519 public key for KCdsa verification.
            eddsa_public_key: 32-byte Ed25519 public key for EdDSA verification.

        Returns:
            bool: True if all signatures are valid, False otherwise.
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
        Saves the NovaPackage to a file.

        This method serializes the package structure and writes it to disk
        in NPK format with proper headers.

        Args:
            file: Path string or file object to write to.
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
        Loads a NovaPackage from a file.

        Args:
            file: Path string or file object to read from.

        Returns:
            NovaPackage: The parsed package object.

        Raises:
            AssertionError: If file is not a valid NPK format.
        """
        with open(file, 'rb') as f:
            data = f.read()
        assert int.from_bytes(data[:4], 'little') == NovaPackage.NPK_MAGIC, \
            'Invalid Nova Package Magic'
        assert int.from_bytes(data[4:8], 'little') == len(data) - 8, \
            'Invalid Nova Package Size'
        return NovaPackage(data[8:])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='nova package creator and editor')
    subparsers = parser.add_subparsers(dest="command")
    sign_parser = subparsers.add_parser('sign', help='sign npk file')
    sign_parser.add_argument('input', type=str, help='Input file')
    sign_parser.add_argument('output', type=str, help='Output file')
    verify_parser = subparsers.add_parser('verify', help='Verify npk file')
    verify_parser.add_argument('input', type=str, help='Input file')
    create_option_parser = subparsers.add_parser('create', help='Create option.npk file')
    create_option_parser.add_argument('input', type=str, help='From npk file')
    create_option_parser.add_argument('output', type=str, help='Output file')
    create_option_parser.add_argument('name', type=str, help='NPK name')
    create_option_parser.add_argument('squashfs', type=str, help='NPK squashfs file')
    create_option_parser.add_argument('-desc', '--description', type=str, help='NPK description')
    args = parser.parse_args()
    kcdsa_private_key = bytes.fromhex(os.environ['CUSTOM_LICENSE_PRIVATE_KEY'])
    eddsa_private_key = bytes.fromhex(os.environ['CUSTOM_NPK_SIGN_PRIVATE_KEY'])
    kcdsa_public_key = bytes.fromhex(os.environ['CUSTOM_LICENSE_PUBLIC_KEY'])
    eddsa_public_key = bytes.fromhex(os.environ['CUSTOM_NPK_SIGN_PUBLIC_KEY'])

    if args.command == 'sign':
        print(f'Signing {args.input}')
        npk = NovaPackage.load(args.input)
        npk.sign(kcdsa_private_key, eddsa_private_key)
        npk.save(args.output)
    elif args.command == 'verify':
        npk = NovaPackage.load(args.input)
        print(f'Verifying {args.input} ', end="")
        if npk.verify(kcdsa_public_key, eddsa_public_key):
            print('Valid')
            exit(0)
        else:
            print('Invalid')
            exit(-1)
    elif args.command == 'create':
        print(f'Creating {args.output} from {args.input}')
        option_npk = NovaPackage.load(args.input)
        option_npk[NpkPartID.NAME_INFO].data.name = args.name
        option_npk[NpkPartID.DESCRIPTION].data = args.description.encode() if args.description else args.name.encode()
        option_npk[NpkPartID.NULL_BLOCK].data = b''
        option_npk[NpkPartID.SQUASHFS].data = open(args.squashfs, 'rb').read()
        option_npk.sign(kcdsa_private_key, eddsa_private_key)
        option_npk.save(args.output)
        print(f'Created {args.output}')
    else:
        parser.print_help()
