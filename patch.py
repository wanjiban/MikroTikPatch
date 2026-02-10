"""
MikroTik RouterOS 补丁模块

本模块提供用于通过替换公钥和修改各种组件来修补
MikroTik RouterOS 固件镜像的函数。

功能：
- 替换内核镜像中的公钥（bzImage、ELF、initrd）
- 修补 PE 和 ELF 格式的引导加载程序
- 修改 SquashFS 文件系统
- 替换许可证、升级、云和续订端点的 URL
- 修补 netinstall 镜像
- 直接修补块设备

修补过程通常包括：
1. 在二进制数据中定位公钥或 URL
2. 使用自定义密钥/URL 替换它
3. 重新签署 NPK 包（如果适用）

此模块由 GitHub Actions 工作流使用，用于自动生成
各种架构（x86、ARM、MIPS 等）的修补 RouterOS 镜像。
"""

import subprocess
import lzma
import struct
import os
import re
from npk import NovaPackage, NpkPartID, NpkFileContainer


def replace_chunks(old_chunks, new_chunks, data, name):
    """
    使用正则表达式模式匹配替换字节字符串中的多个数据块。

    此函数用于替换分成多个块且带有可变长度分隔符的公钥。
    它在替换实际密钥数据的同时保留块之间的分隔符字节。

    参数:
        old_chunks: 表示原始数据块的字节字符串列表
        new_chunks: 表示替换数据块的字节字符串列表
        data: 要搜索和替换的完整字节字符串
        name: 用于日志记录的名称标识符

    返回:
        bytes: 用新块替换旧块后的修改数据
    """
    pattern_parts = [re.escape(chunk) + b'(.{0,6})' for chunk in old_chunks[:-1]]
    pattern_parts.append(re.escape(old_chunks[-1]))
    pattern_bytes = b''.join(pattern_parts)
    pattern = re.compile(pattern_bytes, flags=re.DOTALL)

    def replace_match(match):
        """保留分隔符字节的替换函数。"""
        replaced = b''.join([new_chunks[i] + match.group(i+1) for i in range(len(new_chunks) - 1)])
        replaced += new_chunks[-1]
        print(f'{name} 公钥已修补 {b"".join(old_chunks)[:16].hex().upper()}...')
        return replaced
    return re.sub(pattern, replace_match, data)


def replace_key(old, new, data, name=''):
    """
    替换二进制数据中的公钥，支持多种密钥格式。

    此函数处理各种密钥表示格式：
    1. 连续的 4 字节块
    2. 洗牌的字节顺序（key_map 置换）
    3. ARM32 大端块
    4. ARM64 压缩格式

    参数:
        old: 要替换的原始公钥字节
        new: 替换后的公钥字节
        data: 要搜索和修改的二进制数据
        name: 用于日志记录的可选名称标识符

    返回:
        bytes: 替换密钥后的修改数据
    """
    old_chunks = [old[i:i+4] for i in range(0, len(old), 4)]
    new_chunks = [new[i:i+4] for i in range(0, len(new), 4)]
    data = replace_chunks(old_chunks, new_chunks, data, name)

    key_map = [28, 19, 25, 16, 14, 3, 24, 15, 22, 8, 6, 17, 11, 7, 9, 23,
               18, 13, 10, 0, 26, 21, 2, 5, 20, 30, 31, 4, 27, 29, 1, 12]
    old_chunks = [bytes([old[i]]) for i in key_map]
    new_chunks = [bytes([new[i]]) for i in key_map]
    data = replace_chunks(old_chunks, new_chunks, data, name)

    arch = os.getenv('ARCH') or 'x86'
    arch = arch.replace('-', '')
    if arch in ['arm64', 'arm']:
        old_chunks = [old[i:i+4] for i in range(0, len(old), 4)]
        new_chunks = [new[i:i+4] for i in range(0, len(new), 4)]
        old_bytes = (old_chunks[4] + old_chunks[5] + old_chunks[2] + old_chunks[0] +
                     old_chunks[1] + old_chunks[6] + old_chunks[7])
        new_bytes = (new_chunks[4] + new_chunks[5] + new_chunks[2] + new_chunks[0] +
                     new_chunks[1] + new_chunks[6] + new_chunks[7])
        if old_bytes in data:
            print(f'{name} 公钥已修补 {old[:16].hex().upper()}...')
            data = data.replace(old_bytes, new_bytes)
            old_codes = [bytes.fromhex('793583E2'), bytes.fromhex('FD3A83E2'),
                         bytes.fromhex('193D83E2')]
            new_codes = [bytes.fromhex('FF34A0E3'), bytes.fromhex('753C83E2'),
                         bytes.fromhex('FC3083E2')]
            data = replace_chunks(old_codes, new_codes, data, name)
        else:
            def conver_chunks(data: bytes):
                """将字节转换为 ARM 特定的 32 位小端字。"""
                ret = [
                    (data[2] << 16) | (data[1] << 8) | data[0] | ((data[3] << 24) & 0x03000000),
                    (data[3] >> 2) | (data[4] << 6) | (data[5] << 14) | ((data[6] << 22) & 0x1C00000),
                    (data[6] >> 3) | (data[7] << 5) | (data[8] << 13) | ((data[9] << 21) & 0x3E00000),
                    (data[9] >> 5) | (data[10] << 3) | (data[11] << 11) | ((data[12] << 19) & 0x1F80000),
                    (data[12] >> 6) | (data[13] << 2) | (data[14] << 10) | (data[15] << 18),
                    data[16] | (data[17] << 8) | (data[18] << 16) | ((data[19] << 24) & 0x01000000),
                    (data[19] >> 1) | (data[20] << 7) | (data[21] << 15) | ((data[22] << 23) & 0x03800000),
                    (data[22] >> 3) | (data[23] << 5) | (data[24] << 13) | ((data[25] << 21) & 0x1E00000),
                    (data[25] >> 4) | (data[26] << 4) | (data[27] << 12) | ((data[28] << 20) & 0x3F00000),
                    (data[28] >> 6) | (data[29] << 2) | (data[30] << 10) | (data[31] << 18)
                ]
                return [struct.pack('<I', x) for x in ret]
            old_chunks = conver_chunks(old)
            new_chunks = conver_chunks(new)
            old_bytes = b''.join([v for i, v in enumerate(old_chunks) if i != 8])
            new_bytes = b''.join([v for i, v in enumerate(new_chunks) if i != 8])
            if old_bytes in data:
                print(f'{name} 公钥已修补 {old[:16].hex().upper()}...')
                data = data.replace(old_bytes, new_bytes)
                old_codes = [bytes.fromhex('713783E2'), bytes.fromhex('223A83E2'),
                             bytes.fromhex('8D3F83E2')]
                new_codes = [bytes.fromhex('973303E3'), bytes.fromhex('DD3883E3'),
                             bytes.fromhex('033483E3')]
                data = replace_chunks(old_codes, new_codes, data, name)

    return data


def patch_bzimage(data: bytes, key_dict: dict) -> bytes:
    """
    通过替换 initramfs 中的公钥来修补 bzImage（x86_64 EFI 内核）。

    RouterOS 使用的 bzImage 格式包含：
    1. PE/EFI 头
    2. 包含以下内容的 XZ 压缩有效载荷：
       - Linux 内核（vmlinux）
       - 带有公钥的 CPIO 存档（initramfs）

    此函数：
    1. 提取 XZ 压缩的有效载荷
    2. 定位 CPIO initramfs 存档
    3. 替换 initramfs 中的公钥
    4. 重新压缩并打包 bzImage

    参数:
        data: 原始 bzImage 字节
        key_dict: 将旧公钥映射到新公钥的字典

    返回:
        bytes: 修补后的 bzImage 字节
    """
    PE_TEXT_SECTION_OFFSET = 414
    HEADER_PAYLOAD_OFFSET = 584
    HEADER_PAYLOAD_LENGTH_OFFSET = HEADER_PAYLOAD_OFFSET + 4

    text_section_raw_data = struct.unpack_from('<I', data, PE_TEXT_SECTION_OFFSET)[0]
    payload_offset = text_section_raw_data + struct.unpack_from('<I', data, HEADER_PAYLOAD_OFFSET)[0]
    payload_length = struct.unpack_from('<I', data, HEADER_PAYLOAD_LENGTH_OFFSET)[0]
    payload_length = payload_length - 4
    z_output_len = struct.unpack_from('<I', data, payload_offset + payload_length)[0]

    vmlinux_xz = data[payload_offset:payload_offset + payload_length]
    vmlinux = lzma.decompress(vmlinux_xz)
    assert z_output_len == len(vmlinux), 'vmlinux 大小与预期不符'

    CPIO_HEADER_MAGIC = b'07070100'
    CPIO_FOOTER_MAGIC = b'TRAILER!!!\x00\x00\x00\x00'

    cpio_offset1 = vmlinux.index(CPIO_HEADER_MAGIC)
    initramfs = vmlinux[cpio_offset1:]
    cpio_offset2 = initramfs.index(CPIO_FOOTER_MAGIC) + len(CPIO_FOOTER_MAGIC)
    initramfs = initramfs[:cpio_offset2]

    new_initramfs = initramfs
    for old_public_key, new_public_key in key_dict.items():
        new_initramfs = replace_key(old_public_key, new_public_key, new_initramfs, 'initramfs')

    new_vmlinux = vmlinux.replace(initramfs, new_initramfs)
    new_vmlinux_xz = lzma.compress(new_vmlinux, check=lzma.CHECK_CRC32, filters=[
        {"id": lzma.FILTER_X86},
        {"id": lzma.FILTER_LZMA2,
         "preset": 9 | lzma.PRESET_EXTREME,
         'dict_size': 32*1024*1024,
         "lc": 4, "lp": 0, "pb": 0},
    ])

    new_payload_length = len(new_vmlinux_xz)
    assert new_payload_length <= payload_length, '新的 vmlinux.xz 大小太大'
    new_payload_length = new_payload_length + 4

    new_data = bytearray(data)
    struct.pack_into('<I', new_data, HEADER_PAYLOAD_LENGTH_OFFSET, new_payload_length)
    vmlinux_xz += struct.pack('<I', z_output_len)
    new_vmlinux_xz += struct.pack('<I', z_output_len)
    new_vmlinux_xz = new_vmlinux_xz.ljust(len(vmlinux_xz), b'\0')
    new_data = new_data.replace(vmlinux_xz, new_vmlinux_xz)

    return new_data


def patch_block(dev: str, file: str, key_dict):
    """
    通过修改单个块来修补块设备中的文件。

    此函数使用 debugfs 来：
    1. 定位文件在设备上的块
    2. 读取文件数据
    3. 应用内核修补
    4. 将修改后的数据写回原始块位置

    参数:
        dev: 块设备路径（例如：'/dev/nbd0p1'）
        file: 文件系统内的文件路径（例如：'boot/initrd.rgz'）
        key_dict: 将旧公钥映射到新公钥的字典
    """
    BLOCK_SIZE = 4096

    stdout, _ = run_shell_command(
        f"debugfs {dev} -R 'stat {file}' 2> /dev/null | sed -n '11p' ")

    blocks_info = stdout.decode().strip().split(',')
    print(f'blocks_info : {blocks_info}')
    blocks = []
    ind_block_id = None

    for block_info in blocks_info:
        _tmp = block_info.strip().split(':')
        if _tmp[0].strip() == '(IND)':
            ind_block_id = int(_tmp[1])
        else:
            print(f'block_info : {block_info}')
            id_range = _tmp[0].strip().replace('(', '').replace(')', '').split('-')
            block_range = _tmp[1].strip().replace('(', '').replace(')', '').split('-')
            blocks += [id for id in range(int(block_range[0]), int(block_range[1]) + 1)]

    print(f' blocks : {len(blocks)} ind_block_id : {ind_block_id}')

    data, stderr = run_shell_command(
        f"debugfs {dev} -R 'cat {file}' 2> /dev/null")
    new_data = patch_kernel(data, key_dict)

    print(f'write block {len(blocks)} : [', end="")
    with open(dev, 'wb') as f:
        for index, block_id in enumerate(blocks):
            print('#', end="")
            f.seek(block_id * BLOCK_SIZE)
            f.write(new_data[index * BLOCK_SIZE:(index + 1) * BLOCK_SIZE])
        f.flush()
    print(']')


def patch_initrd_xz(initrd_xz: bytes, key_dict: dict, ljust=True) -> bytes:
    """
    修补 XZ 压缩的 initramfs/initrd 镜像。

    此函数：
    1. 解压缩 initrd XZ 数据
    2. 替换文件内容中的所有公钥
    3. 根据需要调整压缩级别后重新压缩

    参数:
        initrd_xz: 原始 XZ 压缩的 initrd 字节
        key_dict: 将旧公钥映射到新公钥的字典
        ljust: 如果为 True，将输出填充到原始大小（默认为 True）

    返回:
        bytes: 修补后的 XZ 压缩 initrd 数据
    """
    initrd = lzma.decompress(initrd_xz)
    new_initrd = initrd

    for old_public_key, new_public_key in key_dict.items():
        new_initrd = replace_key(old_public_key, new_public_key, new_initrd, 'initrd')

    preset = 6
    new_initrd_xz = lzma.compress(new_initrd, check=lzma.CHECK_CRC32,
                                   filters=[{"id": lzma.FILTER_LZMA2, "preset": preset}])

    while len(new_initrd_xz) > len(initrd_xz) and preset < 9:
        print(f'preset:{preset}')
        print(f'新的 initrd xz 大小:{len(new_initrd_xz)}')
        print(f'旧的 initrd xz 大小:{len(initrd_xz)}')
        preset += 1
        new_initrd_xz = lzma.compress(new_initrd, check=lzma.CHECK_CRC32,
                                       filters=[{"id": lzma.FILTER_LZMA2, "preset": preset}])

    if len(new_initrd_xz) > len(initrd_xz):
        new_initrd_xz = lzma.compress(new_initrd, check=lzma.CHECK_CRC32,
                                       filters=[{"id": lzma.FILTER_LZMA2, "preset": 9 | lzma.PRESET_EXTREME,
                                                'dict_size': 32*1024*1024, "lc": 4, "lp": 0, "pb": 0}])

    if ljust:
        print(f'preset:{preset}')
        print(f'新的 initrd xz 大小:{len(new_initrd_xz)}')
        print(f'旧的 initrd xz 大小:{len(initrd_xz)}')
        print(f'ljust 大小:{len(initrd_xz) - len(new_initrd_xz)}')
        assert len(new_initrd_xz) <= len(initrd_xz), '新的 initrd xz 大小太大'
        new_initrd_xz = new_initrd_xz.ljust(len(initrd_xz), b'\0')

    return new_initrd_xz


def find_7zXZ_data(data: bytes) -> bytes:
    """
    在较大的二进制文件中定位嵌入的 7zXZ（LZMA）数据。

    此函数搜索 7zXZ 魔数字节并找到相应的
    结束标记以提取完整的 LZMA 压缩数据块。

    参数:
        data: 可能包含 7zXZ 数据的二进制数据

    返回:
        bytes: 提取的 7zXZ 数据块
    """
    offset1 = 0
    _data = data
    while b'\xFD7zXZ\x00\x00\x01' in _data:
        offset1 = offset1 + _data.index(b'\xFD7zXZ\x00\x00\x01') + 8
        _data = _data[offset1:]
    offset1 -= 8

    offset2 = 0
    _data = data
    while b'\x00\x00\x00\x00\x01\x59\x5A' in _data:
        offset2 = offset2 + _data.index(b'\x00\x00\x00\x00\x01\x59\x5A') + 7
        _data = _data[offset2:]

    print(f'找到 7zXZ 数据偏移:{offset1} 大小:{offset2 - offset1}')
    return data[offset1:offset2]


def patch_elf(data: bytes, key_dict: dict) -> bytes:
    """
    修补包含嵌入 initrd 的 ELF 二进制文件。

    此函数：
    1. 在 ELF 中查找 7zXZ initrd 数据
    2. 修补 initrd
    3. 返回修改后的 ELF 二进制文件

    参数:
        data: 原始 ELF 二进制字节
        key_dict: 将旧公钥映射到新公钥的字典

    返回:
        bytes: 修补后的 ELF 二进制字节
    """
    initrd_xz = find_7zXZ_data(data)
    new_initrd_xz = patch_initrd_xz(initrd_xz, key_dict)
    return data.replace(initrd_xz, new_initrd_xz)


def patch_pe(data: bytes, key_dict: dict) -> bytes:
    """
    修补包含嵌入 vmlinux 的 PE（Windows EFI）二进制文件。

    PE 文件包含 XZ 压缩的 vmlinux，vmlinux 本身包含
    嵌入的 initrd。此函数修补两层。

    参数:
        data: 原始 PE 二进制字节
        key_dict: 将旧公钥映射到新公钥的字典

    返回:
        bytes: 修补后的 PE 二进制字节
    """
    vmlinux_xz = find_7zXZ_data(data)
    vmlinux = lzma.decompress(vmlinux_xz)

    initrd_xz_offset = vmlinux.index(b'\xFD7zXZ\x00\x00\x01')
    initrd_xz_size = vmlinux[initrd_xz_offset:].index(b'\x00\x00\x00\x00\x01\x59\x5A') + 7
    initrd_xz = vmlinux[initrd_xz_offset:initrd_xz_offset + initrd_xz_size]

    new_initrd_xz = patch_initrd_xz(initrd_xz, key_dict)

    new_vmlinux = vmlinux.replace(initrd_xz, new_initrd_xz)
    new_vmlinux_xz = lzma.compress(new_vmlinux, check=lzma.CHECK_CRC32,
                                    filters=[{"id": lzma.FILTER_LZMA2, "preset": 9}])

    assert len(new_vmlinux_xz) <= len(vmlinux_xz), '新的 vmlinux xz 大小太大'
    print(f'新的 vmlinux xz 大小:{len(new_vmlinux_xz)}')
    print(f'旧的 vmlinux xz 大小:{len(vmlinux_xz)}')
    print(f'ljust 大小:{len(vmlinux_xz) - len(new_vmlinux_xz)}')
    new_vmlinux_xz = new_vmlinux_xz.ljust(len(vmlinux_xz), b'\0')
    new_data = data.replace(vmlinux_xz, new_vmlinux_xz)

    return new_data


def patch_netinstall(key_dict: dict, input_file, output_file=None):
    """
    修补 RouterOS netinstall 可执行文件。

    Netinstall 文件是包含各种架构嵌入引导加载程序的 PE 可执行文件。
    此函数：
    1. 从资源中提取嵌入的引导加载程序
    2. 修补每个引导加载程序
    3. 用修补后的引导加载程序更新 PE 资源

    参数:
        key_dict: 将旧公钥映射到新公钥的字典
        input_file: 输入 netinstall PE 文件的路径
        output_file: 可选的输出文件路径（默认为覆盖输入）
    """
    netinstall = open(input_file, 'rb').read()

    if netinstall[:2] == b'MZ':
        from package import check_install_package
        check_install_package(['pefile'])
        import pefile

        ROUTEROS_BOOT = {
            129: {'arch': 'power', 'name': 'Powerboot'},
            130: {'arch': 'e500', 'name': 'e500_boot'},
            131: {'arch': 'mips', 'name': 'Mips_boot'},
            135: {'arch': '400', 'name': '440__boot'},
            136: {'arch': 'tile', 'name': 'tile_boot'},
            137: {'arch': 'arm', 'name': 'ARM__boot'},
            138: {'arch': 'mmips', 'name': 'MMipsBoot'},
            139: {'arch': 'arm64', 'name': 'ARM64__boot'},
            143: {'arch': 'x86_64', 'name': 'x86_64boot'}
        }

        with pefile.PE(input_file) as pe:
            for resource in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if resource.id == pefile.RESOURCE_TYPE["RT_RCDATA"]:
                    for sub_resource in resource.directory.entries:
                        if sub_resource.id in ROUTEROS_BOOT:
                            bootloader = ROUTEROS_BOOT[sub_resource.id]
                            print(f'找到 {bootloader["arch"]}({sub_resource.id}) 引导加载程序')
                            rva = sub_resource.directory.entries[0].data.struct.OffsetToData
                            size = sub_resource.directory.entries[0].data.struct.Size
                            data = pe.get_data(rva, size)
                            _size = struct.unpack('<I', data[:4])[0]
                            _data = data[4:4 + _size]

                            try:
                                if _data[:2] == b'MZ':
                                    new_data = patch_pe(_data, key_dict)
                                elif _data[:4] == b'\x7FELF':
                                    new_data = patch_elf(_data, key_dict)
                                else:
                                    raise Exception(f'未知的引导加载程序格式 {_data[:4].hex().upper()}')
                            except Exception as e:
                                print(f'修补 {bootloader["arch"]}({sub_resource.id}) 引导加载程序失败 {e}')
                                new_data = _data

                            new_data = struct.pack("<I", _size) + new_data.ljust(len(_data), b'\0')
                            new_data = new_data.ljust(size, b'\0')
                            pe.set_bytes_at_rva(rva, new_data)

        pe.write(output_file or input_file)

    elif netinstall[:4] == b'\x7FELF':
        SECTION_HEADER_OFFSET_IN_FILE = struct.unpack_from(b'<I', netinstall[0x20:])[0]
        SECTION_HEADER_ENTRY_SIZE = struct.unpack_from(b'<H', netinstall[0x2E:])[0]
        NUMBER_OF_SECTION_HEADER_ENTRIES = struct.unpack_from(b'<H', netinstall[0x30:])[0]
        STRING_TABLE_INDEX = struct.unpack_from(b'<H', netinstall[0x32:])[0]

        section_name_offset = (SECTION_HEADER_OFFSET_IN_FILE + STRING_TABLE_INDEX *
                               SECTION_HEADER_ENTRY_SIZE + 16)
        SECTION_NAME_BLOCK = struct.unpack_from(b'<I', netinstall[section_name_offset:])[0]

        text_section_addr = None
        text_section_offset = None

        for i in range(NUMBER_OF_SECTION_HEADER_ENTRIES):
            section_offset = SECTION_HEADER_OFFSET_IN_FILE + i * SECTION_HEADER_ENTRY_SIZE
            name_offset, _, _, addr, offset = struct.unpack_from('<IIIII', netinstall[section_offset:])
            name = netinstall[SECTION_NAME_BLOCK + name_offset:].split(b'\0')[0]
            if name == b'.text':
                print(f'找到 .text 节偏移 {hex(offset)} 地址 {hex(addr)}')
                text_section_addr = addr
                text_section_offset = offset
                break

        offset = re.search(rb'\x83\x00\x00\x00.{12}\x8A\x00\x00\x00.{12}\x81\x00\x00\x00.{12}',
                           netinstall).start()
        print(f'找到引导加载程序偏移 {hex(offset)}')

        for i in range(10):
            id, name_ptr, data_ptr, data_size = struct.unpack_from(
                '<IIII', netinstall[offset + i*16:offset + i*16 + 16])
            name = netinstall[text_section_offset + name_ptr - text_section_addr:].split(b'\0')[0]
            data = netinstall[text_section_offset + data_ptr - text_section_addr:
                             text_section_offset + data_ptr - text_section_addr + data_size]
            print(f'找到 {name.decode()}({id}) 引导加载程序偏移 '
                  f'{hex(text_section_offset + data_ptr - text_section_addr)} 大小 {data_size}')

            try:
                if data[:2] == b'MZ':
                    new_data = patch_pe(data, key_dict)
                elif data[:4] == b'\x7FELF':
                    new_data = patch_elf(data, key_dict)
                else:
                    raise Exception(f'未知的引导加载程序格式 {data[:4].hex().upper()}')
            except Exception as e:
                print(f'修补 {name.decode()}({id}) 引导加载程序失败 {e}')
                new_data = data

            new_data = new_data.ljust(len(data), b'\0')
            netinstall = netinstall.replace(data, new_data)

        open(output_file or input_file, 'wb').write(netinstall)


def patch_kernel(data: bytes, key_dict) -> bytes:
    """
    修补内核镜像（自动检测格式）。

    支持多种内核格式：
    - bzImage (x86_64 EFI): 带 'ARM\x64' 魔数的 PE 头 = ARM64
    - ELF: 标准 ELF 二进制文件
    - 原始 initrd: 仅 XZ 压缩的 initramfs

    参数:
        data: 原始内核字节
        key_dict: 将旧公钥映射到新公钥的字典

    返回:
        bytes: 修补后的内核字节

    异常:
        Exception: 如果内核格式无法识别
    """
    if data[:2] == b'MZ':
        print('正在修补 EFI 内核')
        if data[56:60] == b'ARM\x64':
            print('正在修补 arm64')
            return patch_elf(data, key_dict)
        else:
            print('正在修补 x86_64')
            return patch_bzimage(data, key_dict)
    elif data[:4] == b'\x7FELF':
        print('正在修补 ELF')
        return patch_elf(data, key_dict)
    elif data[:5] == b'\xFD7zXZ':
        print('正在修补 initrd')
        return patch_initrd_xz(data, key_dict)
    else:
        raise Exception('无法识别的内核格式')


def patch_loader(loader_file):
    """
    使用加载程序修补模块修补独立的加载程序文件。

    参数:
        loader_file: 要修补的加载程序文件的路径
    """
    try:
        from package import check_install_package
        check_install_package(['pyelftools'])
        from loader.patch_loader import patch_loader as do_patch_loader
        arch = os.getenv('ARCH') or 'x86'
        arch = arch.replace('-', '')
        do_patch_loader(loader_file, loader_file, arch)
    except ImportError as e:
        print(e)
        print("加载程序模块导入失败。无法运行 patch_loader.py")


def patch_squashfs(path, key_dict):
    """
    修补提取的 SquashFS 文件系统目录中的文件。

    此函数：
    1. 遍历目录中的所有文件
    2. 修补内核文件（BOOTX64.EFI、kernel）
    3. 替换所有文件中的公钥
    4. 替换许可证、升级、云和续订端点的 URL

    参数:
        path: 提取的 SquashFS 的根目录
        key_dict: 将旧公钥映射到新公钥的字典
    """
    for root, dirs, files in os.walk(path):
        for _file in files:
            file = os.path.join(root, _file)
            if os.path.isfile(file):
                if _file == 'loader':
                    patch_loader(file)
                    continue
                if _file == 'BOOTX64.EFI':
                    print(f'修补 {file} ...')
                    data = open(file, 'rb').read()
                    data = patch_kernel(data, key_dict)
                    open(file, 'wb').write(data)
                    continue

                data = open(file, 'rb').read()
                for old_public_key, new_public_key in key_dict.items():
                    _data = replace_key(old_public_key, new_public_key, data, file)
                    if _data != data:
                        open(file, 'wb').write(_data)

                url_dict = {
                    os.environ['MIKRO_LICENCE_URL'].encode():
                        os.environ['CUSTOM_LICENCE_URL'].encode(),
                    os.environ['MIKRO_UPGRADE_URL'].encode():
                        os.environ['CUSTOM_UPGRADE_URL'].encode(),
                    os.environ['MIKRO_CLOUD_URL'].encode():
                        os.environ['CUSTOM_CLOUD_URL'].encode(),
                    os.environ['MIKRO_CLOUD_PUBLIC_KEY'].encode():
                        os.environ['CUSTOM_CLOUD_PUBLIC_KEY'].encode(),
                }
                data = open(file, 'rb').read()
                for old_url, new_url in url_dict.items():
                    if old_url in data:
                        print(f'{file} URL 已修补 {old_url.decode()[:7]}...')
                        data = data.replace(old_url, new_url)
                        open(file, 'wb').write(data)

                if os.path.split(file)[1] == 'licupgr':
                    url_dict = {
                        os.environ['MIKRO_RENEW_URL'].encode():
                            os.environ['CUSTOM_RENEW_URL'].encode(),
                    }
                    for old_url, new_url in url_dict.items():
                        if old_url in data:
                            print(f'{file} URL 已修补 {old_url.decode()[:7]}...')
                            data = data.replace(old_url, new_url)
                            open(file, 'wb').write(data)


def run_shell_command(command):
    """
    执行 shell 命令并返回 stdout/stderr。

    参数:
        command: 要执行的 shell 命令字符串

    返回:
        tuple: (stdout_bytes, stderr_bytes)
    """
    process = subprocess.run(command, shell=True, check=True,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return process.stdout, process.stderr


def patch_npk_package(package, key_dict):
    """
    通过修改内容来修补 NPK 包。

    此函数：
    1. 从包中提取 SquashFS
    2. 修补 SquashFS 中的文件
    3. 重建和重新打包 SquashFS
    4. 用修补后的 SquashFS 更新包

    参数:
        package: 要修补的 NPK 包对象
        key_dict: 将旧公钥映射到新公钥的字典
    """
    if package[NpkPartID.NAME_INFO].data.name == 'system':
        file_container = NpkFileContainer.unserialize_from(
            package[NpkPartID.FILE_CONTAINER].data)
        for item in file_container:
            if item.name in [b'boot/EFI/BOOT/BOOTX64.EFI', b'boot/kernel', b'boot/initrd.rgz']:
                print(f'修补 {item.name} ...')
                item.data = patch_kernel(item.data, key_dict)
        package[NpkPartID.FILE_CONTAINER].data = file_container.serialize()

        squashfs_file = 'squashfs-root.sfs'
        extract_dir = 'squashfs-root'
        open(squashfs_file, 'wb').write(package[NpkPartID.SQUASHFS].data)
        print(f"提取 {squashfs_file} ...")
        run_shell_command(f"unsquashfs -d {extract_dir} {squashfs_file}")

        patch_squashfs(extract_dir, key_dict)

        logo = os.path.join(extract_dir, "nova/lib/console/logo.txt")
        run_shell_command(f"sudo sed -i '1d' {logo}")
        run_shell_command(
            f"sudo sed -i '8s#.*#  elseif@live.cn     https://github.com/elseif/MikroTikPatch#' {logo}")

        print(f"打包 {extract_dir} ...")
        run_shell_command(f"rm -f {squashfs_file}")
        run_shell_command(f"mksquashfs {extract_dir} {squashfs_file} -quiet -comp xz -no-xattrs -b 256k")
        print(f"清理 ...")
        run_shell_command(f"rm -rf {extract_dir}")
        package[NpkPartID.SQUASHFS].data = open(squashfs_file, 'rb').read()
        run_shell_command(f"rm -f {squashfs_file}")


def patch_npk_file(key_dict, kcdsa_private_key, eddsa_private_key, input_file, output_file=None):
    """
    修补和重新签署 NPK 文件。

    参数:
        key_dict: 将旧公钥映射到新公钥的字典
        kcdsa_private_key: 用于重新签署的 KCdsa 私钥
        eddsa_private_key: 用于重新签署的 EdDSA 私钥
        input_file: 输入 NPK 文件的路径
        output_file: 可选的输出文件路径（默认为覆盖输入）
    """
    npk = NovaPackage.load(input_file)

    if len(npk._packages) > 0:
        for package in npk._packages:
            patch_npk_package(package, key_dict)
    else:
        patch_npk_package(npk, key_dict)

    npk.sign(kcdsa_private_key, eddsa_private_key)
    npk.save(output_file or input_file)


if __name__ == '__main__':
    import argparse
    import os

    parser = argparse.ArgumentParser(description='MikroTik 修补工具')
    subparsers = parser.add_subparsers(dest="command")

    npk_parser = subparsers.add_parser('npk', help='修补和签署 npk 文件')
    npk_parser.add_argument('input', type=str, help='输入文件')
    npk_parser.add_argument('-O', '--output', type=str, help='输出文件')

    kernel_parser = subparsers.add_parser('kernel', help='修补内核文件')
    kernel_parser.add_argument('input', type=str, help='输入文件')
    kernel_parser.add_argument('-O', '--output', type=str, help='输出文件')

    block_parser = subparsers.add_parser('block', help='修补块文件')
    block_parser.add_argument('dev', type=str, help='块设备')
    block_parser.add_argument('file', type=str, help='文件路径')

    netinstall_parser = subparsers.add_parser('netinstall', help='修补 netinstall 文件')
    netinstall_parser.add_argument('input', type=str, help='输入文件')
    netinstall_parser.add_argument('-O', '--output', type=str, help='输出文件')

    args = parser.parse_args()

    key_dict = {
        bytes.fromhex(os.environ['MIKRO_LICENSE_PUBLIC_KEY']):
            bytes.fromhex(os.environ['CUSTOM_LICENSE_PUBLIC_KEY']),
        bytes.fromhex(os.environ['MIKRO_NPK_SIGN_PUBLIC_KEY']):
            bytes.fromhex(os.environ['CUSTOM_NPK_SIGN_PUBLIC_KEY'])
    }

    kcdsa_private_key = bytes.fromhex(os.environ['CUSTOM_LICENSE_PRIVATE_KEY'])
    eddsa_private_key = bytes.fromhex(os.environ['CUSTOM_NPK_SIGN_PRIVATE_KEY'])

    if args.command == 'npk':
        print(f'正在修补 {args.input} ...')
        patch_npk_file(key_dict, kcdsa_private_key, eddsa_private_key,
                       args.input, args.output)
    elif args.command == 'kernel':
        print(f'正在修补 {args.input} ...')
        data = patch_kernel(open(args.input, 'rb').read(), key_dict)
        open(args.output or args.input, 'wb').write(data)
    elif args.command == 'block':
        print(f'正在修补 {args.dev} 中的 {args.file} ...')
        patch_block(args.dev, args.file, key_dict)
    elif args.command == 'netinstall':
        print(f'正在修补 {args.input} ...')
        patch_netinstall(key_dict, args.input, args.output)
    else:
        parser.print_help()
