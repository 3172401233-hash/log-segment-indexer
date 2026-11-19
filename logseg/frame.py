"""不可变日志段的二进制记录帧格式。

帧布局（全部为大端字节序）::

    偏移  大小        字段
    0     4 字节      魔数 MAGIC = b"LSEG"
    4     1 字节      帧格式版本 FORMAT_VERSION
    5     1 字节      保留字段（写 0）
    6     8 字节      记录时间戳（纳秒，单调非递减整数）
    14    4 字节      负载长度 n（无符号 32 位整数）
    18    4 字节      CRC32，覆盖 [时间戳 8 字节][长度 4 字节][负载 n 字节]
    22    n 字节      不透明负载

一条记录的“段内偏移”指该记录帧首字节（魔数）在 .log 段文件中的字节位置。
帧一旦写入即不可变；段只允许追加。
"""

import struct
import zlib

MAGIC = b"LSEG"
FORMAT_VERSION = 1
HEADER_SIZE = 22

_HEADER_PREFIX = struct.Struct(">4sBBQ")  # magic, version, reserved, timestamp
_LEN_STRUCT = struct.Struct(">I")
_CRC_STRUCT = struct.Struct(">I")


def crc32(timestamp_ns, payload):
    """计算帧校验值：CRC32 覆盖时间戳、长度与负载。"""
    checksum = zlib.crc32(struct.pack(">Q", timestamp_ns)) & 0xFFFFFFFF
    checksum = zlib.crc32(struct.pack(">I", len(payload)), checksum) & 0xFFFFFFFF
    checksum = zlib.crc32(payload, checksum) & 0xFFFFFFFF
    return checksum


def encode_frame(timestamp_ns, payload):
    """把一条记录编码为完整帧字节串。"""
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload 必须是 bytes 或 bytearray")
    if len(payload) > 0xFFFFFFFF:
        raise ValueError("负载超过单帧最大长度 2^32-1")
    checksum = crc32(timestamp_ns, payload)
    return b"".join(
        (
            _HEADER_PREFIX.pack(MAGIC, FORMAT_VERSION, 0, timestamp_ns),
            _LEN_STRUCT.pack(len(payload)),
            _CRC_STRUCT.pack(checksum),
            bytes(payload),
        )
    )


class FrameTruncated(Exception):
    """帧在读取到完整负载前结束（典型的尾部崩溃残留）。"""

    def __init__(self, offset, expected, available):
        self.offset = offset
        self.expected = expected
        self.available = available
        super().__init__(
            "偏移 %d 处的帧不完整：声明长度 %d，实际剩余 %d 字节"
            % (offset, expected, available)
        )


class FrameCorrupt(Exception):
    """帧头非法（魔数/版本错误）或校验值不匹配。"""


def read_frame(handle, offset):
    """从段文件 ``offset`` 处读取一帧。

    成功返回 :class:`logseg.segment.Record`，失败抛出
    :class:`FrameTruncated` 或 :class:`FrameCorrupt`。
    读取完成后文件指针停在该帧之后。
    """
    from .segment import Record

    handle.seek(offset)
    raw = handle.read(HEADER_SIZE)
    if len(raw) < HEADER_SIZE:
        raise FrameTruncated(offset, HEADER_SIZE, len(raw))
    magic, version, _reserved, timestamp_ns = _HEADER_PREFIX.unpack(raw[:14])
    if magic != MAGIC:
        raise FrameCorrupt("偏移 %d 处魔数不匹配：%r" % (offset, raw[:4]))
    if version != FORMAT_VERSION:
        raise FrameCorrupt(
            "偏移 %d 处帧版本 %d 不受支持（期望 %d）"
            % (offset, version, FORMAT_VERSION)
        )
    (length,) = _LEN_STRUCT.unpack(raw[14:18])
    (stored_crc,) = _CRC_STRUCT.unpack(raw[18:22])
    payload = handle.read(length)
    if len(payload) < length:
        raise FrameTruncated(offset, length, len(payload))
    actual_crc = crc32(timestamp_ns, payload)
    if actual_crc != stored_crc:
        raise FrameCorrupt(
            "偏移 %d 处校验失败：存储 %08x，计算 %08x"
            % (offset, stored_crc, actual_crc)
        )
    return Record(
        timestamp_ns=timestamp_ns,
        offset=offset,
        length=length,
        crc32=stored_crc,
        payload=bytes(payload),
    )
