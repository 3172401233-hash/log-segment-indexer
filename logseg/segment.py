"""段文件的顺序扫描、损坏定位与追加写入。"""

import os
from dataclasses import dataclass, field

from . import frame as frame_mod
from .frame import FrameCorrupt, FrameTruncated, encode_frame


@dataclass(frozen=True)
class Record:
    """一条完整记录（段内偏移、长度、校验值与负载）。"""

    timestamp_ns: int
    offset: int
    length: int
    crc32: int
    payload: bytes = field(repr=False, default=b"")


@dataclass(frozen=True)
class Corruption:
    """扫描中发现的第一个不可读帧，即段的损坏边界。"""

    offset: int
    kind: str  # "truncated" | "bad_magic" | "bad_version" | "crc_mismatch"
    detail: str
    bytes_remaining: int


@dataclass(frozen=True)
class SegmentScan:
    """整段扫描结果。

    ``records`` 仅包含损坏边界之前的完整记录；
    ``valid_end`` 是这些完整记录占用的连续字节数；
    ``corruption`` 为 None 表示段尾完整、没有发现损坏。
    """

    records: list
    valid_end: int
    file_size: int
    corruption: object = None


def scan_segment(path):
    """从头顺序扫描整个段文件，不做任何修改。

    扫描在第一个不完整帧或校验失败的帧处停止，该帧及之后的字节
    都不会被当作记录返回，损坏位置通过 :class:`Corruption` 报告。
    """
    records = []
    file_size = os.path.getsize(path)
    offset = 0
    corruption = None
    with open(path, "rb") as handle:
        while offset < file_size:
            try:
                record = frame_mod.read_frame(handle, offset)
            except FrameTruncated as exc:
                corruption = Corruption(
                    offset=offset,
                    kind="truncated",
                    detail=str(exc),
                    bytes_remaining=file_size - offset,
                )
                break
            except FrameCorrupt as exc:
                message = str(exc)
                if "魔数" in message:
                    kind = "bad_magic"
                elif "版本" in message:
                    kind = "bad_version"
                else:
                    kind = "crc_mismatch"
                corruption = Corruption(
                    offset=offset,
                    kind=kind,
                    detail=message,
                    bytes_remaining=file_size - offset,
                )
                break
            records.append(record)
            offset += frame_mod.HEADER_SIZE + record.length
    return SegmentScan(
        records=records,
        valid_end=offset,
        file_size=file_size,
        corruption=corruption,
    )


def read_record_at(path, offset):
    """随机读取段内 ``offset`` 处的一帧，失败抛出帧级异常。"""
    with open(path, "rb") as handle:
        return frame_mod.read_frame(handle, offset)


class SegmentWriter:
    """只追加的段写入器。

    段是不可变的：写入器只负责向段尾追加新帧，从不修改已有字节。
    时间戳要求单调非递减，便于按时间范围检索。
    """

    def __init__(self, path, sync=False):
        self.path = path
        self.sync = sync
        self._handle = None
        self._size = 0
        self._last_timestamp = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    def open(self):
        if self._handle is not None:
            return
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, exist_ok=True)
        self._handle = open(self.path, "ab")
        self._size = self._handle.tell()

    def append(self, timestamp_ns, payload):
        """追加一条记录，返回该记录的段内偏移。"""
        if self._handle is None:
            raise RuntimeError("写入器尚未打开")
        if self._last_timestamp is not None and timestamp_ns < self._last_timestamp:
            raise ValueError(
                "时间戳必须单调非递减：上一条 %d，当前 %d"
                % (self._last_timestamp, timestamp_ns)
            )
        offset = self._size
        data = encode_frame(timestamp_ns, payload)
        self._handle.write(data)
        if self.sync:
            self._handle.flush()
            os.fsync(self._handle.fileno())
        self._size += len(data)
        self._last_timestamp = timestamp_ns
        return offset

    def tell(self):
        """当前段尾（下一帧的起始偏移）。"""
        return self._size

    def close(self):
        if self._handle is None:
            return
        if self.sync:
            self._handle.flush()
            os.fsync(self._handle.fileno())
        self._handle.close()
        self._handle = None
