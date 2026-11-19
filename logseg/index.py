"""旁路索引（.idx）：段级时间范围与按时间二分查找的记录位置。

索引与段文件分离存放，段本身保持不可变、只追加。索引通过
“临时文件 + 原子替换”写入；当索引记录的段长度与实际段长度
不一致时，:func:`load_index` 抛出 :class:`StaleIndexError`，
绝不静默覆盖，必须由调用方显式 :func:`rebuild_index`。
"""

import bisect
import json
import os
import tempfile
from dataclasses import dataclass, field

from .errors import IndexFormatError, StaleIndexError
from .frame import FORMAT_VERSION as FRAME_FORMAT_VERSION
from .segment import Corruption, scan_segment

INDEX_FORMAT_VERSION = 1
INDEX_SUFFIX = ".idx"


@dataclass(frozen=True)
class IndexEntry:
    """索引中的一条记录定位信息。"""

    timestamp_ns: int
    offset: int
    length: int
    crc32: int


@dataclass(frozen=True)
class SegmentIndex:
    """一个段的旁路索引。"""

    segment_name: str
    base_offset: int
    segment_size: int
    entries: list
    corruption: object = None
    index_format_version: int = INDEX_FORMAT_VERSION
    frame_format_version: int = FRAME_FORMAT_VERSION
    _timestamps: list = field(default=None, repr=False, compare=False)

    @property
    def record_count(self):
        return len(self.entries)

    @property
    def time_min_ns(self):
        return self.entries[0].timestamp_ns if self.entries else None

    @property
    def time_max_ns(self):
        return self.entries[-1].timestamp_ns if self.entries else None

    def overlaps(self, start_ns, end_ns):
        """段的完整记录时间范围是否与 [start_ns, end_ns] 相交。"""
        if not self.entries:
            return False
        return self.time_max_ns >= start_ns and self.time_min_ns <= end_ns

    def locate_ge(self, timestamp_ns):
        """返回时间戳 >= ``timestamp_ns`` 的第一条记录在 entries 中的位置。

        基于有序时间戳的二分查找（bisect_left）。
        """
        if self._timestamps is None:
            object.__setattr__(
                self,
                "_timestamps",
                [entry.timestamp_ns for entry in self.entries],
            )
        return bisect.bisect_left(self._timestamps, timestamp_ns)

    def global_offset(self, entry):
        """把段内偏移换算为跨段全局偏移。"""
        return self.base_offset + entry.offset

    def to_dict(self):
        payload = {
            "index_format_version": self.index_format_version,
            "frame_format_version": self.frame_format_version,
            "segment": self.segment_name,
            "base_offset": self.base_offset,
            "segment_size": self.segment_size,
            "record_count": len(self.entries),
            "time_min_ns": self.time_min_ns,
            "time_max_ns": self.time_max_ns,
            "entries": [
                {
                    "timestamp_ns": entry.timestamp_ns,
                    "offset": entry.offset,
                    "length": entry.length,
                    "crc32": entry.crc32,
                }
                for entry in self.entries
            ],
            "corruption": _corruption_to_dict(self.corruption),
        }
        return payload


def index_path_for(segment_path):
    """约定：``000...001.log`` 的索引为同目录下的 ``000...001.idx``。"""
    if not segment_path.endswith(".log"):
        raise IndexFormatError("段文件名必须以 .log 结尾：%s" % segment_path)
    return segment_path[:-4] + INDEX_SUFFIX


def build_index(segment_path, base_offset, index_path=None, force=False):
    """扫描段并构建索引。

    若索引已存在且 ``force=False``：索引仍然有效时直接返回原索引，
    长度不一致时抛出 :class:`StaleIndexError`，不会覆盖任何文件。
    ``force=True`` 时重新扫描并原子替换索引文件（段文件永不修改）。
    """
    if index_path is None:
        index_path = index_path_for(segment_path)
    if os.path.exists(index_path) and not force:
        try:
            return load_index(index_path, segment_path)
        except StaleIndexError:
            raise
    scan = scan_segment(segment_path)
    entries = [
        IndexEntry(
            timestamp_ns=record.timestamp_ns,
            offset=record.offset,
            length=record.length,
            crc32=record.crc32,
        )
        for record in scan.records
    ]
    index = SegmentIndex(
        segment_name=os.path.basename(segment_path),
        base_offset=base_offset,
        segment_size=scan.file_size,
        entries=entries,
        corruption=scan.corruption,
    )
    _atomic_write_json(index_path, index.to_dict())
    return index


def rebuild_index(segment_path, base_offset, index_path=None):
    """显式重建索引（只读恢复策略的一部分）。

    只重新扫描段并替换 .idx 文件，绝不修改 .log 段文件。
    """
    if not os.path.exists(segment_path):
        raise FileNotFoundError(segment_path)
    return build_index(
        segment_path, base_offset, index_path=index_path, force=True
    )


def load_index(index_path, segment_path=None):
    """读取并校验索引。

    - JSON 损坏或索引格式版本不支持 -> :class:`IndexFormatError`
    - 索引记录的段长度与实际段长度不符 -> :class:`StaleIndexError`
    """
    try:
        with open(index_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (ValueError, OSError) as exc:
        raise IndexFormatError("索引无法解析：%s（%s）" % (index_path, exc))
    if not isinstance(payload, dict):
        raise IndexFormatError("索引顶层结构必须是对象：%s" % index_path)
    version = payload.get("index_format_version")
    if version != INDEX_FORMAT_VERSION:
        raise IndexFormatError(
            "索引格式版本 %r 不受支持（期望 %d）：%s"
            % (version, INDEX_FORMAT_VERSION, index_path)
        )
    if payload.get("frame_format_version") != FRAME_FORMAT_VERSION:
        raise IndexFormatError(
            "索引中的帧格式版本与当前实现不匹配：%s" % index_path
        )
    try:
        entries = [
            IndexEntry(
                timestamp_ns=int(item["timestamp_ns"]),
                offset=int(item["offset"]),
                length=int(item["length"]),
                crc32=int(item["crc32"]),
            )
            for item in payload["entries"]
        ]
        base_offset = int(payload["base_offset"])
        indexed_size = int(payload["segment_size"])
    except (KeyError, TypeError, ValueError) as exc:
        raise IndexFormatError("索引字段缺失或类型错误：%s（%s）" % (index_path, exc))
    if segment_path is not None and os.path.exists(segment_path):
        actual_size = os.path.getsize(segment_path)
        if actual_size != indexed_size:
            raise StaleIndexError(index_path, indexed_size, actual_size)
    corruption = _dict_to_corruption(payload.get("corruption"))
    return SegmentIndex(
        segment_name=str(payload.get("segment", "")),
        base_offset=base_offset,
        segment_size=indexed_size,
        entries=entries,
        corruption=corruption,
        index_format_version=version,
        frame_format_version=int(payload["frame_format_version"]),
    )


def _atomic_write_json(path, payload):
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp-", suffix=INDEX_SUFFIX, dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
        _fsync_directory(directory)
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def _fsync_directory(directory):
    flags = os.O_RDONLY
    dir_fd = os.open(directory, flags)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _corruption_to_dict(corruption):
    if corruption is None:
        return None
    return {
        "offset": corruption.offset,
        "kind": corruption.kind,
        "detail": corruption.detail,
        "bytes_remaining": corruption.bytes_remaining,
    }


def _dict_to_corruption(payload):
    if payload is None:
        return None
    try:
        return Corruption(
            offset=int(payload["offset"]),
            kind=str(payload["kind"]),
            detail=str(payload["detail"]),
            bytes_remaining=int(payload["bytes_remaining"]),
        )
    except (KeyError, TypeError, ValueError):
        raise IndexFormatError("索引中的损坏信息字段非法")
