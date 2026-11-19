"""不可变日志段格式与旁路索引。"""

from .errors import (
    IndexFormatError,
    LogSegError,
    SegmentError,
    StaleIndexError,
)
from .frame import (
    FORMAT_VERSION,
    FrameCorrupt,
    FrameTruncated,
    HEADER_SIZE,
    crc32,
    encode_frame,
)
from .index import (
    INDEX_FORMAT_VERSION,
    IndexEntry,
    SegmentIndex,
    build_index,
    index_path_for,
    load_index,
    rebuild_index,
)
from .segment import Corruption, Record, SegmentWriter, scan_segment
from .store import QueryHit, SegmentStore

__all__ = [
    "LogSegError",
    "IndexFormatError",
    "StaleIndexError",
    "SegmentError",
    "FORMAT_VERSION",
    "INDEX_FORMAT_VERSION",
    "HEADER_SIZE",
    "FrameCorrupt",
    "FrameTruncated",
    "crc32",
    "encode_frame",
    "Record",
    "Corruption",
    "SegmentWriter",
    "scan_segment",
    "IndexEntry",
    "SegmentIndex",
    "build_index",
    "rebuild_index",
    "load_index",
    "index_path_for",
    "SegmentStore",
    "QueryHit",
]
