"""段存储：管理一组不可变段、旁路索引与跨段时间范围查询。

段文件命名为 20 位零填充的全局基偏移，例如 ``00000000000000000007.log``，
配套索引为同名 ``.idx``。一条记录的全局偏移定义为::

    global_offset = 段基偏移 base_offset + 记录在段内的帧偏移 offset

因此跨段查询返回的全局偏移在整个存储内唯一且按段有序。
"""

import os
from dataclasses import dataclass

from .errors import SegmentError
from .index import index_path_for, load_index, rebuild_index
from .segment import SegmentWriter, read_record_at


@dataclass(frozen=True)
class QueryHit:
    """跨段查询命中的一条记录。"""

    global_offset: int
    segment_name: str
    timestamp_ns: int
    length: int
    crc32: int
    payload: bytes = b""


class SegmentStore:
    def __init__(self, root):
        self.root = os.path.abspath(root)
        os.makedirs(self.root, exist_ok=True)

    def segment_path(self, base_offset):
        return os.path.join(self.root, _segment_name(base_offset))

    def new_writer(self, base_offset=None, sync=False):
        """创建并打开一个新段的追加写入器。

        ``base_offset`` 缺省时取“最大已有基偏移 + 该段字节长度”，
        保证全局偏移连续不重叠；显式传入时不得与已有段冲突。
        """
        existing = self.list_base_offsets()
        if base_offset is None:
            if existing:
                last = existing[-1]
                base_offset = last + os.path.getsize(self.segment_path(last))
            else:
                base_offset = 0
        if base_offset in existing:
            raise SegmentError("段基偏移已存在：%d" % base_offset)
        if existing and base_offset < existing[-1]:
            raise SegmentError(
                "新段基偏移 %d 小于已有最大基偏移 %d" % (base_offset, existing[-1])
            )
        path = self.segment_path(base_offset)
        writer = SegmentWriter(path, sync=sync)
        writer.open()
        return writer

    def list_base_offsets(self):
        """返回按基偏移升序排列的已有段基偏移列表。"""
        offsets = []
        for name in os.listdir(self.root):
            parsed = _parse_segment_name(name)
            if parsed is not None:
                offsets.append(parsed)
        return sorted(offsets)

    def load_index(self, base_offset, rebuild=False):
        """加载某段索引。

        索引与段长度不符时默认抛出 :class:`StaleIndexError`；
        显式传 ``rebuild=True`` 才会重建索引（段文件保持只读不变）。
        """
        segment_path = self.segment_path(base_offset)
        index_path = index_path_for(segment_path)
        if rebuild:
            return rebuild_index(segment_path, base_offset, index_path)
        return load_index(index_path, segment_path)

    def load_all_indices(self, rebuild=False):
        """加载全部段的索引，按基偏移升序返回。"""
        return [
            self.load_index(base_offset, rebuild=rebuild)
            for base_offset in self.list_base_offsets()
        ]

    def query(self, start_ns, end_ns, include_payload=True):
        """跨段查询时间戳落在闭区间 [start_ns, end_ns] 的完整记录。

        先用段级时间范围跳过无关段，再在候选段索引上二分定位起点，
        返回结果按 (段基偏移, 段内偏移) 升序，并携带全局偏移。
        损坏边界之后的残缺字节不会被扫描或返回。
        """
        if start_ns > end_ns:
            raise ValueError("start_ns 不能大于 end_ns")
        hits = []
        for index in self.load_all_indices():
            if not index.overlaps(start_ns, end_ns):
                continue
            position = index.locate_ge(start_ns)
            segment_path = self.segment_path(index.base_offset)
            for entry in index.entries[position:]:
                if entry.timestamp_ns > end_ns:
                    break
                payload = b""
                if include_payload:
                    payload = read_record_at(segment_path, entry.offset).payload
                hits.append(
                    QueryHit(
                        global_offset=index.global_offset(entry),
                        segment_name=index.segment_name,
                        timestamp_ns=entry.timestamp_ns,
                        length=entry.length,
                        crc32=entry.crc32,
                        payload=payload,
                    )
                )
        return hits

    def corrupt_segments(self, rebuild=False):
        """返回带损坏边界报告的段索引列表。"""
        return [
            index
            for index in self.load_all_indices(rebuild=rebuild)
            if index.corruption is not None
        ]


def _segment_name(base_offset):
    if base_offset < 0:
        raise SegmentError("段基偏移不能为负数：%d" % base_offset)
    return "%020d.log" % base_offset


def _parse_segment_name(name):
    if not name.endswith(".log") or len(name) != 24:
        return None
    stem = name[:-4]
    if not stem.isdigit():
        return None
    return int(stem)
