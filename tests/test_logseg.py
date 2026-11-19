import json
import os
import shutil
import tempfile
import unittest

from logseg import (
    FORMAT_VERSION,
    FrameCorrupt,
    INDEX_FORMAT_VERSION,
    SegmentStore,
    StaleIndexError,
    build_index,
    crc32,
    encode_frame,
    index_path_for,
    load_index,
    rebuild_index,
    scan_segment,
)


class LogSegTestCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="logseg-test-")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def write_segment(self, base_offset, records, sync=False):
        """records 为 [(timestamp_ns, payload), ...]，返回段路径与基偏移。"""
        store = SegmentStore(self.root)
        writer = store.new_writer(base_offset=base_offset, sync=sync)
        offsets = []
        try:
            for timestamp_ns, payload in records:
                offsets.append(writer.append(timestamp_ns, payload))
        finally:
            writer.close()
        return store.segment_path(base_offset), offsets

    def build(self, store, base_offset):
        return build_index(store.segment_path(base_offset), base_offset)


class NormalBuildTest(LogSegTestCase):
    def test_build_and_lookup(self):
        records = [
            (1000, b"a"),
            (2000, b"bb"),
            (3000, b"ccc"),
        ]
        segment_path, offsets = self.write_segment(0, records)
        index = build_index(segment_path, 0)

        self.assertEqual(index.record_count, 3)
        self.assertEqual(index.time_min_ns, 1000)
        self.assertEqual(index.time_max_ns, 3000)
        self.assertEqual(index.segment_size, os.path.getsize(segment_path))
        self.assertIsNone(index.corruption)
        self.assertEqual(index.index_format_version, INDEX_FORMAT_VERSION)
        self.assertEqual(index.frame_format_version, FORMAT_VERSION)

        scan = scan_segment(segment_path)
        for record, (timestamp_ns, payload), offset in zip(
            scan.records, records, offsets
        ):
            self.assertEqual(record.timestamp_ns, timestamp_ns)
            self.assertEqual(record.payload, payload)
            self.assertEqual(record.offset, offset)
            self.assertEqual(record.length, len(payload))
            self.assertEqual(record.crc32, crc32(timestamp_ns, payload))

    def test_binary_search_locations(self):
        records = [(i * 10, b"x") for i in range(10)]
        segment_path, _ = self.write_segment(0, records)
        index = build_index(segment_path, 0)

        self.assertEqual(index.locate_ge(0), 0)
        self.assertEqual(index.locate_ge(25), 3)
        self.assertEqual(index.locate_ge(90), 9)
        self.assertEqual(index.locate_ge(91), 10)

    def test_existing_valid_index_is_not_rebuilt(self):
        segment_path, _ = self.write_segment(0, [(1, b"a")])
        first = build_index(segment_path, 0)
        idx_path = index_path_for(segment_path)
        mtime = os.path.getmtime(idx_path)
        second = build_index(segment_path, 0)
        self.assertEqual(os.path.getmtime(idx_path), mtime)
        self.assertEqual(second.segment_size, first.segment_size)


class TailTruncationTest(LogSegTestCase):
    def test_partial_tail_record_is_reported(self):
        segment_path, offsets = self.write_segment(
            0, [(1, b"one"), (2, b"two"), (3, b"three")]
        )
        full_size = os.path.getsize(segment_path)
        with open(segment_path, "r+b") as handle:
            handle.truncate(full_size - 3)

        scan = scan_segment(segment_path)
        self.assertEqual(len(scan.records), 2)
        self.assertEqual(scan.valid_end, offsets[-1])
        self.assertEqual(scan.file_size, full_size - 3)
        self.assertIsNotNone(scan.corruption)
        self.assertEqual(scan.corruption.kind, "truncated")
        self.assertEqual(scan.corruption.offset, offsets[-1])
        self.assertEqual(scan.corruption.bytes_remaining, full_size - 3 - offsets[-1])

        index = build_index(segment_path, 0)
        self.assertEqual(index.record_count, 2)
        self.assertEqual(index.time_max_ns, 2)
        self.assertEqual(index.corruption.kind, "truncated")

    def test_truncated_header_only(self):
        segment_path, offsets = self.write_segment(0, [(1, b"a"), (2, b"b")])
        with open(segment_path, "r+b") as handle:
            handle.truncate(offsets[-1] + 5)
        scan = scan_segment(segment_path)
        self.assertEqual(len(scan.records), 1)
        self.assertEqual(scan.corruption.kind, "truncated")
        self.assertEqual(scan.valid_end, offsets[-1])


class ChecksumFailureTest(LogSegTestCase):
    def test_corrupt_payload_crc_mismatch(self):
        segment_path, offsets = self.write_segment(
            0, [(1, b"alpha"), (2, b"beta"), (3, b"gamma")]
        )
        with open(segment_path, "r+b") as handle:
            handle.seek(offsets[1] + 22)
            handle.write(b"X")

        with self.assertRaises(FrameCorrupt):
            from logseg.segment import read_record_at

            read_record_at(segment_path, offsets[1])

        scan = scan_segment(segment_path)
        self.assertEqual(len(scan.records), 1)
        self.assertEqual(scan.records[0].payload, b"alpha")
        self.assertEqual(scan.corruption.kind, "crc_mismatch")
        self.assertEqual(scan.corruption.offset, offsets[1])

        index = build_index(segment_path, 0)
        self.assertEqual(index.record_count, 1)
        self.assertEqual(index.corruption.kind, "crc_mismatch")

    def test_bad_magic_stops_scan(self):
        segment_path, offsets = self.write_segment(0, [(1, b"a"), (2, b"b")])
        with open(segment_path, "r+b") as handle:
            handle.seek(offsets[1])
            handle.write(b"ZZZZ")
        scan = scan_segment(segment_path)
        self.assertEqual(len(scan.records), 1)
        self.assertEqual(scan.corruption.kind, "bad_magic")


class CrossSegmentQueryTest(LogSegTestCase):
    def _build_two_segments(self):
        store = SegmentStore(self.root)
        path_a, offsets_a = self.write_segment(
            0, [(100, b"a0"), (200, b"a1"), (300, b"a2")]
        )
        size_a = os.path.getsize(path_a)
        path_b, offsets_b = self.write_segment(
            size_a, [(400, b"b0"), (500, b"b1"), (600, b"b2")]
        )
        build_index(path_a, 0)
        build_index(path_b, size_a)
        return store, size_a, offsets_b

    def test_global_offsets_are_unique_and_continuous(self):
        store, size_a, offsets_b = self._build_two_segments()
        hits = store.query(0, 1000)
        self.assertEqual(len(hits), 6)
        global_offsets = [hit.global_offset for hit in hits]
        self.assertEqual(global_offsets, sorted(global_offsets))
        self.assertEqual(len(set(global_offsets)), 6)
        self.assertEqual(global_offsets[3], size_a + offsets_b[0])
        self.assertEqual([hit.timestamp_ns for hit in hits], [
            100, 200, 300, 400, 500, 600
        ])
        self.assertEqual(hits[3].payload, b"b0")

    def test_range_filters_segments_and_records(self):
        store, _, _ = self._build_two_segments()
        hits = store.query(200, 500)
        self.assertEqual([hit.timestamp_ns for hit in hits], [200, 300, 400, 500])
        hits = store.query(250, 350)
        self.assertEqual([hit.timestamp_ns for hit in hits], [300])
        hits = store.query(900, 1000)
        self.assertEqual(hits, [])

    def test_query_without_payload(self):
        store, _, _ = self._build_two_segments()
        hits = store.query(100, 100, include_payload=False)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].payload, b"")
        self.assertEqual(hits[0].length, 2)


class EmptySegmentTest(LogSegTestCase):
    def test_empty_segment_index(self):
        store = SegmentStore(self.root)
        writer = store.new_writer(base_offset=0)
        writer.close()
        segment_path = store.segment_path(0)
        self.assertEqual(os.path.getsize(segment_path), 0)

        index = build_index(segment_path, 0)
        self.assertEqual(index.record_count, 0)
        self.assertIsNone(index.time_min_ns)
        self.assertIsNone(index.time_max_ns)
        self.assertIsNone(index.corruption)
        self.assertFalse(index.overlaps(0, 10**18))
        self.assertEqual(index.locate_ge(0), 0)

        reloaded = load_index(index_path_for(segment_path), segment_path)
        self.assertEqual(reloaded.record_count, 0)
        self.assertEqual(store.query(0, 10**18), [])


class IndexRebuildTest(LogSegTestCase):
    def test_stale_index_is_rejected_not_overwritten(self):
        segment_path, _ = self.write_segment(0, [(1, b"a"), (2, b"b")])
        build_index(segment_path, 0)
        idx_path = index_path_for(segment_path)
        with open(idx_path, "rb") as handle:
            before = handle.read()
        original_size = os.path.getsize(segment_path)

        with open(segment_path, "ab") as handle:
            handle.write(encode_frame(3, b"c"))

        with self.assertRaises(StaleIndexError) as ctx:
            load_index(idx_path, segment_path)
        self.assertEqual(ctx.exception.indexed_size, original_size)
        self.assertGreater(ctx.exception.actual_size, ctx.exception.indexed_size)

        with self.assertRaises(StaleIndexError):
            build_index(segment_path, 0)
        with open(idx_path, "rb") as handle:
            self.assertEqual(handle.read(), before)

    def test_explicit_rebuild_picks_up_tail_corruption(self):
        segment_path, offsets = self.write_segment(
            0, [(1, b"a"), (2, b"b"), (3, b"c")]
        )
        build_index(segment_path, 0)
        idx_path = index_path_for(segment_path)
        full_size = os.path.getsize(segment_path)

        with open(segment_path, "r+b") as handle:
            handle.truncate(full_size - 2)

        with self.assertRaises(StaleIndexError):
            load_index(idx_path, segment_path)

        rebuilt = rebuild_index(segment_path, 0, idx_path)
        self.assertEqual(rebuilt.record_count, 2)
        self.assertEqual(rebuilt.corruption.kind, "truncated")
        self.assertEqual(rebuilt.corruption.offset, offsets[-1])

        reloaded = load_index(idx_path, segment_path)
        self.assertEqual(reloaded.record_count, 2)
        self.assertEqual(os.path.getsize(segment_path), full_size - 2)

    def test_rebuild_via_store_and_immutable_segment(self):
        store = SegmentStore(self.root)
        path, _ = self.write_segment(0, [(1, b"a"), (2, b"b")])
        build_index(path, 0)
        size_before = os.path.getsize(path)
        with open(path, "ab") as handle:
            handle.write(b"\x00\x01")
        with self.assertRaises(StaleIndexError):
            store.load_index(0)
        index = store.load_index(0, rebuild=True)
        self.assertEqual(index.record_count, 2)
        self.assertEqual(index.corruption.kind, "truncated")
        self.assertEqual(os.path.getsize(path), size_before + 2)
        self.assertEqual(len(store.corrupt_segments(rebuild=True)), 1)

    def test_damaged_index_file_raises_format_error(self):
        from logseg import IndexFormatError

        segment_path, _ = self.write_segment(0, [(1, b"a")])
        build_index(segment_path, 0)
        idx_path = index_path_for(segment_path)
        with open(idx_path, "w", encoding="utf-8") as handle:
            handle.write("{not valid json")
        with self.assertRaises(IndexFormatError):
            load_index(idx_path, segment_path)
        rebuilt = rebuild_index(segment_path, 0, idx_path)
        self.assertEqual(rebuilt.record_count, 1)

    def test_unknown_index_version_rejected(self):
        from logseg import IndexFormatError

        segment_path, _ = self.write_segment(0, [(1, b"a")])
        build_index(segment_path, 0)
        idx_path = index_path_for(segment_path)
        with open(idx_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        payload["index_format_version"] = 999
        with open(idx_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)
        with self.assertRaises(IndexFormatError):
            load_index(idx_path, segment_path)


if __name__ == "__main__":
    unittest.main()
