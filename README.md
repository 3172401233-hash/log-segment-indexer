# log-segment-indexer

Python 3.8.2+ 的不可变日志段（immutable segment）格式与旁路索引库。写入进程
在段尾崩溃留下不足一条完整记录的数据时，查询端不需要全量扫描日志，也不会因为
尾部损坏而判废整个历史段：损坏边界之前的完整记录继续可读，残缺帧被定位并报告。

## 目录结构

- `logseg/frame.py`：二进制记录帧格式与 CRC32 校验
- `logseg/segment.py`：段顺序扫描、损坏定位、只追加写入器
- `logseg/index.py`：旁路索引（`.idx`）、二分查找、原子写入、过期校验
- `logseg/store.py`：多段管理、全局偏移换算、跨段时间范围查询
- `logseg/errors.py`：异常类型
- `tests/test_logseg.py`：单元测试

## 段文件格式

段文件后缀 `.log`，文件名是 20 位零填充的段基偏移，例如
`00000000000000000007.log`。段一旦写入即不可变，只允许向段尾追加帧。

### 帧布局（大端字节序）

| 偏移 | 长度 | 字段 | 说明 |
| --- | --- | --- | --- |
| 0 | 4 | magic | 固定 `LSEG` |
| 4 | 1 | frame version | 帧格式版本，当前 `1`（`frame.FORMAT_VERSION`） |
| 5 | 1 | reserved | 保留，写 0 |
| 6 | 8 | timestamp_ns | 纳秒时间戳，段内单调非递减 |
| 14 | 4 | length | 负载字节数 `n` |
| 18 | 4 | crc32 | CRC32，覆盖时间戳、长度与负载 |
| 22 | n | payload | 不透明负载 |

帧头固定 22 字节（`frame.HEADER_SIZE`）。校验值用标准库 `zlib.crc32` 对
`[时间戳 8 字节][长度 4 字节][负载 n 字节]` 分段续算，帧头魔数/版本错误或
CRC 不匹配都视为损坏。

每条记录自带时间、偏移、长度和校验值。记录的“段内偏移”是帧首字节在段文件中
的字节位置；“全局偏移”为

```
global_offset = 段基偏移 base_offset + 段内偏移 offset
```

新建段的默认基偏移为“上一段基偏移 + 上一段字节长度”，保证全局偏移连续、
跨段唯一且按段有序。

## 旁路索引格式

索引是与段同目录、同名的 `.idx` 文件，采用 JSON 文本（UTF-8），便于人工排障。
索引格式版本由 `index.INDEX_FORMAT_VERSION` 标识，当前为 `1`。主要字段：

- `index_format_version`：索引格式版本
- `frame_format_version`：对应的帧格式版本
- `segment`：段文件名
- `base_offset`：段基偏移，用于全局偏移换算
- `segment_size`：构建索引时段文件的字节长度（过期判定依据）
- `time_min_ns` / `time_max_ns`：段级时间范围（空段为 `null`）
- `record_count`：完整记录数
- `entries`：每条完整记录一项，含 `timestamp_ns`、`offset`、`length`、`crc32`
- `corruption`：损坏边界报告（无损坏为 `null`）

索引中的 `entries` 按时间戳有序，查询时用 `bisect_left` 二分定位首个
时间戳不小于起点的记录位置，无需扫描段文件。段级 `time_min_ns` /
`time_max_ns` 让跨段查询先跳过时间范围不相交的整段。

索引通过“同目录临时文件 + `os.replace` 原子替换 + 目录 fsync”写入，
不会留下半写的索引文件。

## 损坏边界

扫描从段首逐帧进行，在第一个不可读帧处停止，该帧及其后的所有字节都不会被当作
记录。损坏通过 `Corruption` 报告，包含：

- `offset`：损坏帧的起始字节位置（损坏边界）
- `kind`：`truncated`（尾部残缺/帧头不完整）、`bad_magic`、`bad_version`、
  `crc_mismatch`
- `bytes_remaining`：从损坏边界到段尾的字节数
- `detail`：人类可读说明

`SegmentScan.valid_end` 是损坏边界之前所有完整帧占用的连续字节数；这些完整
记录始终可读。写入进程在段尾崩溃通常表现为 `truncated`：最后一帧只写了一部分，
文件在完整负载之前结束。由于扫描在首个损坏帧即停止，中段损坏会遮蔽其后的字节，
这是有意设计——不可信字节之后的内容不再假设可解析。

## 只读恢复策略

1. 恢复与查询只以只读方式打开 `.log` 段文件，库不会截断、修补或重写段内任何
   字节；残缺尾部原样保留，由外部流程决定如何归档。
2. 索引与段长度不符时，`load_index` 抛出 `StaleIndexError`（携带索引记录长度
   与实际长度），`build_index` 同样拒绝静默覆盖，已有 `.idx` 文件保持不变。
3. 只有调用方显式执行 `rebuild_index(...)` 或
   `SegmentStore.load_index(base, rebuild=True)` 时才重算索引：重新只读扫描
   段文件、记录新的损坏边界并原子替换 `.idx`。
4. 索引 JSON 本身损坏或版本不受支持时抛出 `IndexFormatError`，同样只能显式
   重建，不会自动覆盖。
5. 空段（0 字节）是合法状态：生成记录数为 0、时间范围为 `null` 的索引，
   查询直接跳过。

## 用法示例

```python
from logseg import SegmentStore, build_index, scan_segment

store = SegmentStore("./data")

# 写入两个段（实际部署中通常每段一个写入进程/生命周期）
with store.new_writer(base_offset=0) as writer:
    writer.append(1000, b"first")
    writer.append(2000, b"second")
first_path = store.segment_path(0)
base1 = os.path.getsize(first_path)
with store.new_writer(base_offset=base1) as writer:
    writer.append(3000, b"third")

# 为每个段构建旁路索引
build_index(first_path, 0)
build_index(store.segment_path(base1), base1)

# 跨段时间范围查询，返回全局偏移
hits = store.query(1500, 3000)
for hit in hits:
    print(hit.global_offset, hit.timestamp_ns, hit.payload)

# 段尾崩溃后：完整记录继续可读，残缺帧被报告
scan = scan_segment(first_path)
print(scan.valid_end, scan.corruption)

# 索引过期时不能静默覆盖，必须显式重建
try:
    store.load_index(0)
except StaleIndexError:
    store.load_index(0, rebuild=True)
```

## 测试

```bash
python -m unittest
```

覆盖场景：

- 正常构建与二分查找定位
- 尾部截断（残缺帧头 / 残缺负载）的损坏定位与完整记录可读
- 负载篡改导致 CRC 校验失败、魔数错误
- 跨段查询的全局偏移唯一性、连续性与时间范围过滤
- 空段索引与空段查询
- 索引过期拒绝静默覆盖、显式重建、索引文件损坏与版本拒绝
