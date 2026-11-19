"""logseg 的异常类型。"""


class LogSegError(Exception):
    """所有 logseg 异常的基类。"""


class IndexError(LogSegError):
    """旁路索引相关错误的基类。"""


class IndexFormatError(IndexError):
    """索引文件无法解析或格式版本不受支持。"""


class StaleIndexError(IndexError):
    """索引与段文件长度不一致，拒绝静默覆盖。

    调用方必须显式调用 :meth:`logseg.index.rebuild_index`
    （或 ``rebuild=True``）才能重算索引。
    """

    def __init__(self, path, indexed_size, actual_size):
        self.path = path
        self.indexed_size = indexed_size
        self.actual_size = actual_size
        super().__init__(
            "索引 %s 已过期：记录的段长度为 %d，实际段长度为 %d；"
            "拒绝静默覆盖，请显式重建索引" % (path, indexed_size, actual_size)
        )


class SegmentError(LogSegError):
    """段文件命名或写入相关错误。"""
