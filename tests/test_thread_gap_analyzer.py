#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
測試 Thread Gap Analyzer
涵蓋日誌解析、關鍵字判斷、判定邏輯、Thread 隔離、Stack Trace 附加與端到端分析。
"""

import sys
import csv
from datetime import datetime
from io import StringIO
from pathlib import Path
import unittest
from unittest.mock import patch

# 將專案根目錄加入模組搜尋路徑
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from thread_gap_analyzer import (
    LogRecord,
    parse_log_line,
    parse_timestamp,
    is_sql,
    extract_exception_info,
    get_judgment,
    short_text,
    csv_cell,
    ensure_distinct_output_paths,
    export_csv,
    export_html,
    MAX_CONCURRENT_ERRORS_PER_GAP,
    MAX_CONTINUATION_LINE_CHARS,
    analyze_log,
)


class NonClosingStringIO(StringIO):
    """讓被測函式的 context manager 不會關閉測試用 buffer。"""

    def close(self):
        pass


class TestThreadGapAnalyzer(unittest.TestCase):

    def test_parse_timestamp(self):
        """測試 Timestamp 解析（支援微秒、逗號、標準空格）"""
        dt1 = parse_timestamp("2026-10-06 10:00:00.123")
        self.assertIsNotNone(dt1)
        self.assertEqual(dt1, datetime(2026, 10, 6, 10, 0, 0, 123000))

        # 逗號毫秒
        dt2 = parse_timestamp("2026-10-06 10:00:00,456")
        self.assertIsNotNone(dt2)
        self.assertEqual(dt2, datetime(2026, 10, 6, 10, 0, 0, 456000))

        # 無毫秒
        dt3 = parse_timestamp("2026-10-06 10:00:00")
        self.assertIsNotNone(dt3)
        self.assertEqual(dt3, datetime(2026, 10, 6, 10, 0, 0))

        # 無效字串
        self.assertIsNone(parse_timestamp("invalid-date"))

    def test_parse_log_line(self):
        """測試 Log 行解析"""
        line = "2026-10-06 10:00:00.000 [thread-17] SELECT * FROM POLICY_HISTORY"
        rec = parse_log_line(line, 1)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.thread_name, "thread-17")
        self.assertEqual(rec.message, "SELECT * FROM POLICY_HISTORY")
        self.assertEqual(rec.line_number, 1)

        # 包含 Log level 的行
        line_with_level = "2026-10-06 10:06:15.000 [thread-17] ERROR java.sql.SQLTimeoutException: timeout"
        rec_level = parse_log_line(line_with_level, 4)
        self.assertIsNotNone(rec_level)
        self.assertEqual(rec_level.thread_name, "thread-17")
        self.assertIn("SQLTimeoutException", rec_level.message)

        # 無 timestamp 的行（例如 stack trace）應回傳 None
        stack_line = "    at oracle.jdbc.driver.T4CPreparedStatement.execute()"
        self.assertIsNone(parse_log_line(stack_line, 5))

    def _make_dummy_record(self, msg: str) -> LogRecord:
        return LogRecord(datetime.now(), "thread", msg, 1)

    def _analyze_lines(self, lines, threshold=30):
        content = "\n".join(lines) + "\n"
        with patch.object(Path, "open", return_value=StringIO(content)):
            return analyze_log(Path("in-memory.log"), threshold_seconds=threshold)

    def test_is_sql(self):
        """測試 SQL 關鍵字識別"""
        self.assertTrue(is_sql(self._make_dummy_record("SELECT * FROM USERS")))
        self.assertTrue(is_sql(self._make_dummy_record("INSERT INTO orders VALUES (1)")))
        self.assertTrue(is_sql(self._make_dummy_record("UPDATE accounts SET balance = 0")))
        self.assertTrue(is_sql(self._make_dummy_record("DELETE FROM cache")))
        self.assertTrue(is_sql(self._make_dummy_record("WITH cte AS (SELECT 1) SELECT * FROM cte")))
        self.assertFalse(is_sql(self._make_dummy_record("User login successfully")))
        self.assertFalse(is_sql(self._make_dummy_record("Connection pool initialized")))
        # 測試 HTTP DELETE
        self.assertFalse(is_sql(self._make_dummy_record("DELETE /api/v1/users 200")))
        self.assertFalse(is_sql(self._make_dummy_record("INFO DELETE /api/v1/users 200")))



    def test_get_judgment(self):
        """測試 4 種判定類型"""
        ts = datetime(2026, 10, 6, 10, 0, 0)

        sql_record = LogRecord(ts, "t1", "SELECT * FROM USERS", 1)
        timeout_record = LogRecord(ts, "t1", "ERROR java.sql.SQLTimeoutException", 2)
        normal_record = LogRecord(ts, "t1", "INFO query completed", 3)
        app_err_record = LogRecord(ts, "t1", "ERROR NullPointerException in service", 4)

        # 1. SQL 執行過久後發生 Exception
        self.assertEqual(
            get_judgment(sql_record, timeout_record, "SQLTimeoutException"),
            "前一筆 SQL 後發生 Exception（時間關聯）"
        )

        # 2. 疑似慢 SQL
        self.assertEqual(
            get_judgment(sql_record, normal_record, None),
            "前一筆為 SQL（疑似慢 SQL）"
        )

        # 3. 長時間停頓後發生 Exception
        self.assertEqual(
            get_judgment(normal_record, app_err_record, "NullPointerException"),
            "長時間停頓後發生 Exception（時間關聯）"
        )

        # 4. 疑似長時間停頓
        self.assertEqual(
            get_judgment(normal_record, normal_record, None),
            "疑似長時間停頓"
        )

    def test_short_text(self):
        """測試長字串截斷函數"""
        short = "short"
        self.assertEqual(short_text(short, 10), "short")
        long_str = "a" * 100
        result = short_text(long_str, 20)
        self.assertTrue(result.endswith("..."))
        self.assertEqual(len(result), 24)  # 20 + ' ...'

    def test_analyze_sample_log(self):
        """測試使用真實 sample_thread_gap.log 進行完整分析"""
        sample_path = ROOT_DIR / "samples" / "sample_thread_gap.log"
        self.assertTrue(sample_path.exists(), f"Sample file not found at {sample_path}")

        # 門檻設為 30 秒
        events, _ = analyze_log(sample_path, threshold_seconds=30)

        # 預期抓出 6 筆 Gap >= 30s
        self.assertEqual(len(events), 6)

        # 案例 1: thread-17 (375 秒, SQL + Exception)
        e1 = events[0]
        self.assertEqual(e1.thread_name, "thread-17")
        self.assertAlmostEqual(e1.gap_seconds, 375.0, places=2)
        self.assertEqual(e1.judgment, "前一筆 SQL 後發生 Exception（時間關聯）")
        self.assertTrue(
            any("oracle.jdbc.driver.T4CPreparedStatement" in line for line in e1.current.continuation_lines)
        )

        # 案例 2: http-nio-8080-exec-5 (45.5 秒, 疑似慢 SQL)
        e2 = events[1]
        self.assertEqual(e2.thread_name, "http-nio-8080-exec-5")
        self.assertAlmostEqual(e2.gap_seconds, 45.5, places=2)
        self.assertEqual(e2.judgment, "前一筆為 SQL（疑似慢 SQL）")

        # 案例 3: worker-pool-3 (70.0 秒, 長時間停頓後發生 Exception)
        e3 = events[2]
        self.assertEqual(e3.thread_name, "worker-pool-3")
        self.assertAlmostEqual(e3.gap_seconds, 70.0, places=2)
        self.assertEqual(e3.judgment, "長時間停頓後發生 Exception（時間關聯）")

        # 案例 4: batch-calc-1 (52.0 秒, 疑似長時間停頓)
        e4 = events[3]
        self.assertEqual(e4.thread_name, "batch-calc-1")
        self.assertAlmostEqual(e4.gap_seconds, 52.0, places=2)
        self.assertEqual(e4.judgment, "疑似長時間停頓")

        # 案例 5: interleave-A (42.0 秒, 多 Thread 交錯隔離測試)
        e5 = events[4]
        self.assertEqual(e5.thread_name, "interleave-A")
        self.assertAlmostEqual(e5.gap_seconds, 42.0, places=2)
        self.assertEqual(e5.judgment, "前一筆為 SQL（疑似慢 SQL）")

        # 案例 6: deep-stack-thread (60.0 秒, Stack Trace 超過 20 行)
        e6 = events[5]
        self.assertEqual(e6.thread_name, "deep-stack-thread")
        self.assertAlmostEqual(e6.gap_seconds, 60.0, places=2)
        self.assertEqual(e6.judgment, "前一筆 SQL 後發生 Exception（時間關聯）")
        self.assertEqual(len(e6.current.continuation_lines), 23)

    def test_exception_in_continuation_is_collected(self):
        events, exceptions = self._analyze_lines([
            "2026-10-06 10:00:00.000 [worker] INFO start",
            "2026-10-06 10:00:30.000 [worker] INFO request failed",
            "java.lang.NullPointerException: broken",
            "    at com.example.Service.run(Service.java:42)",
        ])

        self.assertEqual(len(exceptions), 1)
        self.assertEqual(exceptions[0].exc_type, "java.lang.NullPointerException")
        self.assertEqual(events[0].judgment, "長時間停頓後發生 Exception（時間關聯）")

    def test_exception_location_prefers_application_frame(self):
        record = LogRecord(
            datetime(2026, 10, 6), "worker", "ERROR java.sql.SQLException", 1,
            continuation_lines=[
                "    at oracle.jdbc.Driver.execute(Driver.java:10)",
                "    at com.example.Service.query(Service.java:42)",
            ],
        )
        self.assertEqual(extract_exception_info(record)[1], "Service.java:42")

    def test_out_of_order_exceptions_are_sorted_before_bisect(self):
        events, _ = self._analyze_lines([
            "2026-10-06 10:00:00.000 [worker] INFO start",
            "2026-10-06 10:00:50.000 [later] ERROR LaterException",
            "2026-10-06 10:00:20.000 [inside] ERROR InsideException",
            "2026-10-06 10:00:30.000 [worker] INFO end",
        ])
        self.assertEqual([item.exc_type for item in events[0].concurrent_errors], ["InsideException"])

    def test_concurrent_error_references_are_capped_with_total_count(self):
        lines = ["2026-10-06 10:00:00.000 [worker] INFO start"]
        lines.extend(
            f"2026-10-06 10:00:15.000 [error-{index}] ERROR TestException"
            for index in range(MAX_CONCURRENT_ERRORS_PER_GAP + 5)
        )
        lines.append("2026-10-06 10:00:30.000 [worker] INFO end")
        events, _ = self._analyze_lines(lines)
        self.assertEqual(events[0].concurrent_error_count, MAX_CONCURRENT_ERRORS_PER_GAP + 5)
        self.assertEqual(len(events[0].concurrent_errors), MAX_CONCURRENT_ERRORS_PER_GAP)

    def test_continuation_line_is_character_limited(self):
        events, _ = self._analyze_lines([
            "2026-10-06 10:00:00.000 [worker] INFO start",
            "x" * (MAX_CONTINUATION_LINE_CHARS + 100),
            "2026-10-06 10:00:30.000 [worker] INFO end",
        ])
        self.assertLessEqual(
            len(events[0].previous.continuation_lines[0]),
            MAX_CONTINUATION_LINE_CHARS + len(" … [truncated]"),
        )

    def test_timezone_offsets_are_normalized_to_utc(self):
        events, _ = self._analyze_lines([
            "2026-10-06 10:00:00+02:00 [worker] INFO start",
            "2026-10-06 10:00:00+00:00 [worker] INFO end",
        ], threshold=1)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].gap_seconds, 7200)

    def test_csv_formula_cells_are_neutralized(self):
        self.assertEqual(csv_cell("=1+1"), "'=1+1")
        self.assertEqual(csv_cell("normal text"), "normal text")

    def test_csv_export_neutralizes_log_formula(self):
        events, _ = self._analyze_lines([
            "2026-10-06 10:00:00.000 [=worker] =message",
            "2026-10-06 10:00:30.000 [=worker] INFO end",
        ])
        output = NonClosingStringIO()
        with patch.object(Path, "open", return_value=output):
            export_csv(events, Path("report.csv"))

        row = list(csv.reader(StringIO(output.getvalue().lstrip("\ufeff"))))[1]
        self.assertEqual(row[0], "'=worker")
        self.assertEqual(row[8], "'=message")

    def test_html_export_escapes_log_content(self):
        payload = "<img src=x onerror=alert(1)>"
        events, exceptions = self._analyze_lines([
            f"2026-10-06 10:00:00.000 [{payload}] {payload}",
            f"2026-10-06 10:00:30.000 [{payload}] ERROR TestException {payload}",
        ])
        output = NonClosingStringIO()
        with patch.object(Path, "open", return_value=output):
            export_html(events, exceptions, Path("report.html"))

        content = output.getvalue()
        self.assertNotIn(payload, content)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", content)

    def test_output_path_cannot_overwrite_input(self):
        path = Path("sample.log")
        with self.assertRaises(ValueError):
            ensure_distinct_output_paths(path, path)



if __name__ == "__main__":
    unittest.main()
