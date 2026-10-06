#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
測試 Thread Gap Analyzer
涵蓋日誌解析、關鍵字判斷、判定邏輯、Thread 隔離、Stack Trace 附加與端到端分析。
"""

import sys
from datetime import datetime
from io import StringIO
from pathlib import Path
import unittest

# 將專案根目錄加入模組搜尋路徑
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from thread_gap_analyzer import (
    LogRecord,
    parse_log_line,
    parse_timestamp,
    is_sql,
    is_exception,
    get_judgment,
    short_text,
    print_gap,
    analyze_log,
)


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

    def test_is_sql(self):
        """測試 SQL 關鍵字識別"""
        self.assertTrue(is_sql("SELECT * FROM USERS"))
        self.assertTrue(is_sql("INSERT INTO orders VALUES (1)"))
        self.assertTrue(is_sql("UPDATE accounts SET balance = 0"))
        self.assertTrue(is_sql("DELETE FROM cache"))
        self.assertTrue(is_sql("WITH cte AS (SELECT 1) SELECT * FROM cte"))
        self.assertFalse(is_sql("User login successfully"))
        self.assertFalse(is_sql("Connection pool initialized"))

    def test_is_exception(self):
        """測試 Exception 關鍵字識別"""
        self.assertTrue(is_exception("ERROR java.sql.SQLTimeoutException: timeout"))
        self.assertTrue(is_exception("Exception in thread main"))
        self.assertTrue(is_exception("ORA-01013: user requested cancel"))
        self.assertTrue(is_exception("Connection TIMEOUT after 30s"))
        self.assertFalse(is_exception("Query completed in 10ms"))
        self.assertFalse(is_exception("System ready to accept connections"))

    def test_get_judgment(self):
        """測試 4 種判定類型"""
        ts = datetime(2026, 10, 6, 10, 0, 0)

        sql_record = LogRecord(ts, "t1", "SELECT * FROM USERS", 1, "")
        timeout_record = LogRecord(ts, "t1", "ERROR java.sql.SQLTimeoutException", 2, "")
        normal_record = LogRecord(ts, "t1", "INFO query completed", 3, "")
        app_err_record = LogRecord(ts, "t1", "ERROR NullPointerException in service", 4, "")

        # 1. SQL 執行過久後發生 Exception
        self.assertEqual(
            get_judgment(sql_record, timeout_record),
            "SQL 執行過久後發生 Exception"
        )

        # 2. 疑似慢 SQL
        self.assertEqual(
            get_judgment(sql_record, normal_record),
            "疑似慢 SQL"
        )

        # 3. 長時間停頓後發生 Exception
        self.assertEqual(
            get_judgment(normal_record, app_err_record),
            "長時間停頓後發生 Exception"
        )

        # 4. 疑似長時間停頓
        self.assertEqual(
            get_judgment(normal_record, normal_record),
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
        events = analyze_log(sample_path, threshold_seconds=30)

        # 預期抓出 6 筆 Gap >= 30s
        self.assertEqual(len(events), 6)

        # 案例 1: thread-17 (375 秒, SQL + Exception)
        e1 = events[0]
        self.assertEqual(e1.thread_name, "thread-17")
        self.assertAlmostEqual(e1.gap_seconds, 375.0, places=2)
        self.assertEqual(e1.judgment, "SQL 執行過久後發生 Exception")
        self.assertTrue(
            any("oracle.jdbc.driver.T4CPreparedStatement" in line for line in e1.current.continuation_lines)
        )

        # 案例 2: http-nio-8080-exec-5 (45.5 秒, 疑似慢 SQL)
        e2 = events[1]
        self.assertEqual(e2.thread_name, "http-nio-8080-exec-5")
        self.assertAlmostEqual(e2.gap_seconds, 45.5, places=2)
        self.assertEqual(e2.judgment, "疑似慢 SQL")

        # 案例 3: worker-pool-3 (70.0 秒, 長時間停頓後發生 Exception)
        e3 = events[2]
        self.assertEqual(e3.thread_name, "worker-pool-3")
        self.assertAlmostEqual(e3.gap_seconds, 70.0, places=2)
        self.assertEqual(e3.judgment, "長時間停頓後發生 Exception")

        # 案例 4: batch-calc-1 (52.0 秒, 疑似長時間停頓)
        e4 = events[3]
        self.assertEqual(e4.thread_name, "batch-calc-1")
        self.assertAlmostEqual(e4.gap_seconds, 52.0, places=2)
        self.assertEqual(e4.judgment, "疑似長時間停頓")

        # 案例 5: interleave-A (42.0 秒, 多 Thread 交錯隔離測試)
        e5 = events[4]
        self.assertEqual(e5.thread_name, "interleave-A")
        self.assertAlmostEqual(e5.gap_seconds, 42.0, places=2)
        self.assertEqual(e5.judgment, "疑似慢 SQL")

        # 案例 6: deep-stack-thread (60.0 秒, Stack Trace 超過 20 行)
        e6 = events[5]
        self.assertEqual(e6.thread_name, "deep-stack-thread")
        self.assertAlmostEqual(e6.gap_seconds, 60.0, places=2)
        self.assertEqual(e6.judgment, "SQL 執行過久後發生 Exception")
        self.assertEqual(len(e6.current.continuation_lines), 23)

    def test_print_gap_output(self):
        """測試 print_gap 的輸出格式與長 stack trace 省略提示"""
        sample_path = ROOT_DIR / "samples" / "sample_thread_gap.log"
        events = analyze_log(sample_path, threshold_seconds=30)

        # 測試截獲 deep-stack-thread 的 print_gap 輸出
        deep_event = [e for e in events if e.thread_name == "deep-stack-thread"][0]

        buf = StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = buf
            print_gap(deep_event)
        finally:
            sys.stdout = old_stdout

        output = buf.getvalue()
        self.assertIn("Thread       : deep-stack-thread", output)
        self.assertIn("判定         : SQL 執行過久後發生 Exception", output)
        self.assertIn("Exception Stack Trace：", output)
        self.assertIn("... stack trace 已省略 ...", output)


if __name__ == "__main__":
    unittest.main()
