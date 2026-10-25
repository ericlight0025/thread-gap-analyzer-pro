#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
測試 Thread Gap Analyzer
涵蓋日誌解析、關鍵字判斷、判定邏輯、Thread 隔離、Stack Trace 附加與端到端分析。
"""

import sys
import csv
import subprocess
import tempfile
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
    record_text,
    csv_cell,
    ensure_distinct_output_paths,
    load_config,
    export_csv,
    export_html,
    MAX_CONCURRENT_ERRORS_PER_GAP,
    MAX_CONTINUATION_LINE_CHARS,
    MAX_DETAILED_EXCEPTIONS_PRINTED,
    ExceptionRecord,
    analyze_log,
    is_exception,
    print_summary,
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
        # 形狀正確但數值不合法
        self.assertIsNone(parse_timestamp("2026-13-45 10:00:00"))

        # 非 3/6 位小數秒、無冒號時區與 Z，在 Python 3.8–3.10 的 fromisoformat 不支援
        self.assertEqual(parse_timestamp("2026-10-06 10:00:00.12"), datetime(2026, 10, 6, 10, 0, 0, 120000))
        self.assertEqual(parse_timestamp("2026-10-06 10:00:00,1234"), datetime(2026, 10, 6, 10, 0, 0, 123400))
        self.assertEqual(parse_timestamp("2026-10-06T10:00:00+0800"), datetime(2026, 10, 6, 2, 0, 0))
        self.assertEqual(parse_timestamp("2026-10-06T10:00:00.5-05:30"), datetime(2026, 10, 6, 15, 30, 0, 500000))
        self.assertEqual(parse_timestamp("2026-10-06T10:00:00Z"), datetime(2026, 10, 6, 10, 0, 0))

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

        # 部分 Logback / Log4j 格式會將時間戳記包在方括號內
        bracketed_line = "[2026-10-06 10:00:00.000] [thread-17] INFO started"
        bracketed_record = parse_log_line(bracketed_line, 6)
        self.assertIsNotNone(bracketed_record)
        self.assertEqual(bracketed_record.thread_name, "thread-17")

    def test_invalid_timezone_offsets_and_utc_overflow_are_rejected(self):
        for timestamp in (
            "2026-10-06T10:00:00+24:00",
            "2026-10-06T10:00:00+08:60",
            "2026-10-06T10:00:00-9999",
            "0001-01-01T00:00:00+00:01",
            "9999-12-31T23:59:59-00:01",
        ):
            with self.subTest(timestamp=timestamp):
                self.assertIsNone(parse_timestamp(timestamp))
                self.assertIsNone(parse_log_line(f"{timestamp} [worker] INFO test", 1))
        self.assertEqual(
            parse_timestamp("2026-10-06T10:00:00+23:59"),
            datetime(2026, 10, 5, 10, 1),
        )

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

    def test_generic_error_and_timeout_are_collected(self):
        events, exceptions = self._analyze_lines([
            "2026-10-06 10:00:00.000 [worker] SELECT * FROM USERS",
            "2026-10-06 10:00:30.000 [worker] ERROR Connection refused",
            "2026-10-06 10:01:00.000 [timeout-worker] WARN Query timeout after 60 seconds",
        ])

        self.assertEqual([item.exc_type for item in exceptions], [
            "Error (unclassified)",
            "Timeout (unclassified)",
        ])
        self.assertEqual(events[0].judgment, "前一筆 SQL 後發生 Exception（時間關聯）")

    def test_analyze_log_rejects_unparseable_log(self):
        with self.assertRaises(ValueError):
            self._analyze_lines(["not a supported log format", "still not a log"])

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

    def test_record_text_and_exports_include_continuation_lines(self):
        events, exceptions = self._analyze_lines([
            "2026-10-06 10:00:00.000 [worker] DEBUG Preparing statement",
            "SELECT * FROM SECRET_QUERY_TABLE",
            "WHERE ID = 1",
            "2026-10-06 10:00:30.000 [worker] INFO done",
        ])
        self.assertIn("SECRET_QUERY_TABLE", record_text(events[0].previous))

        html_output = NonClosingStringIO()
        csv_output = NonClosingStringIO()
        with patch.object(Path, "open", side_effect=[html_output, csv_output]):
            export_html(events, exceptions, Path("report.html"))
            export_csv(events, Path("report.csv"))

        self.assertIn("SECRET_QUERY_TABLE", html_output.getvalue())
        self.assertIn("SECRET_QUERY_TABLE", csv_output.getvalue())

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

    def test_is_exception_prefilter_keeps_all_signals(self):
        for message in (
            "ERROR something failed",
            "java.lang.NullPointerException",
            "ORA-01013: user requested cancel",
            "Read TIMEOUT after 30s",
            "com.example.CustomError raised",
        ):
            self.assertTrue(is_exception(message), message)
        self.assertFalse(is_exception("INFO Processed incoming request successfully"))

    def test_sql_candidate_is_computed_lazily_and_cached(self):
        ts = datetime(2026, 10, 6, 10, 0, 0)
        previous = LogRecord(ts, "t1", "SELECT * FROM USERS", 1)
        current = LogRecord(ts, "t1", "INFO done", 2)
        self.assertIsNone(previous.sql_candidate)
        get_judgment(previous, current, None)
        self.assertTrue(previous.sql_candidate)

    def test_detailed_exception_list_is_capped_in_terminal(self):
        ts = datetime(2026, 10, 6, 10, 0, 0)
        total = MAX_DETAILED_EXCEPTIONS_PRINTED + 7
        exceptions = [
            ExceptionRecord(ts, f"t{i}", "java.lang.NullPointerException", "Unknown", i)
            for i in range(total)
        ]
        with patch("sys.stdout", new_callable=StringIO) as stdout:
            print_summary([], exceptions, 30)
        output = stdout.getvalue()
        self.assertIn("其餘 7 筆未顯示", output)
        self.assertNotIn(f"t{total - 1} ", output.split("詳細異常清單")[1])


    def test_load_config_reads_toml(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text(
                "log_file = \"app.log\"\n"
                "threshold_seconds = 45\n"
                "ignore_threads = 'batch.*|ping'\n"
                "[output]\nquiet = true\nhtml_report = \"r.html\"\n",
                encoding="utf-8",
            )
            config = load_config(path)
        self.assertEqual(config["threshold_seconds"], 45)
        self.assertEqual(config["ignore_threads"], "batch.*|ping")
        self.assertEqual(config["output"], {"quiet": True, "html_report": "r.html"})

    def test_load_config_missing_file_returns_empty(self):
        self.assertEqual(load_config(Path("does-not-exist.toml")), {})

    def test_load_config_rejects_invalid_toml(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text("threshold_seconds: 30\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_config(path)

    def test_bundled_config_is_valid(self):
        config = load_config(ROOT_DIR / "config.toml")
        self.assertEqual(config["log_file"], "samples/demo_performance.log")
        self.assertIsInstance(config["output"], dict)

    def test_cli_validates_output_table(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.toml"
            log_path = ROOT_DIR / "samples" / "sample_thread_gap.log"
            for value in ("false", "0", '""', "[]"):
                with self.subTest(output=value):
                    config_path.write_text(f"output = {value}\n", encoding="utf-8")
                    result = subprocess.run(
                        [sys.executable, str(ROOT_DIR / "thread_gap_analyzer.py"),
                         str(log_path), "--config", str(config_path)],
                        capture_output=True, text=True, encoding="utf-8",
                    )
                    self.assertEqual(result.returncode, 2)
                    self.assertIn("output 必須是 TOML table", result.stderr)
            config_path.write_text("[output]\n", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(ROOT_DIR / "thread_gap_analyzer.py"),
                 str(log_path), "--config", str(config_path)],
                capture_output=True, text=True, encoding="utf-8",
            )
            self.assertEqual(result.returncode, 0, result.stderr)



if __name__ == "__main__":
    unittest.main()
