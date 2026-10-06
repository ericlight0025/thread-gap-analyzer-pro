#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Thread Gap Analyzer Pro

透過串流架構與時間差計算，快速找出應用程式日誌中的異常停頓點，
並支援 YAML 配置、跨行 SQL 擷取與 HTML 報表產出。
"""

import argparse
import csv
import html
import re
import sys
from bisect import bisect_left, bisect_right
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml

TIME_FORMATS = (
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
)

LOG_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?(?:Z|[+-]\d{2}:?\d{2})?)[^\[]*\[([^\]]+)\]\s*(.*)$"
)

MAX_CONTINUATION_LINES = 100
MAX_CONTINUATION_LINE_CHARS = 4_096
MAX_CONTINUATION_CHARS = 65_536
MAX_MESSAGE_CHARS = 16_384
MAX_CONCURRENT_ERRORS_PER_GAP = 50
TRUNCATION_MARKER = " … [truncated]"

HTTP_REQUEST_PATTERN = re.compile(
    r"^\s*(?:[A-Z]+\s+){0,4}(?:GET|POST|PUT|DELETE|PATCH)\s+/",
    re.IGNORECASE,
)
SQL_KEYWORD_PATTERN = re.compile(
    r"\b(?:SELECT|INSERT|UPDATE|DELETE|MERGE|WITH)\b\s+",
    re.IGNORECASE,
)
STACK_LOCATION_PATTERN = re.compile(r"at\s+([a-zA-Z0-9_.$]+)\(([^:]+:\d+)\)")
EXCEPTION_TYPE_PATTERN = re.compile(
    r"([a-zA-Z0-9_.]+(?:Exception|Error))\b", re.IGNORECASE
)
ORA_PATTERN = re.compile(r"(ORA-\d{5})")
FRAMEWORK_PREFIXES = (
    "java.", "javax.", "org.apache.", "org.springframework.",
    "oracle.jdbc.", "com.sun.",
)


def compact_dataclass(cls):
    """Python 3.10+ 使用 slots；保留 README 宣告的 Python 3.8 相容性。"""
    if sys.version_info >= (3, 10):
        return dataclass(cls, slots=True)
    return dataclass(cls)


@compact_dataclass
class LogRecord:
    timestamp: datetime
    thread_name: str
    message: str
    line_number: int
    continuation_lines: List[str] = field(default_factory=list)
    continuation_char_count: int = 0
    exc_type: Optional[str] = None
    exc_location: Optional[str] = None
    sql_candidate: Optional[bool] = None

@compact_dataclass
class ExceptionRecord:
    """輕量級的異常紀錄，避免將完整 LogRecord 存在全域清單吃光記憶體"""
    timestamp: datetime
    thread_name: str
    exc_type: str
    location: str
    line_number: int

@compact_dataclass
class GapEvent:
    thread_name: str
    previous: LogRecord
    current: LogRecord
    gap_seconds: float
    judgment: str
    concurrent_errors: List[ExceptionRecord] = field(default_factory=list)
    concurrent_error_count: int = 0
    exc_type: Optional[str] = None
    exc_location: Optional[str] = None

def parse_timestamp(ts_str: str) -> Optional[datetime]:
    clean_ts = ts_str.replace(",", ".").replace("T", " ")
    if clean_ts.endswith("Z"):
        clean_ts = clean_ts[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(clean_ts)
        if parsed.tzinfo is not None:
            # 將帶時區的日誌統一成 UTC naive datetime，避免 aware/naive 無法比較。
            return parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    except ValueError:
        pass

    for fmt in TIME_FORMATS:
        try:
            return datetime.strptime(clean_ts, fmt)
        except ValueError:
            pass
    return None

def parse_log_line(line: str, line_number: int) -> Optional[LogRecord]:
    match = LOG_PATTERN.match(line)
    if not match:
        return None

    timestamp = parse_timestamp(match.group(1))
    if timestamp is None:
        return None

    return LogRecord(
        timestamp=timestamp,
        thread_name=match.group(2).strip(),
        message=truncate_text(match.group(3), MAX_MESSAGE_CHARS),
        line_number=line_number,
    )

def is_sql(record: LogRecord) -> bool:
    texts = (record.message, *record.continuation_lines[:5])
    first_text = record.message.strip()
    if HTTP_REQUEST_PATTERN.match(first_text):
        return False

    return any(SQL_KEYWORD_PATTERN.search(text) for text in texts)

def is_exception(message: str) -> bool:
    upper = message.upper()
    keywords = ("EXCEPTION", "ERROR", "SQLERROR", "SQLEXCEPTION", "SQLTIMEOUTEXCEPTION", "ORA-", "TIMEOUT")
    return any(keyword in upper for keyword in keywords)


def has_exception_signal(record: LogRecord) -> bool:
    return any(is_exception(text) for text in (record.message, *record.continuation_lines))

def extract_exception_info(record: LogRecord) -> Tuple[Optional[str], Optional[str]]:
    """回傳 (ExceptionType, Location)，優化避開 Framework 層"""
    if not has_exception_signal(record):
        return None, None
        
    exc_type = None
    location = None
    fallback_location = None
    
    search_texts = [record.message] + record.continuation_lines
    for text in search_texts:
        if not exc_type:
            # 尋找典型的 Exception 類別名稱，或是 ORA- 開頭的錯誤
            match = EXCEPTION_TYPE_PATTERN.search(text)
            ora_match = ORA_PATTERN.search(text)
            if match:
                exc_type = match.group(1)
            elif ora_match:
                exc_type = ora_match.group(1)
                
        # 尋找 StackTrace 中的業務邏輯位置，跳過常見 Framework
        if location is None:
            loc_match = STACK_LOCATION_PATTERN.search(text)
            if loc_match:
                full_class = loc_match.group(1)
                loc_file_line = loc_match.group(2)
                if not any(full_class.startswith(p) for p in FRAMEWORK_PREFIXES):
                    location = loc_file_line
                elif fallback_location is None:
                    fallback_location = loc_file_line

    return exc_type, location or fallback_location


def finalize_record(record: LogRecord, global_exceptions: List[ExceptionRecord]) -> None:
    """在讀到下一筆 Log 後，將已完整的多行紀錄只分析一次。"""
    record.sql_candidate = is_sql(record)
    record.exc_type, record.exc_location = extract_exception_info(record)
    if record.exc_type:
        global_exceptions.append(ExceptionRecord(
            timestamp=record.timestamp,
            thread_name=record.thread_name,
            exc_type=record.exc_type,
            location=record.exc_location or "Unknown",
            line_number=record.line_number,
        ))

def get_judgment(previous: LogRecord, current: LogRecord, current_exc_type: Optional[str]) -> str:
    previous_is_sql = (
        previous.sql_candidate
        if previous.sql_candidate is not None
        else is_sql(previous)
    )
    current_is_exception = bool(current_exc_type)

    if previous_is_sql and current_is_exception:
        return "前一筆 SQL 後發生 Exception（時間關聯）"
    elif previous_is_sql:
        return "前一筆為 SQL（疑似慢 SQL）"
    elif current_is_exception:
        return "長時間停頓後發生 Exception（時間關聯）"
    else:
        return "疑似長時間停頓"

def analyze_log(
    log_file: Path, 
    threshold_seconds: int = 30,
    ignore_threads_pattern: Optional[str] = None
) -> Tuple[List[GapEvent], List[ExceptionRecord]]:
    
    gap_events: List[GapEvent] = []
    last_record_by_thread: Dict[str, LogRecord] = {}
    current_record: Optional[LogRecord] = None
    global_exceptions: List[ExceptionRecord] = []
    
    ignore_re = re.compile(ignore_threads_pattern) if ignore_threads_pattern else None

    # 第一階段：解析與擷取
    with log_file.open("r", encoding="utf-8", errors="replace") as file:
        for line_number, line in enumerate(file, start=1):
            record = parse_log_line(line, line_number)

            if record is not None:
                # 結算上一筆完整的多行紀錄。
                if current_record is not None:
                    finalize_record(current_record, global_exceptions)
                
                current_record = record
                thread = record.thread_name
                
                if ignore_re and ignore_re.match(thread):
                    continue
                    
                previous = last_record_by_thread.get(thread)
                if previous is not None:
                    gap = (record.timestamp - previous.timestamp).total_seconds()
                    if gap >= threshold_seconds:
                        event = GapEvent(
                            thread_name=thread,
                            previous=previous,
                            current=record,
                            gap_seconds=gap,
                            judgment="" # 將在第二階段賦值
                        )
                        gap_events.append(event)
                last_record_by_thread[thread] = record

            else:
                if current_record is not None:
                    append_continuation_line(current_record, line)

        # 處理檔案最後一筆紀錄
        if current_record is not None:
            finalize_record(current_record, global_exceptions)

    # 第二階段：關聯 Concurrent Errors 並補完 judgment (避免 O(G*E) 效能問題)
    # 多來源或非同步寫入 Log 可能亂序，必須在 bisect 前依時間排序。
    global_exceptions.sort(key=lambda exc: exc.timestamp)
    exc_timestamps = [e.timestamp for e in global_exceptions]

    for event in gap_events:
        event.exc_type = event.current.exc_type
        event.exc_location = event.current.exc_location
        event.judgment = get_judgment(event.previous, event.current, event.exc_type)

        t_start = event.previous.timestamp
        t_end = event.current.timestamp
        
        # 二元搜尋找尋時間區間內的 exceptions
        idx_start = bisect_left(exc_timestamps, t_start)
        idx_end = bisect_right(exc_timestamps, t_end)
        
        for i in range(idx_start, idx_end):
            exc_rec = global_exceptions[i]
            if exc_rec.thread_name != event.thread_name:
                event.concurrent_error_count += 1
                if len(event.concurrent_errors) < MAX_CONCURRENT_ERRORS_PER_GAP:
                    event.concurrent_errors.append(exc_rec)

    return gap_events, global_exceptions


def short_text(text: str, max_length: int = 500) -> str:
    text = text.strip()
    if len(text) <= max_length:
        return text
    return text[:max_length] + " ..."


def truncate_text(text: str, max_length: int) -> str:
    """限制保留的字元數，避免單一畸形 Log 行耗盡記憶體。"""
    if len(text) <= max_length:
        return text
    if max_length <= len(TRUNCATION_MARKER):
        return text[:max_length]
    return text[:max_length - len(TRUNCATION_MARKER)] + TRUNCATION_MARKER


def append_continuation_line(record: LogRecord, line: str) -> None:
    if len(record.continuation_lines) >= MAX_CONTINUATION_LINES:
        return
    if record.continuation_char_count >= MAX_CONTINUATION_CHARS:
        return

    remaining = MAX_CONTINUATION_CHARS - record.continuation_char_count
    stripped = line.strip()
    if not stripped:
        return
    value = truncate_text(stripped, min(MAX_CONTINUATION_LINE_CHARS, remaining))
    record.continuation_lines.append(value)
    record.continuation_char_count += len(value)


def group_exceptions(global_exceptions: List[ExceptionRecord]) -> List[Tuple[str, List[str]]]:
    exc_grouping = {}
    for exc in global_exceptions:
        if exc.exc_type not in exc_grouping:
            exc_grouping[exc.exc_type] = set()
        exc_grouping[exc.exc_type].add(exc.thread_name)
    
    # 轉為排序好的 list，回傳 (exc_type, [thread1, thread2...])
    return sorted(
        [(k, sorted(v)) for k, v in exc_grouping.items()],
        key=lambda x: (-len(x[1]), x[0]),
    )


def generate_error_heatmap(global_exceptions: List[ExceptionRecord]) -> Dict[str, int]:
    heatmap = {}
    for exc in global_exceptions:
        minute_key = exc.timestamp.strftime("%Y-%m-%d %H:%M")
        heatmap[minute_key] = heatmap.get(minute_key, 0) + 1
    return dict(sorted(heatmap.items()))


def print_summary(events: List[GapEvent], global_exceptions: List[ExceptionRecord], threshold: int):
    print("=" * 100)
    print("【分析摘要】")
    print(f"總共發現 {len(events)} 筆 Thread Gap (>= {threshold} 秒)")
    print()

    if events:
        sorted_events = sorted(events, key=lambda e: e.gap_seconds, reverse=True)
        print("🏆 Top 10 最耗時停頓：")
        for i, e in enumerate(sorted_events[:10], start=1):
            print(f"  {i}. [{e.gap_seconds:7.2f}s] {e.thread_name} - {e.judgment}")
        print()

    if global_exceptions:
        heatmap = generate_error_heatmap(global_exceptions)
        print("📉 異常時間熱區圖 (Error Heatmap - per minute)：")
        max_count = max(heatmap.values())
        for time_key, count in heatmap.items():
            bar_len = int((count / max_count) * 40) if max_count > 0 else 0
            bar = "█" * bar_len
            print(f"  {time_key} : {count:3} 筆 | {bar}")
        print()

    if global_exceptions:
        print("💥 Exception 反向追蹤與影響範圍 (Exceptions Grouped by Type)：")
        grouped = group_exceptions(global_exceptions)
        for exc_type, threads in grouped:
            display_threads = ", ".join(threads[:5])
            if len(threads) > 5:
                display_threads += f" ... (等共 {len(threads)} 個 Thread)"
            print(f"  [{len(threads):>3} 影響] {exc_type:<35}")
            print(f"           👉 Threads: {display_threads}")
        print()

        print("📋 詳細異常清單 (Detailed Exceptions Summary)：")
        print(f"{'Thread ID':<25} | {'Line':<8} | {'Exception Type':<35} | Location")
        print("-" * 100)
        
        for exc in global_exceptions:
            exc_type = short_text(exc.exc_type, 33)
            loc = exc.location
            print(f"{exc.thread_name:<25} | {exc.line_number:<8} | {exc_type:<35} | {loc}")
        print()


def export_html(events: List[GapEvent], global_exceptions: List[ExceptionRecord], html_path: Path) -> None:
    """逐段寫入報表，避免大型結果在記憶體中再複製一份 HTML 字串。"""
    with html_path.open("w", encoding="utf-8", newline="\n") as output:
        output.write(f"""<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <title>Thread Gap & Exception Report</title>
    <style>
        body {{ background-color: #1e1e1e; color: #d4d4d4; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; }}
        h1, h2, h3 {{ color: #569cd6; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 30px; background-color: #252526; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #3c3c3c; }}
        th {{ background-color: #333333; color: #4ec9b0; }}
        tr:hover {{ background-color: #2a2d2e; }}
        .card {{ background-color: #252526; padding: 15px; border-radius: 5px; margin-bottom: 20px; border-left: 4px solid #c586c0; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; margin-right: 10px; }}
        .bg-red {{ background-color: #f44336; color: white; }}
        .bg-orange {{ background-color: #ff9800; color: white; }}
        pre {{ background-color: #1e1e1e; padding: 10px; border: 1px solid #3c3c3c; overflow-x: auto; color: #ce9178; font-size: 13px; }}
        .context-box {{ background-color: #3e2a2a; border-left: 4px solid #f44336; padding: 10px; margin-top: 10px; }}
        .heatmap-row {{ display: flex; align-items: center; margin-bottom: 5px; }}
        .heatmap-time {{ width: 140px; font-family: monospace; color: #9cdcfe; }}
        .heatmap-bar-container {{ width: 300px; background-color: #333; border-radius: 3px; overflow: hidden; }}
        .heatmap-bar {{ background-color: #f44336; color: white; font-size: 11px; text-align: right; padding-right: 5px; height: 18px; line-height: 18px; white-space: nowrap; }}
    </style>
</head>
<body>
    <h1>🧵 Thread Gap & Exception Analyzer</h1>
    <p>產出時間：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
"""
        )
        if global_exceptions:
            output.write("<h2>📉 異常時間熱區圖 (Error Heatmap)</h2>\n")
            heatmap = generate_error_heatmap(global_exceptions)
            max_count = max(heatmap.values())
            for time_key, count in heatmap.items():
                pct = int((count / max_count) * 100) if max_count > 0 else 0
                width_pct = max(pct, 8)
                output.write(f"""
            <div class="heatmap-row">
                <div class="heatmap-time">{html.escape(time_key)}</div>
                <div class="heatmap-bar-container">
                    <div class="heatmap-bar" style="width: {width_pct}%;">{count}</div>
                </div>
            </div>
            """
                )

            output.write("<h2>🔍 Exception 影響範圍 (Grouped by Type)</h2>\n")
            for exc_type, threads in group_exceptions(global_exceptions):
                display_threads = ", ".join(
                    f"<code>{html.escape(t)}</code>" for t in threads[:10]
                )
                if len(threads) > 10:
                    display_threads += f" ... 等共 {len(threads)} 個 Thread"
                output.write(f"""
            <div class="card" style="border-left-color: #f44336;">
                <h3><span class="badge bg-red">{len(threads)} 影響</span> {html.escape(exc_type)}</h3>
                <p><b>牽連的 Thread：</b> {display_threads}</p>
            </div>
            """
                )

        output.write("""
    <h2>📋 詳細異常清單 (Detailed Exceptions)</h2>
    <table>
        <tr>
            <th>Thread ID</th>
            <th>Log 行號</th>
            <th>發生時間</th>
            <th>Exception 類型</th>
            <th>程式碼位置 (Location)</th>
        </tr>
"""
        )
        for exc in global_exceptions:
            output.write(f"""
        <tr>
            <td><code>{html.escape(exc.thread_name)}</code></td>
            <td>{exc.line_number}</td>
            <td>{exc.timestamp}</td>
            <td style="color: #f48771;">{html.escape(exc.exc_type)}</td>
            <td><code>{html.escape(exc.location)}</code></td>
        </tr>"""
            )

        output.write("""
    </table>

    <h2>⏱️ Top 停頓事件 (Gap Events)</h2>
"""
        )
        for event in sorted(events, key=lambda item: item.gap_seconds, reverse=True):
            badge_class = "bg-red" if event.exc_type else "bg-orange"
            concurrent_html = ""
            if event.concurrent_error_count:
                concurrent_html = (
                    "<h4>🚨 停頓期間其他 Thread 發生的異常 "
                    f"（共 {event.concurrent_error_count} 筆，最多顯示 "
                    f"{MAX_CONCURRENT_ERRORS_PER_GAP} 筆）：</h4>"
                )
                concurrent_html += "".join(
                    f"<div class='context-box'><b>[{error.timestamp}] "
                    f"{html.escape(error.thread_name)}</b>: "
                    f"{html.escape(error.exc_type)} at "
                    f"{html.escape(error.location)}</div>"
                    for error in event.concurrent_errors
                )

            output.write(f"""
        <div class="card">
            <h3><span class="badge {badge_class}">{event.judgment}</span> Thread: {html.escape(event.thread_name)} ({event.gap_seconds:.2f} 秒)</h3>
            <p><b>時間區間：</b> {event.previous.timestamp} ➔ {event.current.timestamp}</p>
            <p><b>前一筆 Log：</b> <code>{html.escape(short_text(event.previous.message))}</code></p>
            <p><b>後一筆 Log：</b> <code>{html.escape(short_text(event.current.message))}</code></p>
            {concurrent_html}
        </div>
        """
            )

        output.write("""
</body>
</html>
"""
        )


def export_csv(events: List[GapEvent], csv_path: Path):
    sorted_events = sorted(events, key=lambda e: e.gap_seconds, reverse=True)
    
    with csv_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Thread", "Gap(Seconds)", "Judgment", "Exception Type",
            "Start Time", "End Time", "Start Line", "End Line",
            "Previous Log", "Next Log"
        ])
        
        for e in sorted_events:
            writer.writerow([
                csv_cell(e.thread_name),
                csv_cell(f"{e.gap_seconds:.3f}"),
                csv_cell(e.judgment),
                csv_cell(e.exc_type or ""),
                csv_cell(e.previous.timestamp),
                csv_cell(e.current.timestamp),
                csv_cell(e.previous.line_number),
                csv_cell(e.current.line_number),
                csv_cell(short_text(e.previous.message, 200)),
                csv_cell(short_text(e.current.message, 200)),
            ])


def csv_cell(value: object) -> str:
    """避免 Excel 將來自 Log 的資料當成可執行公式。"""
    text = str(value)
    return f"'{text}" if text[:1] in ("=", "+", "-", "@") else text


def load_config(config_path: Path) -> dict:
    if not config_path.exists():
        return {}
    try:
        with config_path.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"無法讀取設定檔 {config_path}: {exc}") from exc


def ensure_distinct_output_paths(log_file: Path, *output_paths: Optional[Path]) -> None:
    """避免報表輸出覆寫原始 Log，或彼此互相覆寫。"""
    resolved_input = log_file.resolve()
    resolved_outputs = []
    for output_path in output_paths:
        if output_path is None:
            continue
        resolved = output_path.resolve()
        if resolved == resolved_input:
            raise ValueError(f"輸出路徑不可與輸入 Log 檔相同：{output_path}")
        if resolved in resolved_outputs:
            raise ValueError(f"HTML 與 CSV 輸出路徑不可相同：{output_path}")
        resolved_outputs.append(resolved)

def main():
    parser = argparse.ArgumentParser(description="Thread Gap Analyzer (維運強化版 - YAML 配置)")
    parser.add_argument("log_file", type=str, nargs="?", help="欲分析的 Log 檔案路徑 (會覆寫 YAML 設定)")
    parser.add_argument("-c", "--config", type=str, default="config.yaml", help="YAML 設定檔路徑 (預設: config.yaml)")
    
    # 支援 CLI 覆寫 YAML
    parser.add_argument("-t", "--threshold", type=int, help="覆寫 YAML 的 threshold_seconds")
    parser.add_argument("-i", "--ignore-threads", type=str, help="覆寫 YAML 的 ignore_threads")
    parser.add_argument("--html", type=str, help="覆寫 YAML 的 html_report 路徑")
    parser.add_argument("--csv", type=str, help="覆寫 YAML 的 csv_report 路徑")
    parser.add_argument("-q", "--quiet", action="store_true", help="開啟 quiet 模式 (覆寫 YAML)")
    
    args = parser.parse_args()
    config_path = Path(args.config)
    
    try:
        config = load_config(config_path)
    except ValueError as exc:
        parser.error(str(exc))
    if not isinstance(config, dict):
        parser.error("設定檔根節點必須是 YAML mapping")
    
    log_file_str = args.log_file or config.get("log_file")
    if not log_file_str:
        print("錯誤：未指定 log_file。請在 config.yaml 或指令列中提供日誌檔案路徑。")
        sys.exit(1)
        
    log_file = Path(log_file_str)
    if not log_file.exists():
        print(f"找不到檔案：{log_file}")
        sys.exit(1)

    try:
        threshold = args.threshold if args.threshold is not None else int(config.get("threshold_seconds", 30))
    except (TypeError, ValueError):
        parser.error("threshold_seconds 必須是正整數")
    if threshold <= 0:
        parser.error("threshold_seconds 必須大於 0")

    ignore_threads = args.ignore_threads if args.ignore_threads is not None else str(config.get("ignore_threads", "") or "")
    try:
        re.compile(ignore_threads) if ignore_threads else None
    except re.error as exc:
        parser.error(f"ignore_threads 正規表達式無效：{exc}")

    output_cfg = config.get("output", {})
    if not isinstance(output_cfg, dict):
        parser.error("output 必須是 YAML mapping")
    quiet = args.quiet if args.quiet else bool(output_cfg.get("quiet", False))
    html_out = args.html if args.html is not None else str(output_cfg.get("html_report", "") or "")
    csv_out = args.csv if args.csv is not None else str(output_cfg.get("csv_report", "") or "")

    html_path = Path(html_out) if html_out else None
    csv_path = Path(csv_out) if csv_out else None
    try:
        ensure_distinct_output_paths(log_file, html_path, csv_path)
    except ValueError as exc:
        parser.error(str(exc))

    print(f"開始分析: {log_file} (門檻 >= {threshold}s) ...")
    events, global_exceptions = analyze_log(log_file, threshold, ignore_threads)

    if not quiet:
        for e in events:
            print("=" * 80)
            print(f"Thread: {e.thread_name} | Gap: {e.gap_seconds:.2f}s | {e.judgment}")
            if e.exc_type:
                print(f"Exception: {e.exc_type}")
            print(f"Previous: {short_text(e.previous.message, 100)}")
            print(f"Current : {short_text(e.current.message, 100)}")
            if e.concurrent_error_count:
                print(f"** 停頓期間有 {e.concurrent_error_count} 筆全域異常發生 "
                      f"（最多顯示 {MAX_CONCURRENT_ERRORS_PER_GAP} 筆）**")
            print()

    print_summary(events, global_exceptions, threshold)

    if html_path:
        export_html(events, global_exceptions, html_path)
        print(f"✅ 已成功匯出 HTML 報告：{html_path}")
        
    if csv_path:
        export_csv(events, csv_path)
        print(f"✅ 已成功匯出 CSV 報告：{csv_path}")

if __name__ == "__main__":
    main()
