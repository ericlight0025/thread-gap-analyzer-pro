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
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set

import yaml

TIME_FORMATS = (
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
)

LOG_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?)[^\[]*\[([^\]]+)\]\s*(.*)$"
)

MAX_CONTINUATION_LINES = 100

@dataclass
class LogRecord:
    timestamp: datetime
    thread_name: str
    message: str
    line_number: int
    raw_line: str
    continuation_lines: List[str] = field(default_factory=list)

@dataclass
class ExceptionRecord:
    """輕量級的異常紀錄，避免將完整 LogRecord 存在全域清單吃光記憶體"""
    timestamp: datetime
    thread_name: str
    exc_type: str
    location: str
    line_number: int

@dataclass
class GapEvent:
    thread_name: str
    previous: LogRecord
    current: LogRecord
    gap_seconds: float
    judgment: str
    concurrent_errors: List[ExceptionRecord] = field(default_factory=list)
    exc_type: Optional[str] = None
    exc_location: Optional[str] = None

def parse_timestamp(ts_str: str) -> Optional[datetime]:
    clean_ts = ts_str.replace(",", ".").replace("T", " ")
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
        message=match.group(3),
        line_number=line_number,
        raw_line=line.rstrip()
    )

def is_sql(record: LogRecord) -> bool:
    texts = [record.message] + record.continuation_lines[:5]
    upper_combined = " ".join(texts).upper()
    
    if re.search(r"^(GET|POST|PUT|DELETE|PATCH)\s+/", upper_combined.strip()):
        return False

    keywords = ("SELECT ", "INSERT ", "UPDATE ", "DELETE ", "MERGE ", "WITH ")
    return any(keyword in upper_combined for keyword in keywords)

def is_exception(message: str) -> bool:
    upper = message.upper()
    keywords = ("EXCEPTION", "ERROR", "SQLERROR", "SQLEXCEPTION", "SQLTIMEOUTEXCEPTION", "ORA-", "TIMEOUT")
    return any(keyword in upper for keyword in keywords)

def extract_exception_info(record: LogRecord) -> Tuple[Optional[str], Optional[str]]:
    """回傳 (ExceptionType, Location)，優化避開 Framework 層"""
    if not is_exception(record.message):
        return None, None
        
    exc_type = None
    location = None
    
    search_texts = [record.message] + record.continuation_lines
    for text in search_texts:
        if not exc_type:
            # 尋找典型的 Exception 類別名稱，或是 ORA- 開頭的錯誤
            match = re.search(r"([a-zA-Z0-9_.]+(?:Exception|Error))\b", text, re.IGNORECASE)
            ora_match = re.search(r"(ORA-\d{5})", text)
            if match:
                exc_type = match.group(1)
            elif ora_match:
                exc_type = ora_match.group(1)
                
        # 尋找 StackTrace 中的業務邏輯位置，跳過常見 Framework
        if not location:
            loc_match = re.search(r"at\s+([a-zA-Z0-9_.$]+)\(([^:]+:\d+)\)", text)
            if loc_match:
                full_class = loc_match.group(1)
                loc_file_line = loc_match.group(2)
                # 若為框架底層，先暫存，但繼續尋找真正的業務邏輯
                skip_prefixes = ("java.", "javax.", "org.apache.", "org.springframework.", "oracle.jdbc.", "com.sun.")
                if not any(full_class.startswith(p) for p in skip_prefixes):
                    location = loc_file_line
                elif location is None:
                    location = loc_file_line # Fallback to first found even if framework
                    
    return exc_type, location

def get_judgment(previous: LogRecord, current: LogRecord, current_exc_type: Optional[str]) -> str:
    previous_is_sql = is_sql(previous)
    current_is_exception = bool(current_exc_type)

    if previous_is_sql and current_is_exception:
        return "SQL 執行過久後發生 Exception"
    elif previous_is_sql:
        return "疑似慢 SQL"
    elif current_is_exception:
        return "長時間停頓後發生 Exception"
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
                # 結算上一筆紀錄 (如果在結算時發現它是 Exception，則存入輕量級表)
                if current_record is not None:
                    exc_type, loc = extract_exception_info(current_record)
                    if exc_type:
                        global_exceptions.append(ExceptionRecord(
                            timestamp=current_record.timestamp,
                            thread_name=current_record.thread_name,
                            exc_type=exc_type,
                            location=loc or "Unknown",
                            line_number=current_record.line_number
                        ))
                
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
                    if len(current_record.continuation_lines) < MAX_CONTINUATION_LINES:
                        stripped = line.rstrip()
                        if stripped:
                            current_record.continuation_lines.append(stripped)

        # 處理檔案最後一筆紀錄
        if current_record is not None:
            exc_type, loc = extract_exception_info(current_record)
            if exc_type:
                global_exceptions.append(ExceptionRecord(
                    timestamp=current_record.timestamp,
                    thread_name=current_record.thread_name,
                    exc_type=exc_type,
                    location=loc or "Unknown",
                    line_number=current_record.line_number
                ))

    # 第二階段：關聯 Concurrent Errors 並補完 judgment (避免 O(G*E) 效能問題)
    # global_exceptions 本身已依照檔案順序 (時間順序) 排序，可使用 bisect 二元搜尋
    exc_timestamps = [e.timestamp for e in global_exceptions]

    for event in gap_events:
        # 計算 Exception Info
        exc_type, exc_loc = extract_exception_info(event.current)
        event.exc_type = exc_type
        event.exc_location = exc_loc
        event.judgment = get_judgment(event.previous, event.current, exc_type)

        t_start = event.previous.timestamp
        t_end = event.current.timestamp
        
        # 二元搜尋找尋時間區間內的 exceptions
        idx_start = bisect_left(exc_timestamps, t_start)
        idx_end = bisect_right(exc_timestamps, t_end)
        
        for i in range(idx_start, idx_end):
            exc_rec = global_exceptions[i]
            if exc_rec.thread_name != event.thread_name:
                event.concurrent_errors.append(exc_rec)

    return gap_events, global_exceptions


def short_text(text: str, max_length: int = 500) -> str:
    text = text.strip()
    if len(text) <= max_length:
        return text
    return text[:max_length] + " ..."


def group_exceptions(global_exceptions: List[ExceptionRecord]) -> List[Tuple[str, List[str]]]:
    exc_grouping = {}
    for exc in global_exceptions:
        if exc.exc_type not in exc_grouping:
            exc_grouping[exc.exc_type] = set()
        exc_grouping[exc.exc_type].add(exc.thread_name)
    
    # 轉為排序好的 list，回傳 (exc_type, [thread1, thread2...])
    return sorted([(k, list(v)) for k, v in exc_grouping.items()], key=lambda x: len(x[1]), reverse=True)


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


def export_html(events: List[GapEvent], global_exceptions: List[ExceptionRecord], html_path: Path):
    html_content = f"""<!DOCTYPE html>
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
    if global_exceptions:
        html_content += "<h2>📉 異常時間熱區圖 (Error Heatmap)</h2>\n"
        heatmap = generate_error_heatmap(global_exceptions)
        max_count = max(heatmap.values())
        for time_key, count in heatmap.items():
            pct = int((count / max_count) * 100) if max_count > 0 else 0
            # 確保數字顯示空間
            width_pct = max(pct, 8) 
            html_content += f"""
            <div class="heatmap-row">
                <div class="heatmap-time">{html.escape(time_key)}</div>
                <div class="heatmap-bar-container">
                    <div class="heatmap-bar" style="width: {width_pct}%;">{count}</div>
                </div>
            </div>
            """

        html_content += "<h2>🔍 Exception 影響範圍 (Grouped by Type)</h2>\n"
        grouped = group_exceptions(global_exceptions)
            
        for exc_type, threads in grouped:
            display_threads = ", ".join(f"<code>{html.escape(t)}</code>" for t in threads[:10])
            if len(threads) > 10:
                display_threads += f" ... 等共 {len(threads)} 個 Thread"
            
            html_content += f"""
            <div class="card" style="border-left-color: #f44336;">
                <h3><span class="badge bg-red">{len(threads)} 影響</span> {html.escape(exc_type)}</h3>
                <p><b>牽連的 Thread：</b> {display_threads}</p>
            </div>
            """

    html_content += """
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
    for exc in global_exceptions:
        html_content += f"""
        <tr>
            <td><code>{html.escape(exc.thread_name)}</code></td>
            <td>{exc.line_number}</td>
            <td>{exc.timestamp}</td>
            <td style="color: #f48771;">{html.escape(exc.exc_type)}</td>
            <td><code>{html.escape(exc.location)}</code></td>
        </tr>"""

    html_content += """
    </table>

    <h2>⏱️ Top 停頓事件 (Gap Events)</h2>
"""
    sorted_events = sorted(events, key=lambda e: e.gap_seconds, reverse=True)
    for e in sorted_events:
        badge_class = "bg-red" if e.exc_type else "bg-orange"
        
        concurrent_html = ""
        if e.concurrent_errors:
            concurrent_html = "<h4>🚨 停頓期間其他 Thread 發生的異常 (全域關聯)：</h4>"
            for ce in e.concurrent_errors:
                concurrent_html += f"<div class='context-box'><b>[{ce.timestamp}] {html.escape(ce.thread_name)}</b>: {html.escape(ce.exc_type)} at {html.escape(ce.location)}</div>"

        html_content += f"""
        <div class="card">
            <h3><span class="badge {badge_class}">{e.judgment}</span> Thread: {html.escape(e.thread_name)} ({e.gap_seconds:.2f} 秒)</h3>
            <p><b>時間區間：</b> {e.previous.timestamp} ➔ {e.current.timestamp}</p>
            <p><b>前一筆 Log：</b> <code>{html.escape(short_text(e.previous.message))}</code></p>
            <p><b>後一筆 Log：</b> <code>{html.escape(short_text(e.current.message))}</code></p>
            {concurrent_html}
        </div>
        """

    html_content += """
</body>
</html>
"""
    html_path.write_text(html_content, encoding="utf-8")


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
                e.thread_name,
                f"{e.gap_seconds:.3f}",
                e.judgment,
                e.exc_type or "",
                e.previous.timestamp,
                e.current.timestamp,
                e.previous.line_number,
                e.current.line_number,
                short_text(e.previous.message, 200),
                short_text(e.current.message, 200)
            ])


def load_config(config_path: Path) -> dict:
    if not config_path.exists():
        return {}
    with config_path.open("r", encoding="utf-8") as f:
        try:
            return yaml.safe_load(f) or {}
        except Exception:
            return {}

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
    
    config = load_config(config_path)
    
    log_file_str = args.log_file or config.get("log_file")
    if not log_file_str:
        print("錯誤：未指定 log_file。請在 config.yaml 或指令列中提供日誌檔案路徑。")
        sys.exit(1)
        
    log_file = Path(log_file_str)
    if not log_file.exists():
        print(f"找不到檔案：{log_file}")
        sys.exit(1)

    threshold = args.threshold if args.threshold is not None else int(config.get("threshold_seconds", 30))
    ignore_threads = args.ignore_threads if args.ignore_threads is not None else str(config.get("ignore_threads", "") or "")
    
    output_cfg = config.get("output", {})
    quiet = args.quiet if args.quiet else bool(output_cfg.get("quiet", False))
    html_out = args.html if args.html is not None else str(output_cfg.get("html_report", "") or "")
    csv_out = args.csv if args.csv is not None else str(output_cfg.get("csv_report", "") or "")

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
            if e.concurrent_errors:
                print(f"** 停頓期間有 {len(e.concurrent_errors)} 筆全域異常發生 **")
            print()

    print_summary(events, global_exceptions, threshold)

    if html_out:
        html_path = Path(html_out)
        export_html(events, global_exceptions, html_path)
        print(f"✅ 已成功匯出 HTML 報告：{html_path}")
        
    if csv_out:
        csv_path = Path(csv_out)
        export_csv(events, csv_path)
        print(f"✅ 已成功匯出 CSV 報告：{csv_path}")

if __name__ == "__main__":
    main()
