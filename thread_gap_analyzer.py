#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Thread Gap Analyzer (高階維運強化版)

包含以下優化：
1. 支援「跨行 SQL (Multiline SQL)」精準判斷。
2. 支援排除「背景閒置 Thread」(--ignore-threads)。
3. 全域前後文 (Global Context)：自動捕捉 Gap 期間其他 Thread 發生的例外。
4. Exception 彙整表：精準抓取 Exception 類型與發生位置 (Source Code Location)。
5. 支援輸出美觀的單檔 HTML 互動報告 (--html)。
"""

import argparse
import csv
import html
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


TIME_FORMATS = (
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
)

LOG_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?)[^\[]*\[([^\]]+)\]\s*(.*)$"
)


@dataclass
class LogRecord:
    timestamp: datetime
    thread_name: str
    message: str
    line_number: int
    raw_line: str
    continuation_lines: List[str] = field(default_factory=list)


@dataclass
class GapEvent:
    thread_name: str
    previous: LogRecord
    current: LogRecord
    gap_seconds: float
    judgment: str
    concurrent_errors: List[LogRecord] = field(default_factory=list)

    @property
    def exception_info(self) -> Tuple[Optional[str], Optional[str]]:
        """回傳 (Exception類別, 發生位置檔案與行號)"""
        return extract_exception_info(self.current)


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
    """判斷是否為 SQL（支援跨行判斷）"""
    texts = [record.message] + record.continuation_lines[:5]
    upper_combined = " ".join(texts).upper()
    
    # 排除常見 HTTP 存取日誌
    if re.search(r"^(GET|POST|PUT|DELETE|PATCH)\s+/", upper_combined.strip()):
        return False

    keywords = ("SELECT ", "INSERT ", "UPDATE ", "DELETE ", "MERGE ", "WITH ")
    return any(keyword in upper_combined for keyword in keywords)


def is_exception(message: str) -> bool:
    upper = message.upper()
    keywords = (
        "EXCEPTION", "ERROR", "SQLERROR", "SQLEXCEPTION", 
        "SQLTIMEOUTEXCEPTION", "ORA-", "TIMEOUT"
    )
    return any(keyword in upper for keyword in keywords)


def extract_exception_info(record: LogRecord) -> Tuple[Optional[str], Optional[str]]:
    """回傳 (ExceptionType, Location)"""
    exc_type = None
    location = None
    
    if not is_exception(record.message):
        return None, None
        
    search_texts = [record.message] + record.continuation_lines
    for text in search_texts:
        if not exc_type:
            match = re.search(r"([a-zA-Z0-9_.]+(?:Exception|Error))\b", text, re.IGNORECASE)
            if match:
                exc_type = match.group(1)
                
        if not location:
            # 匹配類似: at com.pkg.Class.method(File.java:123)
            loc_match = re.search(r"at\s+.*?\(([^:]+:\d+)\)", text)
            if loc_match:
                location = loc_match.group(1)
                
        if exc_type and location:
            break
            
    return exc_type or "UnknownException", location


def short_text(text: str, max_length: int = 500) -> str:
    text = text.strip()
    if len(text) <= max_length:
        return text
    return text[:max_length] + " ..."


def get_judgment(previous: LogRecord, current: LogRecord) -> str:
    previous_is_sql = is_sql(previous)
    current_is_exception = is_exception(current.message)

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
) -> Tuple[List[GapEvent], List[LogRecord]]:
    
    gap_events: List[GapEvent] = []
    last_record_by_thread: Dict[str, LogRecord] = {}
    current_record: Optional[LogRecord] = None
    global_exceptions: List[LogRecord] = []
    
    ignore_re = re.compile(ignore_threads_pattern) if ignore_threads_pattern else None

    with log_file.open("r", encoding="utf-8", errors="replace") as file:
        for line_number, line in enumerate(file, start=1):
            record = parse_log_line(line, line_number)

            if record is not None:
                thread = record.thread_name
                
                # 如果該 Log 是 Exception，加入全域異常清單
                if is_exception(record.message):
                    global_exceptions.append(record)

                if ignore_re and ignore_re.match(thread):
                    current_record = record
                    continue
                    
                previous = last_record_by_thread.get(thread)
                if previous is not None:
                    gap = (record.timestamp - previous.timestamp).total_seconds()
                    if gap >= threshold_seconds:
                        judgment = get_judgment(previous, record)
                        event = GapEvent(
                            thread_name=thread,
                            previous=previous,
                            current=record,
                            gap_seconds=gap,
                            judgment=judgment
                        )
                        gap_events.append(event)

                last_record_by_thread[thread] = record
                current_record = record
            else:
                if current_record is not None:
                    stripped = line.rstrip()
                    if stripped:
                        current_record.continuation_lines.append(stripped)

    # 捕捉 Concurrent Errors (全域前後文)
    for event in gap_events:
        t_start = event.previous.timestamp
        t_end = event.current.timestamp
        for exc_rec in global_exceptions:
            # 排除自己 Thread 的 Exception
            if exc_rec.thread_name == event.thread_name:
                continue
            if t_start <= exc_rec.timestamp <= t_end:
                event.concurrent_errors.append(exc_rec)

    return gap_events, global_exceptions


def generate_error_heatmap(global_exceptions: List[LogRecord]) -> Dict[str, int]:
    """將異常依「分鐘」分組，產生熱區統計"""
    heatmap = {}
    for exc in global_exceptions:
        minute_key = exc.timestamp.strftime("%Y-%m-%d %H:%M")
        heatmap[minute_key] = heatmap.get(minute_key, 0) + 1
    # 依時間先後排序
    return dict(sorted(heatmap.items()))

def print_summary(events: List[GapEvent], global_exceptions: List[LogRecord], threshold: int):
    print("=" * 100)
    print("【分析摘要】")
    print(f"總共發現 {len(events)} 筆 Thread Gap (>= {threshold} 秒)")
    print()

    # Top Gaps
    if events:
        sorted_events = sorted(events, key=lambda e: e.gap_seconds, reverse=True)
        print("🏆 Top 10 最耗時停頓：")
        for i, e in enumerate(sorted_events[:10], start=1):
            print(f"  {i}. [{e.gap_seconds:7.2f}s] {e.thread_name} - {e.judgment}")
        print()

    # 異常時間熱區圖
    if global_exceptions:
        heatmap = generate_error_heatmap(global_exceptions)
        print("📉 異常時間熱區圖 (Error Heatmap - per minute)：")
        max_count = max(heatmap.values())
        for time_key, count in heatmap.items():
            # 依比例印出長條圖，最長 40 個方塊
            bar_len = int((count / max_count) * 40) if max_count > 0 else 0
            bar = "█" * bar_len
            print(f"  {time_key} : {count:3} 筆 | {bar}")
        print()

    # 統一彙整 Exception 位置與 Thread
    if global_exceptions:
        # 新增：反向追蹤 (依 Exception 類型分群)
        print("💥 Exception 反向追蹤與影響範圍 (Exceptions Grouped by Type)：")
        exc_grouping = {}
        for exc in global_exceptions:
            exc_type, _ = extract_exception_info(exc)
            exc_type = exc_type or "UnknownError"
            if exc_type not in exc_grouping:
                exc_grouping[exc_type] = set()
            exc_grouping[exc_type].add(exc.thread_name)
            
        for exc_type, threads in sorted(exc_grouping.items(), key=lambda x: len(x[1]), reverse=True):
            thread_list = list(threads)
            display_threads = ", ".join(thread_list[:5])
            if len(thread_list) > 5:
                display_threads += f" ... (等共 {len(thread_list)} 個 Thread)"
            print(f"  [{len(thread_list):>3} 影響] {exc_type:<35}")
            print(f"           👉 Threads: {display_threads}")
        print()

        print("📋 詳細異常清單 (Detailed Exceptions Summary)：")
        print(f"{'Thread ID':<25} | {'Line':<8} | {'Exception Type':<35} | Location")
        print("-" * 100)
        
        for exc in global_exceptions:
            exc_type, loc = extract_exception_info(exc)
            exc_type = short_text(exc_type or "UnknownError", 33)
            loc = loc or "N/A"
            print(f"{exc.thread_name:<25} | {exc.line_number:<8} | {exc_type:<35} | {loc}")
        print()


def export_html(events: List[GapEvent], global_exceptions: List[LogRecord], html_path: Path):
    """產生精美單檔 HTML 報表"""
    
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
                <div class="heatmap-time">{time_key}</div>
                <div class="heatmap-bar-container">
                    <div class="heatmap-bar" style="width: {width_pct}%;">{count}</div>
                </div>
            </div>
            """

        # HTML: Exception 反向追蹤
        html_content += "<h2>🔍 Exception 影響範圍 (Grouped by Type)</h2>\n"
        exc_grouping = {}
        for exc in global_exceptions:
            exc_type, _ = extract_exception_info(exc)
            exc_type = exc_type or "UnknownError"
            if exc_type not in exc_grouping:
                exc_grouping[exc_type] = set()
            exc_grouping[exc_type].add(exc.thread_name)
            
        for exc_type, threads in sorted(exc_grouping.items(), key=lambda x: len(x[1]), reverse=True):
            thread_list = list(threads)
            display_threads = ", ".join(f"<code>{html.escape(t)}</code>" for t in thread_list[:10])
            if len(thread_list) > 10:
                display_threads += f" ... 等共 {len(thread_list)} 個 Thread"
            
            html_content += f"""
            <div class="card" style="border-left-color: #f44336;">
                <h3><span class="badge bg-red">{len(thread_list)} 影響</span> {html.escape(exc_type)}</h3>
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
        exc_type, loc = extract_exception_info(exc)
        html_content += f"""
        <tr>
            <td><code>{html.escape(exc.thread_name)}</code></td>
            <td>{exc.line_number}</td>
            <td>{exc.timestamp}</td>
            <td style="color: #f48771;">{html.escape(exc_type or 'Unknown')}</td>
            <td><code>{html.escape(loc or 'N/A')}</code></td>
        </tr>"""

    html_content += """
    </table>

    <h2>⏱️ Top 停頓事件 (Gap Events)</h2>
"""
    sorted_events = sorted(events, key=lambda e: e.gap_seconds, reverse=True)
    for e in sorted_events:
        exc_type, _ = e.exception_info
        badge_class = "bg-red" if exc_type else "bg-orange"
        
        concurrent_html = ""
        if e.concurrent_errors:
            concurrent_html = "<h4>🚨 停頓期間其他 Thread 發生的異常 (全域關聯)：</h4>"
            for ce in e.concurrent_errors:
                c_exc, c_loc = extract_exception_info(ce)
                concurrent_html += f"<div class='context-box'><b>[{ce.timestamp}] {ce.thread_name}</b>: {c_exc} at {c_loc}</div>"

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
    """將分析結果匯出為 CSV"""
    sorted_events = sorted(events, key=lambda e: e.gap_seconds, reverse=True)
    
    with csv_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Thread", "Gap(Seconds)", "Judgment", "Exception Type",
            "Start Time", "End Time", "Start Line", "End Line",
            "Previous Log", "Next Log"
        ])
        
        for e in sorted_events:
            exc_type, _ = e.exception_info
            writer.writerow([
                e.thread_name,
                f"{e.gap_seconds:.3f}",
                e.judgment,
                exc_type or "",
                e.previous.timestamp,
                e.current.timestamp,
                e.previous.line_number,
                e.current.line_number,
                short_text(e.previous.message, 200),
                short_text(e.current.message, 200)
            ])


import yaml

def load_config(config_path: Path) -> dict:
    if not config_path.exists():
        print(f"找不到設定檔：{config_path}，將使用預設設定。")
        return {}
    with config_path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def main():
    parser = argparse.ArgumentParser(description="Thread Gap Analyzer (維運強化版 - YAML 配置)")
    parser.add_argument("log_file", type=str, nargs="?", help="欲分析的 Log 檔案路徑 (會覆寫 YAML 設定)")
    parser.add_argument("-c", "--config", type=str, default="config.yaml", help="YAML 設定檔路徑 (預設: config.yaml)")
    
    args = parser.parse_args()
    config_path = Path(args.config)
    
    # 讀取 YAML 設定
    config = load_config(config_path)
    
    # 參數優先序：CLI argument > YAML config > 預設值
    log_file_str = args.log_file or config.get("log_file")
    if not log_file_str:
        print("錯誤：未指定 log_file。請在 config.yaml 或指令列中提供日誌檔案路徑。")
        sys.exit(1)
        
    log_file = Path(log_file_str)
    if not log_file.exists():
        print(f"找不到檔案：{log_file}")
        sys.exit(1)

    threshold = config.get("threshold_seconds", 30)
    ignore_threads = config.get("ignore_threads", "")
    output_cfg = config.get("output", {})
    quiet = output_cfg.get("quiet", False)
    html_out = output_cfg.get("html_report", "")
    csv_out = output_cfg.get("csv_report", "")

    print(f"開始分析: {log_file} (設定檔: {args.config}, 門檻 >= {threshold}s) ...")
    events, global_exceptions = analyze_log(log_file, threshold, ignore_threads)

    if not quiet:
        for e in events:
            exc_type, _ = e.exception_info
            print("=" * 80)
            print(f"Thread: {e.thread_name} | Gap: {e.gap_seconds:.2f}s | {e.judgment}")
            if exc_type:
                print(f"Exception: {exc_type}")
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
