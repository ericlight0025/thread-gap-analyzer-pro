# Thread Gap Analyzer Pro (高階維運執行時間差分析器)

## 📌 專案簡介
這是一套專為企業級維運與 DBA 設計的日誌分析工具。針對含有時間戳記 (Timestamp) 與執行緒 (Thread) 識別碼的 Application Log，進行**依 Thread 隔離的精準時間差 (Gap) 計算與異常關聯分析**。

當產線發生「SQL 執行 6 分鐘後 Timeout」或「長時間停頓後拋出 Exception」等詭異現象時，本工具能瞬間在百萬行日誌中撈出最致命的停頓點，並以終端機圖表或單檔 HTML 互動儀表板呈現。

---

## ✨ 核心特色與優化亮點

1. **🚀 Streaming 記憶體控制 (High Performance)**
   - 採用「邊讀邊計算」的串流架構。處理 300 萬行巨量 Log (約數百 MB 到近 1GB) 僅需 **22 秒**，記憶體佔用極低，徹底杜絕 OutOfMemory。
2. **🔎 跨行 SQL 精準捕捉 (Multiline SQL Support)**
   - 當 SQL 為了排版被拆成多行印出時，分析器會連帶檢查後續無時間戳記的 Log 區塊，確保 `SELECT/UPDATE` 等關鍵字百分百被抓出。
   - 自動過濾 `DELETE /api/v1/...` 等 HTTP 請求日誌，避免 False Positive。
3. **💥 統一系統異常一覽表 (Unified Exceptions Summary)**
   - 透過正則表達式，自動從 Stack Trace 抽取出 **Exception 型別** 與 **程式碼出錯位置** (如 `PolicyService.java:45`)。
   - 把所有不同 Thread 發生的異常統一彙整為一張表，抓蟲時一目了然。
4. **🌐 全域前後文關聯 (Global Context Capture)**
   - 捕捉每個 Thread 卡住的期間，**整個系統是否同時爆發其他錯誤**。
   - 協助您快速釐清是「單一 Request 卡死」還是「資料庫崩潰引發的全域災難」。
5. **🔕 支援背景雜訊過濾 (Ignore Idle Threads)**
   - 支援傳入正規表達式，過濾掉固定頻率在睡覺的排程器 (如 `health-check`, `scheduler`)，減少報表雜訊。
   - **防呆設計**：若被忽略的 Thread 噴出 Exception，依然會被攔截進統一異常表。
6. **📊 精美單檔 HTML 互動儀表板與熱區圖**
   - 支援將結果產出為 `.html` 檔案。
   - 內建**異常時間熱區圖 (Error Heatmap)**，可精準看出異常發生的時間集中點。
   - 零依賴，無需外部 CSS/JS 即可在離線內網環境開啟。

---

## 🛠️ 安裝與相依性 (Dependencies)

本專案核心邏輯皆使用 Python 內建模組實作，以確保最高相容性與執行效能。
- **核心語言**：`Python 3.8+` (相依內建套件：`re`, `argparse`, `csv`, `dataclasses`, `datetime`, `pathlib`, `collections`)
- **外部依賴**：唯一需要安裝的外部套件為解析設定檔用的 `PyYAML`。

```bash
# 建議安裝 PyYAML 6.0 以上版本
pip install -r requirements.txt
```

---

## ⚙️ YAML 設定檔說明 (`config.yaml`)

本專案使用 `config.yaml` 作為主要設定中心，免去輸入冗長指令的麻煩。以下是各欄位的詳細說明：

| 欄位名稱 | 型別 | 預設值 / 範例 | 欄位說明 |
| :--- | :--- | :--- | :--- |
| `log_file` | String | `"samples/demo_performance.log"` | 預設要分析的日誌檔案路徑。若您在命令列直接輸入檔案名稱，則會覆寫此設定。 |
| `threshold_seconds` | Integer | `30` | 判定為「異常停頓」的時間門檻。前後 Log 時間差大於此秒數才會被捕捉。 |
| `ignore_threads` | String | `"batch.*\|ping"` | **[可選]** 欲過濾的背景 Thread 正則表達式。留空代表不過濾。符合條件的 Thread 即使閒置超時也不會列入 Top Gap，但若拋出 Exception 仍會被收錄進全域異常表。 |
| `output.quiet` | Boolean | `true` | 若設為 `true`，終端機將只印出「分析摘要」與「異常彙整表」，隱藏各筆 Thread 停頓的明細，讓畫面更乾淨。 |
| `output.html_report`| String | `"report.html"` | **[可選]** 輸出的精美單檔 HTML 互動儀表板路徑。留空字串 `""` 則不產出。 |
| `output.csv_report` | String | `"report.csv"` | **[可選]** 將 Top Gap 細節匯出為 CSV 的路徑。適合交給 DBA 用 Excel 排序分析。留空字串 `""` 則不產出。 |

---

## 🚀 執行分析

**方法 A：直接執行 (完全吃 config.yaml 的設定)**
```bash
python thread_gap_analyzer.py
```

**方法 B：只替換要分析的 Log 檔案 (常用於臨時查修)**
```bash
python thread_gap_analyzer.py application-error.log
```

**方法 C：指定另一個不同環境的設定檔**
```bash
python thread_gap_analyzer.py -c prod_config.yaml
```

---

## 📂 專案結構
- `thread_gap_analyzer.py`: 核心分析器程式碼。
- `config.yaml`: 預設的 YAML 設定檔。
- `requirements.txt`: Python 依賴套件清單 (`PyYAML>=6.0`)。
- `generate_large_log.py`: 效能壓測工具 (可模擬 10 萬至百萬筆真實 Log 與 Stack Trace)。
- `samples/`: 存放極端情境日誌 `sample_thread_gap.log` 與 效能展示日誌 `demo_performance.log`。
- `samples/demo_performance_report.html`: 範例產出的 HTML 儀表板，可直接點擊預覽。
- `tests/`: 完整的 `unittest` 單元測試與整合測試套件。

---
*專案建置時間：2026-10-06 | 驅動模型：Gemini 3.1 Pro*
