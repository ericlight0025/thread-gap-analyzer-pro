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

## 🛠️ 安裝與使用方式

環境需求：`Python 3.8+` (僅使用內建模組，無須 pip install)

### 基本用法 (終端機輸出)
```bash
python thread_gap_analyzer.py application.log 30
```
*(30 代表停頓 >= 30 秒即列為異常)*

### 匯出精美 HTML 報告與 CSV
```bash
python thread_gap_analyzer.py application.log -t 30 --html report.html --csv output.csv
```

### 過濾背景排程器 (減少雜訊)
```bash
python thread_gap_analyzer.py application.log -i "batch-worker.*|health-check"
```

---

## 📂 專案結構
- `thread_gap_analyzer.py`: 核心分析器程式碼。
- `generate_large_log.py`: 效能壓測工具 (可模擬 10 萬至百萬筆真實 Log 與 Stack Trace)。
- `samples/`: 存放各種極端與真實情境的 Log 測試檔。
- `tests/`: 完整的 `unittest` 單元測試與整合測試。

---
*專案建置時間：2026-10-06 | 驅動模型：Gemini 3.1 Pro*
