import random
from datetime import datetime, timedelta

def generate_log(filename: str, num_lines: int = 100000):
    start_time = datetime(2026, 10, 6, 10, 0, 0)
    threads = [f"http-nio-8080-exec-{i}" for i in range(1, 101)] + [f"batch-worker-{i}" for i in range(1, 21)]
    
    with open(filename, "w", encoding="utf-8") as f:
        current_time = start_time
        
        for i in range(num_lines):
            thread = random.choice(threads)
            
            # 隨機產生時間推進 (1~50毫秒)
            current_time += timedelta(milliseconds=random.randint(1, 50))
            
            # 偶爾產生 40 秒的大 Gap
            if i % 5000 == 0:
                current_time += timedelta(seconds=40)
            
            ts_str = current_time.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            
            # 產生 Log 內容
            msg_type = random.randint(1, 100)
            if msg_type <= 10:
                msg = f"SELECT * FROM USER_TABLE WHERE ID = {random.randint(1, 10000)}"
            elif msg_type == 11:
                msg = "ERROR java.sql.SQLTimeoutException: ORA-01013"
            elif msg_type == 12:
                msg = "ERROR java.lang.NullPointerException: Object is null"
            else:
                msg = "INFO Processed incoming request successfully"
            
            f.write(f"{ts_str} [{thread}] {msg}\n")
            
            # 如果是 Exception，隨機補上 Stack Trace
            if "ERROR" in msg:
                for j in range(random.randint(5, 15)):
                    f.write(f"    at com.example.Application.method{j}(Application.java:{j*10})\n")

if __name__ == "__main__":
    import sys
    lines = int(sys.argv[1]) if len(sys.argv) > 1 else 100000
    generate_log("large_sample.log", lines)
    print(f"✅ 成功產生 {lines} 筆 Log：large_sample.log")
