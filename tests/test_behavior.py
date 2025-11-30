import requests
import time

URL = "http://192.168.1.11/project_course/login"

for i in range(1):
    try:
        resp = requests.post(URL, data={
            "username": "testuser",
            "password": "wrongpassword"
        })

        print(f"[{i+1}/100] Status: {resp}")

    except Exception as e:
        print(f"[{i+1}/100] Error: {e}")

    time.sleep(0.005)  # giảm tốc độ để server không bị nghẽn
