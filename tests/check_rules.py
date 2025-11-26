import json

def check_duplicate_uuids(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        rules = json.load(f)

    seen = set()
    duplicates = []
    for r in rules:
        uid = r.get("uuid")
        if uid in seen:
            duplicates.append(uid)
        else:
            seen.add(uid)

    if duplicates:
        print(f"⚠️  Found duplicate UUIDs: {duplicates}")
    else:
        print("✅ No duplicate UUIDs found.")

if __name__ == "__main__":
    check_duplicate_uuids("rules.json")
