import asyncio
import json
from app.services.cai_project.testGM import main_cai_flow

async def analyze_traffic_block(log_block: str, verbose: bool = True):
    """
    Hàm AI dùng để phân tích 1 traffic log (1 block log nghi ngờ).
    
    Args:
        log_block (str): nội dung log (có thể là 1 đoạn text traffic)
        verbose (bool): nếu True thì in kết quả ra console
    
    Returns:
        dict: kết quả phân tích từ main_cai_flow()
    """
    if not log_block.strip():
        return {"status": "empty", "message": "No log content provided"}

    try:
        result = await main_cai_flow(log_block)
        if verbose:
            print("\n--- CAI Alert Analysis Result ---")
            print(json.dumps(result, indent=2, ensure_ascii=False))
            print("---------------------------------\n")
        return result
    except Exception as e:
        if verbose:
            print(f"[❌] Lỗi khi gọi main_cai_flow: {e}")
        return {"status": "error", "message": str(e)}
