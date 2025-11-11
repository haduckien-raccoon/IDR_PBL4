import asyncio
from app.workers.ai_runner import analyze_traffic_block

sample_log = """
2025-10-05 17:19:05,263 [TRAFFIC] TRAFFIC proto=6 192.168.2.22:50008->169.254.169.254:80 entropy=4.152 bytes=40
hexdump:
00000000  47 45 54 20 2f 61 6e 79 70 61 74 68 3f 69 64 3d   GET /anypath?id=
00000010  31 20 55 4e 49 4f 4e 20 53 45 4c 45 43 54 20 31   1 UNION SELECT 1
00000020  2d 2d 20 48 54 54 50 2f 31 2e 31 0d 0a 48 6f 73   -- HTTP/1.1..Hos
00000030  74 3a 20 6c 6f 63 61 6c 68 6f 73 74 0d 0a 43 6f   t: localhost..Co
00000040  6e 6e 65 63 74 69 6f 6e 3a 20 63 6c 6f 73 65 0d   nnection: close.
00000050  0a 0d 0a                                          ...
"""

async def main():
    await analyze_traffic_block(sample_log)

if __name__ == "__main__":
    asyncio.run(main())
