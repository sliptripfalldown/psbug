#!/usr/bin/env python3
"""kptr_analyze.py — kernel pointer histogram + table runs for a kdata dump.
Usage: kptr_analyze.py <dump.bin> [kdata_base_hex]"""
import struct, sys
from collections import Counter

data = open(sys.argv[1], 'rb').read()
kdata = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0

kptrs = Counter(); tables = []; run = 0; run_start = 0; minp = 1 << 64
for off in range(0, len(data) - 8, 8):
    v = struct.unpack_from('<Q', data, off)[0]
    if 0xffffffff80000000 <= v < 0xffffffffffffffff and (v & 0xfff):
        kptrs[v >> 21] += 1; run += 1
        if run == 1: run_start = off
        if v < minp: minp = v
    else:
        if run >= 32: tables.append((run_start, run))
        run = 0

print("top 2MB buckets:", [f"{b<<21:#x} x{n}" for b, n in kptrs.most_common(8)])
print(f"min text-ish pointer: {minp:#x} -> derived kbase: {minp & ~0x1FFFFF:#x}")
print("pointer tables (>=32):", [f"+{s:#x}/{n}" for s, n in tables[:12]])
