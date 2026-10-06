#!/usr/bin/env python3
"""kdump_scan.py — offline scan of a raw PS5 kernel-text dump.

Finds what an hv_defeat port needs, with no symbols:
  - ROP gadgets (byte-exact) used by ps5-linux-loader chains
  - kernel build/version strings
  - pointer tables that look like IDT/TSS/FACS anchors (heuristic, ranked)

Usage: kdump_scan.py <dump.bin> [more.bin ...]
"""
import re
import sys
from collections import Counter

GADGETS = {
    "ret": b"\xc3",
    "pop rdi; ret": b"\x5f\xc3",
    "pop rsi; ret": b"\x5e\xc3",
    "pop rdx; ret": b"\x5a\xc3",
    "pop rcx; ret": b"\x59\xc3",
    "pop rax; ret": b"\x58\xc3",
    "pop rsp; ret": b"\x5c\xc3",
    "mov [rdi], rsi; pop rbp; ret": b"\x48\x89\x37\x5d\xc3",
    "mov [rdi], rax; ret": b"\x48\x89\x07\xc3",
    "mov rax, [rax]; ret": b"\x48\x8b\x00\xc3",
    "add rsp, 0x28; pop rbp; ret": b"\x48\x83\xc4\x28\x5d\xc3",
    "wrmsr; ret": b"\x0f\x30\xc3",
    "iretq": b"\x48\xcf",
}

KERNEL_PTR = re.compile(rb"\x48\x8d[\x00-\xff]{3}", re.DOTALL)  # lea r64, [rip+x] — coarse


def scan(path):
    data = open(path, "rb").read()
    print(f"== {path}: {len(data)} bytes ==")

    for name, pat in GADGETS.items():
        hits = []
        start = 0
        while len(hits) < 5:
            i = data.find(pat, start)
            if i < 0:
                break
            hits.append(f"0x{i:x}")
            start = i + 1
        total = data.count(pat)
        print(f"  {name:36s} {total:6d} hits  {', '.join(hits)}")

    for m in re.finditer(rb"[ -~]{12,}", data):
        s = m.group().decode()
        if re.search(r"(?i)(build|version|freebsd|prospero|13\.6|13\.03|scei|patch|beta)", s):
            print(f"  str @0x{m.start():x}: {s[:100]}")

    # Heuristic: IDT-like run of kernel code pointers (16-byte gates, high halves 0xffffffff8xxxxxxx)
    gates = 0
    run = 0
    best_run, best_at = 0, 0
    for off in range(0, len(data) - 16, 16):
        q = int.from_bytes(data[off + 8:off + 16], "little")
        if q >> 40 == 0xFFFFFF and q & 0xFFFF:  # 0xFFFFFF... = kernel-half canonical
            run += 1
            if run > best_run:
                best_run, best_at = run, off - 16 * (run - 1)
        else:
            run = 0
    print(f"  longest aligned kernel-ptr run: {best_run} entries @0x{best_at:x} (IDT/TSS candidate)")
    print()


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    for p in sys.argv[1:]:
        scan(p)


if __name__ == "__main__":
    main()
