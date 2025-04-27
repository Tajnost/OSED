#!/usr/bin/env python3
import sys

def ror(val: int, r_bits: int, width: int = 32) -> int:
    """Rotate `val` right by `r_bits` within `width` bits."""
    return ((val >> r_bits) | (val << (width - r_bits))) & ((1 << width) - 1)


def hash_api_name(name: str) -> int:
    """Compute the rotate-right-13 & add hash for a given API name."""
    edx = 0
    for ch in name:
        edx = ror(edx, 13)
        edx = (edx + ord(ch)) & 0xFFFFFFFF
    return edx


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} API_NAME [API_NAME ...]")
        sys.exit(1)
    for name in sys.argv[1:]:
        h = hash_api_name(name)
        print(f"{name}: 0x{h:08x}")


if __name__ == "__main__":
    main()
