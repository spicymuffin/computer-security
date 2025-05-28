import sys

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 script.py '<python_bytes_expr>'")
        print("Example: python3 script.py 'b\"A\" * 20 + b\"\\x50\\x11\\x40\\x00\\x00\\x00\\x00\\x00\"'")
        sys.exit(1)

    try:
        # evaluate the input expression as a bytes literal
        expr = sys.argv[1]
        byte_data = eval(expr, {"__builtins__": {}}, {})  # sandboxed
        if not isinstance(byte_data, bytes):
            raise TypeError("Expression did not evaluate to bytes.")
        sys.stdout.buffer.write(byte_data)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)