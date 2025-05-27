#!/bin/bash

# Check for at least one argument
if [ -z "$1" ]; then
    echo "Usage: $0 <binary> [output_file]"
    echo "Example: $0 ./a.out"
    echo "         $0 ./a.out /tmp/full_dump.txt"
    exit 1
fi

BINARY="$1"

# Use second argument as full output file path if provided, else use default
if [ -n "$2" ]; then
    OUTFILE="$2"
else
    OUTBASE=$(basename "$BINARY")
    OUTFILE="${OUTBASE}_reverse_dump.txt"
fi

# Create directory if needed
mkdir -p "$(dirname "$OUTFILE")"

# Generate dump
objdump -M intel -D -R -f -C -r -s -S -x "$BINARY" > "$OUTFILE"

echo "[+] Dump saved to $OUTFILE"
