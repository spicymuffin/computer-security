# commands

gdb -x <init_file> warmup

x/10gx $rsp

script -q -c "objdump -M intel -d --visualize-jumps=extended-color ./executable" asm/executable.S

x/gx $r15 + $r12 * 8 - 0x400
