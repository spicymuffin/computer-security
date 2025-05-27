
warmup:     file format elf64-x86-64
warmup
architecture: i386:x86-64, flags 0x00000112:
EXEC_P, HAS_SYMS, D_PAGED
start address 0x0000000000401060

Program Header:
    PHDR off    0x0000000000000040 vaddr 0x0000000000400040 paddr 0x0000000000400040 align 2**3
         filesz 0x00000000000002d8 memsz 0x00000000000002d8 flags r--
  INTERP off    0x0000000000000318 vaddr 0x0000000000400318 paddr 0x0000000000400318 align 2**0
         filesz 0x000000000000001c memsz 0x000000000000001c flags r--
    LOAD off    0x0000000000000000 vaddr 0x0000000000400000 paddr 0x0000000000400000 align 2**12
         filesz 0x0000000000000560 memsz 0x0000000000000560 flags r--
    LOAD off    0x0000000000001000 vaddr 0x0000000000401000 paddr 0x0000000000401000 align 2**12
         filesz 0x00000000000001d1 memsz 0x00000000000001d1 flags r-x
    LOAD off    0x0000000000002000 vaddr 0x0000000000402000 paddr 0x0000000000402000 align 2**12
         filesz 0x0000000000000124 memsz 0x0000000000000124 flags r--
    LOAD off    0x0000000000002df8 vaddr 0x0000000000403df8 paddr 0x0000000000403df8 align 2**12
         filesz 0x0000000000000230 memsz 0x0000000000000238 flags rw-
 DYNAMIC off    0x0000000000002e08 vaddr 0x0000000000403e08 paddr 0x0000000000403e08 align 2**3
         filesz 0x00000000000001d0 memsz 0x00000000000001d0 flags rw-
    NOTE off    0x0000000000000338 vaddr 0x0000000000400338 paddr 0x0000000000400338 align 2**3
         filesz 0x0000000000000020 memsz 0x0000000000000020 flags r--
    NOTE off    0x0000000000000358 vaddr 0x0000000000400358 paddr 0x0000000000400358 align 2**2
         filesz 0x0000000000000044 memsz 0x0000000000000044 flags r--
0x6474e553 off    0x0000000000000338 vaddr 0x0000000000400338 paddr 0x0000000000400338 align 2**3
         filesz 0x0000000000000020 memsz 0x0000000000000020 flags r--
EH_FRAME off    0x000000000000201c vaddr 0x000000000040201c paddr 0x000000000040201c align 2**2
         filesz 0x000000000000003c memsz 0x000000000000003c flags r--
   STACK off    0x0000000000000000 vaddr 0x0000000000000000 paddr 0x0000000000000000 align 2**4
         filesz 0x0000000000000000 memsz 0x0000000000000000 flags rw-
   RELRO off    0x0000000000002df8 vaddr 0x0000000000403df8 paddr 0x0000000000403df8 align 2**0
         filesz 0x0000000000000208 memsz 0x0000000000000208 flags r--

Dynamic Section:
  NEEDED               libc.so.6
  INIT                 0x0000000000401000
  FINI                 0x00000000004011c4
  INIT_ARRAY           0x0000000000403df8
  INIT_ARRAYSZ         0x0000000000000008
  FINI_ARRAY           0x0000000000403e00
  FINI_ARRAYSZ         0x0000000000000008
  GNU_HASH             0x00000000004003a0
  STRTAB               0x0000000000400450
  SYMTAB               0x00000000004003c0
  STRSZ                0x0000000000000056
  SYMENT               0x0000000000000018
  DEBUG                0x0000000000000000
  PLTGOT               0x0000000000403fe8
  PLTRELSZ             0x0000000000000048
  PLTREL               0x0000000000000007
  JMPREL               0x0000000000400518
  RELA                 0x00000000004004e8
  RELASZ               0x0000000000000030
  RELAENT              0x0000000000000018
  VERNEED              0x00000000004004b8
  VERNEEDNUM           0x0000000000000001
  VERSYM               0x00000000004004a6

Version References:
  required from libc.so.6:
    0x09691a75 0x00 03 GLIBC_2.2.5
    0x069691b4 0x00 02 GLIBC_2.34

Sections:
Idx Name          Size      VMA               LMA               File off  Algn
  0 .interp       0000001c  0000000000400318  0000000000400318  00000318  2**0
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  1 .note.gnu.property 00000020  0000000000400338  0000000000400338  00000338  2**3
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  2 .note.gnu.build-id 00000024  0000000000400358  0000000000400358  00000358  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  3 .note.ABI-tag 00000020  000000000040037c  000000000040037c  0000037c  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  4 .gnu.hash     0000001c  00000000004003a0  00000000004003a0  000003a0  2**3
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  5 .dynsym       00000090  00000000004003c0  00000000004003c0  000003c0  2**3
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  6 .dynstr       00000056  0000000000400450  0000000000400450  00000450  2**0
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  7 .gnu.version  0000000c  00000000004004a6  00000000004004a6  000004a6  2**1
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  8 .gnu.version_r 00000030  00000000004004b8  00000000004004b8  000004b8  2**3
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  9 .rela.dyn     00000030  00000000004004e8  00000000004004e8  000004e8  2**3
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
 10 .rela.plt     00000048  0000000000400518  0000000000400518  00000518  2**3
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
 11 .init         0000001b  0000000000401000  0000000000401000  00001000  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
 12 .plt          00000040  0000000000401020  0000000000401020  00001020  2**4
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
 13 .text         00000163  0000000000401060  0000000000401060  00001060  2**4
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
 14 .fini         0000000d  00000000004011c4  00000000004011c4  000011c4  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
 15 .rodata       00000019  0000000000402000  0000000000402000  00002000  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
 16 .eh_frame_hdr 0000003c  000000000040201c  000000000040201c  0000201c  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
 17 .eh_frame     000000cc  0000000000402058  0000000000402058  00002058  2**3
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
 18 .init_array   00000008  0000000000403df8  0000000000403df8  00002df8  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 19 .fini_array   00000008  0000000000403e00  0000000000403e00  00002e00  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 20 .dynamic      000001d0  0000000000403e08  0000000000403e08  00002e08  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 21 .got          00000010  0000000000403fd8  0000000000403fd8  00002fd8  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 22 .got.plt      00000030  0000000000403fe8  0000000000403fe8  00002fe8  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 23 .data         00000010  0000000000404018  0000000000404018  00003018  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 24 .bss          00000008  0000000000404028  0000000000404028  00003028  2**0
                  ALLOC
 25 .comment      00000052  0000000000000000  0000000000000000  00003028  2**0
                  CONTENTS, READONLY
SYMBOL TABLE:
no symbols


Contents of section .interp:
 400318 2f6c6962 36342f6c 642d6c69 6e75782d  /lib64/ld-linux-
 400328 7838362d 36342e73 6f2e3200           x86-64.so.2.    
Contents of section .note.gnu.property:
 400338 04000000 10000000 05000000 474e5500  ............GNU.
 400348 028000c0 04000000 01000000 00000000  ................
Contents of section .note.gnu.build-id:
 400358 04000000 14000000 03000000 474e5500  ............GNU.
 400368 26bb55ef cfd9dcd5 f21b29f6 93ef0617  &.U.......).....
 400378 3195272c                             1.',            
Contents of section .note.ABI-tag:
 40037c 04000000 10000000 01000000 474e5500  ............GNU.
 40038c 00000000 03000000 02000000 00000000  ................
Contents of section .gnu.hash:
 4003a0 01000000 01000000 01000000 00000000  ................
 4003b0 00000000 00000000 00000000           ............    
Contents of section .dynsym:
 4003c0 00000000 00000000 00000000 00000000  ................
 4003d0 00000000 00000000 0d000000 12000000  ................
 4003e0 00000000 00000000 00000000 00000000  ................
 4003f0 1f000000 12000000 00000000 00000000  ................
 400400 00000000 00000000 06000000 12000000  ................
 400410 00000000 00000000 00000000 00000000  ................
 400420 47000000 20000000 00000000 00000000  G... ...........
 400430 00000000 00000000 01000000 12000000  ................
 400440 00000000 00000000 00000000 00000000  ................
Contents of section .dynstr:
 400450 00676574 73006578 65637665 005f5f6c  .gets.execve.__l
 400460 6962635f 73746172 745f6d61 696e0070  ibc_start_main.p
 400470 72696e74 66006c69 62632e73 6f2e3600  rintf.libc.so.6.
 400480 474c4942 435f322e 322e3500 474c4942  GLIBC_2.2.5.GLIB
 400490 435f322e 3334005f 5f676d6f 6e5f7374  C_2.34.__gmon_st
 4004a0 6172745f 5f00                        art__.          
Contents of section .gnu.version:
 4004a6 00000200 03000300 01000300           ............    
Contents of section .gnu.version_r:
 4004b8 01000200 26000000 10000000 00000000  ....&...........
 4004c8 751a6909 00000300 30000000 10000000  u.i.....0.......
 4004d8 b4919606 00000200 3c000000 00000000  ........<.......
Contents of section .rela.dyn:
 4004e8 d83f4000 00000000 06000000 01000000  .?@.............
 4004f8 00000000 00000000 e03f4000 00000000  .........?@.....
 400508 06000000 04000000 00000000 00000000  ................
Contents of section .rela.plt:
 400518 00404000 00000000 07000000 02000000  .@@.............
 400528 00000000 00000000 08404000 00000000  .........@@.....
 400538 07000000 03000000 00000000 00000000  ................
 400548 10404000 00000000 07000000 05000000  .@@.............
 400558 00000000 00000000                    ........        
Contents of section .init:
 401000 f30f1efa 4883ec08 488b05d1 2f000048  ....H...H.../..H
 401010 85c07402 ffd04883 c408c3             ..t...H....     
Contents of section .plt:
 401020 ff35ca2f 0000ff25 cc2f0000 0f1f4000  .5./...%./....@.
 401030 ff25ca2f 00006800 000000e9 e0ffffff  .%./..h.........
 401040 ff25c22f 00006801 000000e9 d0ffffff  .%./..h.........
 401050 ff25ba2f 00006802 000000e9 c0ffffff  .%./..h.........
Contents of section .text:
 401060 f30f1efa 31ed4989 d15e4889 e24883e4  ....1.I..^H..H..
 401070 f0505445 31c031c9 48c7c7a0 114000ff  .PTE1.1.H....@..
 401080 15532f00 00f4662e 0f1f8400 00000000  .S/...f.........
 401090 f30f1efa c3662e0f 1f840000 00000090  .....f..........
 4010a0 b8284040 00483d28 40400074 13b80000  .(@@.H=(@@.t....
 4010b0 00004885 c07409bf 28404000 ffe06690  ..H..t..(@@...f.
 4010c0 c366662e 0f1f8400 00000000 0f1f4000  .ff...........@.
 4010d0 be284040 004881ee 28404000 4889f048  .(@@.H..(@@.H..H
 4010e0 c1ee3f48 c1f80348 01c648d1 fe7411b8  ..?H...H..H..t..
 4010f0 00000000 4885c074 07bf2840 4000ffe0  ....H..t..(@@...
 401100 c366662e 0f1f8400 00000000 0f1f4000  .ff...........@.
 401110 f30f1efa 803d0d2f 00000075 13554889  .....=./...u.UH.
 401120 e5e87aff ffffc605 fb2e0000 015dc390  ..z..........]..
 401130 c366662e 0f1f8400 00000000 0f1f4000  .ff...........@.
 401140 f30f1efa eb8a662e 0f1f8400 00000000  ......f.........
 401150 554889e5 488d3da9 0e000031 c089c248  UH..H.=....1...H
 401160 89d6e8d9 feffff5d c30f1f80 00000000  .......]........
 401170 554889e5 4883ec10 488d3d8d 0e0000b0  UH..H...H.=.....
 401180 00e8aafe ffff488d 7df4e8c1 feffff48  ......H.}......H
 401190 83c4105d c366662e 0f1f8400 00000000  ...].ff.........
 4011a0 554889e5 4883ec10 c745fc00 00000089  UH..H....E......
 4011b0 7df84889 75f0e8b5 ffffff31 c04883c4  }.H.u......1.H..
 4011c0 105dc3                               .].             
Contents of section .fini:
 4011c4 f30f1efa 4883ec08 4883c408 c3        ....H...H....   
Contents of section .rodata:
 402000 01000200 2f62696e 2f736800 456e7465  ..../bin/sh.Ente
 402010 72206e61 6d653a0a 00                 r name:..       
Contents of section .eh_frame_hdr:
 40201c 011b033b 38000000 06000000 04f0ffff  ...;8...........
 40202c 7c000000 44f0ffff 54000000 74f0ffff  |...D...T...t...
 40203c 68000000 34f1ffff a4000000 54f1ffff  h...4.......T...
 40204c c4000000 84f1ffff e4000000           ............    
Contents of section .eh_frame:
 402058 14000000 00000000 017a5200 01781001  .........zR..x..
 402068 1b0c0708 90010000 10000000 1c000000  ................
 402078 e8efffff 26000000 00440710 10000000  ....&....D......
 402088 30000000 04f0ffff 05000000 00000000  0...............
 402098 24000000 44000000 80efffff 40000000  $...D.......@...
 4020a8 000e1046 0e184a0f 0b770880 003f1a3b  ...F..J..w...?.;
 4020b8 2a332422 00000000 1c000000 6c000000  *3$"........l...
 4020c8 88f0ffff 19000000 00410e10 8602430d  .........A....C.
 4020d8 06540c07 08000000 1c000000 8c000000  .T..............
 4020e8 88f0ffff 25000000 00410e10 8602430d  ....%....A....C.
 4020f8 06600c07 08000000 1c000000 ac000000  .`..............
 402108 98f0ffff 23000000 00410e10 8602430d  ....#....A....C.
 402118 065e0c07 08000000 00000000           .^..........    
Contents of section .init_array:
 403df8 40114000 00000000                    @.@.....        
Contents of section .fini_array:
 403e00 10114000 00000000                    ..@.....        
Contents of section .dynamic:
 403e08 01000000 00000000 26000000 00000000  ........&.......
 403e18 0c000000 00000000 00104000 00000000  ..........@.....
 403e28 0d000000 00000000 c4114000 00000000  ..........@.....
 403e38 19000000 00000000 f83d4000 00000000  .........=@.....
 403e48 1b000000 00000000 08000000 00000000  ................
 403e58 1a000000 00000000 003e4000 00000000  .........>@.....
 403e68 1c000000 00000000 08000000 00000000  ................
 403e78 f5feff6f 00000000 a0034000 00000000  ...o......@.....
 403e88 05000000 00000000 50044000 00000000  ........P.@.....
 403e98 06000000 00000000 c0034000 00000000  ..........@.....
 403ea8 0a000000 00000000 56000000 00000000  ........V.......
 403eb8 0b000000 00000000 18000000 00000000  ................
 403ec8 15000000 00000000 00000000 00000000  ................
 403ed8 03000000 00000000 e83f4000 00000000  .........?@.....
 403ee8 02000000 00000000 48000000 00000000  ........H.......
 403ef8 14000000 00000000 07000000 00000000  ................
 403f08 17000000 00000000 18054000 00000000  ..........@.....
 403f18 07000000 00000000 e8044000 00000000  ..........@.....
 403f28 08000000 00000000 30000000 00000000  ........0.......
 403f38 09000000 00000000 18000000 00000000  ................
 403f48 feffff6f 00000000 b8044000 00000000  ...o......@.....
 403f58 ffffff6f 00000000 01000000 00000000  ...o............
 403f68 f0ffff6f 00000000 a6044000 00000000  ...o......@.....
 403f78 00000000 00000000 00000000 00000000  ................
 403f88 00000000 00000000 00000000 00000000  ................
 403f98 00000000 00000000 00000000 00000000  ................
 403fa8 00000000 00000000 00000000 00000000  ................
 403fb8 00000000 00000000 00000000 00000000  ................
 403fc8 00000000 00000000 00000000 00000000  ................
Contents of section .got:
 403fd8 00000000 00000000 00000000 00000000  ................
Contents of section .got.plt:
 403fe8 083e4000 00000000 00000000 00000000  .>@.............
 403ff8 00000000 00000000 36104000 00000000  ........6.@.....
 404008 46104000 00000000 56104000 00000000  F.@.....V.@.....
Contents of section .data:
 404018 00000000 00000000 00000000 00000000  ................
Contents of section .comment:
 0000 4743433a 20285562 756e7475 2031342e  GCC: (Ubuntu 14.
 0010 322e302d 34756275 6e747532 7e32342e  2.0-4ubuntu2~24.
 0020 30342920 31342e32 2e300055 62756e74  04) 14.2.0.Ubunt
 0030 7520636c 616e6720 76657273 696f6e20  u clang version 
 0040 31382e31 2e332028 31756275 6e747531  18.1.3 (1ubuntu1
 0050 2900                                 ).              

Disassembly of section .interp:

0000000000400318 <.interp>:
  400318:	2f                   	(bad)
  400319:	6c                   	ins    BYTE PTR es:[rdi],dx
  40031a:	69 62 36 34 2f 6c 64 	imul   esp,DWORD PTR [rdx+0x36],0x646c2f34
  400321:	2d 6c 69 6e 75       	sub    eax,0x756e696c
  400326:	78 2d                	js     400355 <printf@plt-0xcdb>
  400328:	78 38                	js     400362 <printf@plt-0xcce>
  40032a:	36 2d 36 34 2e 73    	ss sub eax,0x732e3436
  400330:	6f                   	outs   dx,DWORD PTR ds:[rsi]
  400331:	2e 32 00             	cs xor al,BYTE PTR [rax]

Disassembly of section .note.gnu.property:

0000000000400338 <.note.gnu.property>:
  400338:	04 00                	add    al,0x0
  40033a:	00 00                	add    BYTE PTR [rax],al
  40033c:	10 00                	adc    BYTE PTR [rax],al
  40033e:	00 00                	add    BYTE PTR [rax],al
  400340:	05 00 00 00 47       	add    eax,0x47000000
  400345:	4e 55                	rex.WRX push rbp
  400347:	00 02                	add    BYTE PTR [rdx],al
  400349:	80 00 c0             	add    BYTE PTR [rax],0xc0
  40034c:	04 00                	add    al,0x0
  40034e:	00 00                	add    BYTE PTR [rax],al
  400350:	01 00                	add    DWORD PTR [rax],eax
  400352:	00 00                	add    BYTE PTR [rax],al
  400354:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .note.gnu.build-id:

0000000000400358 <.note.gnu.build-id>:
  400358:	04 00                	add    al,0x0
  40035a:	00 00                	add    BYTE PTR [rax],al
  40035c:	14 00                	adc    al,0x0
  40035e:	00 00                	add    BYTE PTR [rax],al
  400360:	03 00                	add    eax,DWORD PTR [rax]
  400362:	00 00                	add    BYTE PTR [rax],al
  400364:	47                   	rex.RXB
  400365:	4e 55                	rex.WRX push rbp
  400367:	00 26                	add    BYTE PTR [rsi],ah
  400369:	bb 55 ef cf d9       	mov    ebx,0xd9cfef55
  40036e:	dc d5                	(bad)
  400370:	f2 1b 29             	repnz sbb ebp,DWORD PTR [rcx]
  400373:	f6 93 ef 06 17 31    	not    BYTE PTR [rbx+0x311706ef]
  400379:	95                   	xchg   ebp,eax
  40037a:	27                   	(bad)
  40037b:	2c                   	.byte 0x2c

Disassembly of section .note.ABI-tag:

000000000040037c <.note.ABI-tag>:
  40037c:	04 00                	add    al,0x0
  40037e:	00 00                	add    BYTE PTR [rax],al
  400380:	10 00                	adc    BYTE PTR [rax],al
  400382:	00 00                	add    BYTE PTR [rax],al
  400384:	01 00                	add    DWORD PTR [rax],eax
  400386:	00 00                	add    BYTE PTR [rax],al
  400388:	47                   	rex.RXB
  400389:	4e 55                	rex.WRX push rbp
  40038b:	00 00                	add    BYTE PTR [rax],al
  40038d:	00 00                	add    BYTE PTR [rax],al
  40038f:	00 03                	add    BYTE PTR [rbx],al
  400391:	00 00                	add    BYTE PTR [rax],al
  400393:	00 02                	add    BYTE PTR [rdx],al
  400395:	00 00                	add    BYTE PTR [rax],al
  400397:	00 00                	add    BYTE PTR [rax],al
  400399:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .gnu.hash:

00000000004003a0 <.gnu.hash>:
  4003a0:	01 00                	add    DWORD PTR [rax],eax
  4003a2:	00 00                	add    BYTE PTR [rax],al
  4003a4:	01 00                	add    DWORD PTR [rax],eax
  4003a6:	00 00                	add    BYTE PTR [rax],al
  4003a8:	01 00                	add    DWORD PTR [rax],eax
	...

Disassembly of section .dynsym:

00000000004003c0 <.dynsym>:
	...
  4003d8:	0d 00 00 00 12       	or     eax,0x12000000
	...
  4003ed:	00 00                	add    BYTE PTR [rax],al
  4003ef:	00 1f                	add    BYTE PTR [rdi],bl
  4003f1:	00 00                	add    BYTE PTR [rax],al
  4003f3:	00 12                	add    BYTE PTR [rdx],dl
	...
  400405:	00 00                	add    BYTE PTR [rax],al
  400407:	00 06                	add    BYTE PTR [rsi],al
  400409:	00 00                	add    BYTE PTR [rax],al
  40040b:	00 12                	add    BYTE PTR [rdx],dl
	...
  40041d:	00 00                	add    BYTE PTR [rax],al
  40041f:	00 47 00             	add    BYTE PTR [rdi+0x0],al
  400422:	00 00                	add    BYTE PTR [rax],al
  400424:	20 00                	and    BYTE PTR [rax],al
	...
  400436:	00 00                	add    BYTE PTR [rax],al
  400438:	01 00                	add    DWORD PTR [rax],eax
  40043a:	00 00                	add    BYTE PTR [rax],al
  40043c:	12 00                	adc    al,BYTE PTR [rax]
	...

Disassembly of section .dynstr:

0000000000400450 <.dynstr>:
  400450:	00 67 65             	add    BYTE PTR [rdi+0x65],ah
  400453:	74 73                	je     4004c8 <printf@plt-0xb68>
  400455:	00 65 78             	add    BYTE PTR [rbp+0x78],ah
  400458:	65 63 76 65          	movsxd esi,DWORD PTR gs:[rsi+0x65]
  40045c:	00 5f 5f             	add    BYTE PTR [rdi+0x5f],bl
  40045f:	6c                   	ins    BYTE PTR es:[rdi],dx
  400460:	69 62 63 5f 73 74 61 	imul   esp,DWORD PTR [rdx+0x63],0x6174735f
  400467:	72 74                	jb     4004dd <printf@plt-0xb53>
  400469:	5f                   	pop    rdi
  40046a:	6d                   	ins    DWORD PTR es:[rdi],dx
  40046b:	61                   	(bad)
  40046c:	69 6e 00 70 72 69 6e 	imul   ebp,DWORD PTR [rsi+0x0],0x6e697270
  400473:	74 66                	je     4004db <printf@plt-0xb55>
  400475:	00 6c 69 62          	add    BYTE PTR [rcx+rbp*2+0x62],ch
  400479:	63 2e                	movsxd ebp,DWORD PTR [rsi]
  40047b:	73 6f                	jae    4004ec <printf@plt-0xb44>
  40047d:	2e 36 00 47 4c       	cs ss add BYTE PTR [rdi+0x4c],al
  400482:	49                   	rex.WB
  400483:	42                   	rex.X
  400484:	43 5f                	rex.XB pop r15
  400486:	32 2e                	xor    ch,BYTE PTR [rsi]
  400488:	32 2e                	xor    ch,BYTE PTR [rsi]
  40048a:	35 00 47 4c 49       	xor    eax,0x494c4700
  40048f:	42                   	rex.X
  400490:	43 5f                	rex.XB pop r15
  400492:	32 2e                	xor    ch,BYTE PTR [rsi]
  400494:	33 34 00             	xor    esi,DWORD PTR [rax+rax*1]
  400497:	5f                   	pop    rdi
  400498:	5f                   	pop    rdi
  400499:	67 6d                	ins    DWORD PTR es:[edi],dx
  40049b:	6f                   	outs   dx,DWORD PTR ds:[rsi]
  40049c:	6e                   	outs   dx,BYTE PTR ds:[rsi]
  40049d:	5f                   	pop    rdi
  40049e:	73 74                	jae    400514 <printf@plt-0xb1c>
  4004a0:	61                   	(bad)
  4004a1:	72 74                	jb     400517 <printf@plt-0xb19>
  4004a3:	5f                   	pop    rdi
  4004a4:	5f                   	pop    rdi
	...

Disassembly of section .gnu.version:

00000000004004a6 <.gnu.version>:
  4004a6:	00 00                	add    BYTE PTR [rax],al
  4004a8:	02 00                	add    al,BYTE PTR [rax]
  4004aa:	03 00                	add    eax,DWORD PTR [rax]
  4004ac:	03 00                	add    eax,DWORD PTR [rax]
  4004ae:	01 00                	add    DWORD PTR [rax],eax
  4004b0:	03 00                	add    eax,DWORD PTR [rax]

Disassembly of section .gnu.version_r:

00000000004004b8 <.gnu.version_r>:
  4004b8:	01 00                	add    DWORD PTR [rax],eax
  4004ba:	02 00                	add    al,BYTE PTR [rax]
  4004bc:	26 00 00             	es add BYTE PTR [rax],al
  4004bf:	00 10                	add    BYTE PTR [rax],dl
  4004c1:	00 00                	add    BYTE PTR [rax],al
  4004c3:	00 00                	add    BYTE PTR [rax],al
  4004c5:	00 00                	add    BYTE PTR [rax],al
  4004c7:	00 75 1a             	add    BYTE PTR [rbp+0x1a],dh
  4004ca:	69 09 00 00 03 00    	imul   ecx,DWORD PTR [rcx],0x30000
  4004d0:	30 00                	xor    BYTE PTR [rax],al
  4004d2:	00 00                	add    BYTE PTR [rax],al
  4004d4:	10 00                	adc    BYTE PTR [rax],al
  4004d6:	00 00                	add    BYTE PTR [rax],al
  4004d8:	b4 91                	mov    ah,0x91
  4004da:	96                   	xchg   esi,eax
  4004db:	06                   	(bad)
  4004dc:	00 00                	add    BYTE PTR [rax],al
  4004de:	02 00                	add    al,BYTE PTR [rax]
  4004e0:	3c 00                	cmp    al,0x0
  4004e2:	00 00                	add    BYTE PTR [rax],al
  4004e4:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .rela.dyn:

00000000004004e8 <.rela.dyn>:
  4004e8:	d8 3f                	fdivr  DWORD PTR [rdi]
  4004ea:	40 00 00             	rex add BYTE PTR [rax],al
  4004ed:	00 00                	add    BYTE PTR [rax],al
  4004ef:	00 06                	add    BYTE PTR [rsi],al
  4004f1:	00 00                	add    BYTE PTR [rax],al
  4004f3:	00 01                	add    BYTE PTR [rcx],al
	...
  4004fd:	00 00                	add    BYTE PTR [rax],al
  4004ff:	00 e0                	add    al,ah
  400501:	3f                   	(bad)
  400502:	40 00 00             	rex add BYTE PTR [rax],al
  400505:	00 00                	add    BYTE PTR [rax],al
  400507:	00 06                	add    BYTE PTR [rsi],al
  400509:	00 00                	add    BYTE PTR [rax],al
  40050b:	00 04 00             	add    BYTE PTR [rax+rax*1],al
	...

Disassembly of section .rela.plt:

0000000000400518 <.rela.plt>:
  400518:	00 40 40             	add    BYTE PTR [rax+0x40],al
  40051b:	00 00                	add    BYTE PTR [rax],al
  40051d:	00 00                	add    BYTE PTR [rax],al
  40051f:	00 07                	add    BYTE PTR [rdi],al
  400521:	00 00                	add    BYTE PTR [rax],al
  400523:	00 02                	add    BYTE PTR [rdx],al
	...
  40052d:	00 00                	add    BYTE PTR [rax],al
  40052f:	00 08                	add    BYTE PTR [rax],cl
  400531:	40                   	rex
  400532:	40 00 00             	rex add BYTE PTR [rax],al
  400535:	00 00                	add    BYTE PTR [rax],al
  400537:	00 07                	add    BYTE PTR [rdi],al
  400539:	00 00                	add    BYTE PTR [rax],al
  40053b:	00 03                	add    BYTE PTR [rbx],al
	...
  400545:	00 00                	add    BYTE PTR [rax],al
  400547:	00 10                	add    BYTE PTR [rax],dl
  400549:	40                   	rex
  40054a:	40 00 00             	rex add BYTE PTR [rax],al
  40054d:	00 00                	add    BYTE PTR [rax],al
  40054f:	00 07                	add    BYTE PTR [rdi],al
  400551:	00 00                	add    BYTE PTR [rax],al
  400553:	00 05 00 00 00 00    	add    BYTE PTR [rip+0x0],al        # 400559 <printf@plt-0xad7>
  400559:	00 00                	add    BYTE PTR [rax],al
  40055b:	00 00                	add    BYTE PTR [rax],al
  40055d:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .init:

0000000000401000 <.init>:
  401000:	f3 0f 1e fa          	endbr64
  401004:	48 83 ec 08          	sub    rsp,0x8
  401008:	48 8b 05 d1 2f 00 00 	mov    rax,QWORD PTR [rip+0x2fd1]        # 403fe0 <gets@plt+0x2f90>
  40100f:	48 85 c0             	test   rax,rax
  401012:	74 02                	je     401016 <printf@plt-0x1a>
  401014:	ff d0                	call   rax
  401016:	48 83 c4 08          	add    rsp,0x8
  40101a:	c3                   	ret

Disassembly of section .plt:

0000000000401020 <printf@plt-0x10>:
  401020:	ff 35 ca 2f 00 00    	push   QWORD PTR [rip+0x2fca]        # 403ff0 <gets@plt+0x2fa0>
  401026:	ff 25 cc 2f 00 00    	jmp    QWORD PTR [rip+0x2fcc]        # 403ff8 <gets@plt+0x2fa8>
  40102c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

0000000000401030 <printf@plt>:
  401030:	ff 25 ca 2f 00 00    	jmp    QWORD PTR [rip+0x2fca]        # 404000 <gets@plt+0x2fb0>
  401036:	68 00 00 00 00       	push   0x0
  40103b:	e9 e0 ff ff ff       	jmp    401020 <printf@plt-0x10>

0000000000401040 <execve@plt>:
  401040:	ff 25 c2 2f 00 00    	jmp    QWORD PTR [rip+0x2fc2]        # 404008 <gets@plt+0x2fb8>
  401046:	68 01 00 00 00       	push   0x1
  40104b:	e9 d0 ff ff ff       	jmp    401020 <printf@plt-0x10>

0000000000401050 <gets@plt>:
  401050:	ff 25 ba 2f 00 00    	jmp    QWORD PTR [rip+0x2fba]        # 404010 <gets@plt+0x2fc0>
  401056:	68 02 00 00 00       	push   0x2
  40105b:	e9 c0 ff ff ff       	jmp    401020 <printf@plt-0x10>

Disassembly of section .text:

0000000000401060 <.text>:
  401060:	f3 0f 1e fa          	endbr64
  401064:	31 ed                	xor    ebp,ebp
  401066:	49 89 d1             	mov    r9,rdx
  401069:	5e                   	pop    rsi
  40106a:	48 89 e2             	mov    rdx,rsp
  40106d:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
  401071:	50                   	push   rax
  401072:	54                   	push   rsp
  401073:	45 31 c0             	xor    r8d,r8d
  401076:	31 c9                	xor    ecx,ecx
  401078:	48 c7 c7 a0 11 40 00 	mov    rdi,0x4011a0
  40107f:	ff 15 53 2f 00 00    	call   QWORD PTR [rip+0x2f53]        # 403fd8 <gets@plt+0x2f88>
  401085:	f4                   	hlt
  401086:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  40108d:	00 00 00 
  401090:	f3 0f 1e fa          	endbr64
  401094:	c3                   	ret
  401095:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  40109c:	00 00 00 
  40109f:	90                   	nop
  4010a0:	b8 28 40 40 00       	mov    eax,0x404028
  4010a5:	48 3d 28 40 40 00    	cmp    rax,0x404028
  4010ab:	74 13                	je     4010c0 <gets@plt+0x70>
  4010ad:	b8 00 00 00 00       	mov    eax,0x0
  4010b2:	48 85 c0             	test   rax,rax
  4010b5:	74 09                	je     4010c0 <gets@plt+0x70>
  4010b7:	bf 28 40 40 00       	mov    edi,0x404028
  4010bc:	ff e0                	jmp    rax
  4010be:	66 90                	xchg   ax,ax
  4010c0:	c3                   	ret
  4010c1:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  4010c8:	00 00 00 00 
  4010cc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  4010d0:	be 28 40 40 00       	mov    esi,0x404028
  4010d5:	48 81 ee 28 40 40 00 	sub    rsi,0x404028
  4010dc:	48 89 f0             	mov    rax,rsi
  4010df:	48 c1 ee 3f          	shr    rsi,0x3f
  4010e3:	48 c1 f8 03          	sar    rax,0x3
  4010e7:	48 01 c6             	add    rsi,rax
  4010ea:	48 d1 fe             	sar    rsi,1
  4010ed:	74 11                	je     401100 <gets@plt+0xb0>
  4010ef:	b8 00 00 00 00       	mov    eax,0x0
  4010f4:	48 85 c0             	test   rax,rax
  4010f7:	74 07                	je     401100 <gets@plt+0xb0>
  4010f9:	bf 28 40 40 00       	mov    edi,0x404028
  4010fe:	ff e0                	jmp    rax
  401100:	c3                   	ret
  401101:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  401108:	00 00 00 00 
  40110c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  401110:	f3 0f 1e fa          	endbr64
  401114:	80 3d 0d 2f 00 00 00 	cmp    BYTE PTR [rip+0x2f0d],0x0        # 404028 <gets@plt+0x2fd8>
  40111b:	75 13                	jne    401130 <gets@plt+0xe0>
  40111d:	55                   	push   rbp
  40111e:	48 89 e5             	mov    rbp,rsp
  401121:	e8 7a ff ff ff       	call   4010a0 <gets@plt+0x50>
  401126:	c6 05 fb 2e 00 00 01 	mov    BYTE PTR [rip+0x2efb],0x1        # 404028 <gets@plt+0x2fd8>
  40112d:	5d                   	pop    rbp
  40112e:	c3                   	ret
  40112f:	90                   	nop
  401130:	c3                   	ret
  401131:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  401138:	00 00 00 00 
  40113c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  401140:	f3 0f 1e fa          	endbr64
  401144:	eb 8a                	jmp    4010d0 <gets@plt+0x80>
  401146:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  40114d:	00 00 00 
  401150:	55                   	push   rbp
  401151:	48 89 e5             	mov    rbp,rsp
  401154:	48 8d 3d a9 0e 00 00 	lea    rdi,[rip+0xea9]        # 402004 <gets@plt+0xfb4>
  40115b:	31 c0                	xor    eax,eax
  40115d:	89 c2                	mov    edx,eax
  40115f:	48 89 d6             	mov    rsi,rdx
  401162:	e8 d9 fe ff ff       	call   401040 <execve@plt>
  401167:	5d                   	pop    rbp
  401168:	c3                   	ret
  401169:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
  401170:	55                   	push   rbp
  401171:	48 89 e5             	mov    rbp,rsp
  401174:	48 83 ec 10          	sub    rsp,0x10
  401178:	48 8d 3d 8d 0e 00 00 	lea    rdi,[rip+0xe8d]        # 40200c <gets@plt+0xfbc>
  40117f:	b0 00                	mov    al,0x0
  401181:	e8 aa fe ff ff       	call   401030 <printf@plt>
  401186:	48 8d 7d f4          	lea    rdi,[rbp-0xc]
  40118a:	e8 c1 fe ff ff       	call   401050 <gets@plt>
  40118f:	48 83 c4 10          	add    rsp,0x10
  401193:	5d                   	pop    rbp
  401194:	c3                   	ret
  401195:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  40119c:	00 00 00 00 
  4011a0:	55                   	push   rbp
  4011a1:	48 89 e5             	mov    rbp,rsp
  4011a4:	48 83 ec 10          	sub    rsp,0x10
  4011a8:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
  4011af:	89 7d f8             	mov    DWORD PTR [rbp-0x8],edi
  4011b2:	48 89 75 f0          	mov    QWORD PTR [rbp-0x10],rsi
  4011b6:	e8 b5 ff ff ff       	call   401170 <gets@plt+0x120>
  4011bb:	31 c0                	xor    eax,eax
  4011bd:	48 83 c4 10          	add    rsp,0x10
  4011c1:	5d                   	pop    rbp
  4011c2:	c3                   	ret

Disassembly of section .fini:

00000000004011c4 <.fini>:
  4011c4:	f3 0f 1e fa          	endbr64
  4011c8:	48 83 ec 08          	sub    rsp,0x8
  4011cc:	48 83 c4 08          	add    rsp,0x8
  4011d0:	c3                   	ret

Disassembly of section .rodata:

0000000000402000 <.rodata>:
  402000:	01 00                	add    DWORD PTR [rax],eax
  402002:	02 00                	add    al,BYTE PTR [rax]
  402004:	2f                   	(bad)
  402005:	62 69 6e 2f 73       	(bad)
  40200a:	68 00 45 6e 74       	push   0x746e4500
  40200f:	65 72 20             	gs jb  402032 <gets@plt+0xfe2>
  402012:	6e                   	outs   dx,BYTE PTR ds:[rsi]
  402013:	61                   	(bad)
  402014:	6d                   	ins    DWORD PTR es:[rdi],dx
  402015:	65 3a 0a             	cmp    cl,BYTE PTR gs:[rdx]
	...

Disassembly of section .eh_frame_hdr:

000000000040201c <.eh_frame_hdr>:
  40201c:	01 1b                	add    DWORD PTR [rbx],ebx
  40201e:	03 3b                	add    edi,DWORD PTR [rbx]
  402020:	38 00                	cmp    BYTE PTR [rax],al
  402022:	00 00                	add    BYTE PTR [rax],al
  402024:	06                   	(bad)
  402025:	00 00                	add    BYTE PTR [rax],al
  402027:	00 04 f0             	add    BYTE PTR [rax+rsi*8],al
  40202a:	ff                   	(bad)
  40202b:	ff                   	(bad)
  40202c:	7c 00                	jl     40202e <gets@plt+0xfde>
  40202e:	00 00                	add    BYTE PTR [rax],al
  402030:	44                   	rex.R
  402031:	f0 ff                	lock (bad)
  402033:	ff 54 00 00          	call   QWORD PTR [rax+rax*1+0x0]
  402037:	00 74 f0 ff          	add    BYTE PTR [rax+rsi*8-0x1],dh
  40203b:	ff 68 00             	jmp    FWORD PTR [rax+0x0]
  40203e:	00 00                	add    BYTE PTR [rax],al
  402040:	34 f1                	xor    al,0xf1
  402042:	ff                   	(bad)
  402043:	ff a4 00 00 00 54 f1 	jmp    QWORD PTR [rax+rax*1-0xeac0000]
  40204a:	ff                   	(bad)
  40204b:	ff c4                	inc    esp
  40204d:	00 00                	add    BYTE PTR [rax],al
  40204f:	00 84 f1 ff ff e4 00 	add    BYTE PTR [rcx+rsi*8+0xe4ffff],al
	...

Disassembly of section .eh_frame:

0000000000402058 <.eh_frame>:
  402058:	14 00                	adc    al,0x0
  40205a:	00 00                	add    BYTE PTR [rax],al
  40205c:	00 00                	add    BYTE PTR [rax],al
  40205e:	00 00                	add    BYTE PTR [rax],al
  402060:	01 7a 52             	add    DWORD PTR [rdx+0x52],edi
  402063:	00 01                	add    BYTE PTR [rcx],al
  402065:	78 10                	js     402077 <gets@plt+0x1027>
  402067:	01 1b                	add    DWORD PTR [rbx],ebx
  402069:	0c 07                	or     al,0x7
  40206b:	08 90 01 00 00 10    	or     BYTE PTR [rax+0x10000001],dl
  402071:	00 00                	add    BYTE PTR [rax],al
  402073:	00 1c 00             	add    BYTE PTR [rax+rax*1],bl
  402076:	00 00                	add    BYTE PTR [rax],al
  402078:	e8 ef ff ff 26       	call   2740206c <gets@plt+0x2700101c>
  40207d:	00 00                	add    BYTE PTR [rax],al
  40207f:	00 00                	add    BYTE PTR [rax],al
  402081:	44 07                	rex.R (bad)
  402083:	10 10                	adc    BYTE PTR [rax],dl
  402085:	00 00                	add    BYTE PTR [rax],al
  402087:	00 30                	add    BYTE PTR [rax],dh
  402089:	00 00                	add    BYTE PTR [rax],al
  40208b:	00 04 f0             	add    BYTE PTR [rax+rsi*8],al
  40208e:	ff                   	(bad)
  40208f:	ff 05 00 00 00 00    	inc    DWORD PTR [rip+0x0]        # 402095 <gets@plt+0x1045>
  402095:	00 00                	add    BYTE PTR [rax],al
  402097:	00 24 00             	add    BYTE PTR [rax+rax*1],ah
  40209a:	00 00                	add    BYTE PTR [rax],al
  40209c:	44 00 00             	add    BYTE PTR [rax],r8b
  40209f:	00 80 ef ff ff 40    	add    BYTE PTR [rax+0x40ffffef],al
  4020a5:	00 00                	add    BYTE PTR [rax],al
  4020a7:	00 00                	add    BYTE PTR [rax],al
  4020a9:	0e                   	(bad)
  4020aa:	10 46 0e             	adc    BYTE PTR [rsi+0xe],al
  4020ad:	18 4a 0f             	sbb    BYTE PTR [rdx+0xf],cl
  4020b0:	0b 77 08             	or     esi,DWORD PTR [rdi+0x8]
  4020b3:	80 00 3f             	add    BYTE PTR [rax],0x3f
  4020b6:	1a 3b                	sbb    bh,BYTE PTR [rbx]
  4020b8:	2a 33                	sub    dh,BYTE PTR [rbx]
  4020ba:	24 22                	and    al,0x22
  4020bc:	00 00                	add    BYTE PTR [rax],al
  4020be:	00 00                	add    BYTE PTR [rax],al
  4020c0:	1c 00                	sbb    al,0x0
  4020c2:	00 00                	add    BYTE PTR [rax],al
  4020c4:	6c                   	ins    BYTE PTR es:[rdi],dx
  4020c5:	00 00                	add    BYTE PTR [rax],al
  4020c7:	00 88 f0 ff ff 19    	add    BYTE PTR [rax+0x19fffff0],cl
  4020cd:	00 00                	add    BYTE PTR [rax],al
  4020cf:	00 00                	add    BYTE PTR [rax],al
  4020d1:	41 0e                	rex.B (bad)
  4020d3:	10 86 02 43 0d 06    	adc    BYTE PTR [rsi+0x60d4302],al
  4020d9:	54                   	push   rsp
  4020da:	0c 07                	or     al,0x7
  4020dc:	08 00                	or     BYTE PTR [rax],al
  4020de:	00 00                	add    BYTE PTR [rax],al
  4020e0:	1c 00                	sbb    al,0x0
  4020e2:	00 00                	add    BYTE PTR [rax],al
  4020e4:	8c 00                	mov    WORD PTR [rax],es
  4020e6:	00 00                	add    BYTE PTR [rax],al
  4020e8:	88 f0                	mov    al,dh
  4020ea:	ff                   	(bad)
  4020eb:	ff 25 00 00 00 00    	jmp    QWORD PTR [rip+0x0]        # 4020f1 <gets@plt+0x10a1>
  4020f1:	41 0e                	rex.B (bad)
  4020f3:	10 86 02 43 0d 06    	adc    BYTE PTR [rsi+0x60d4302],al
  4020f9:	60                   	(bad)
  4020fa:	0c 07                	or     al,0x7
  4020fc:	08 00                	or     BYTE PTR [rax],al
  4020fe:	00 00                	add    BYTE PTR [rax],al
  402100:	1c 00                	sbb    al,0x0
  402102:	00 00                	add    BYTE PTR [rax],al
  402104:	ac                   	lods   al,BYTE PTR ds:[rsi]
  402105:	00 00                	add    BYTE PTR [rax],al
  402107:	00 98 f0 ff ff 23    	add    BYTE PTR [rax+0x23fffff0],bl
  40210d:	00 00                	add    BYTE PTR [rax],al
  40210f:	00 00                	add    BYTE PTR [rax],al
  402111:	41 0e                	rex.B (bad)
  402113:	10 86 02 43 0d 06    	adc    BYTE PTR [rsi+0x60d4302],al
  402119:	5e                   	pop    rsi
  40211a:	0c 07                	or     al,0x7
  40211c:	08 00                	or     BYTE PTR [rax],al
  40211e:	00 00                	add    BYTE PTR [rax],al
  402120:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .init_array:

0000000000403df8 <.init_array>:
  403df8:	40 11 40 00          	rex adc DWORD PTR [rax+0x0],eax
  403dfc:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .fini_array:

0000000000403e00 <.fini_array>:
  403e00:	10 11                	adc    BYTE PTR [rcx],dl
  403e02:	40 00 00             	rex add BYTE PTR [rax],al
  403e05:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .dynamic:

0000000000403e08 <.dynamic>:
  403e08:	01 00                	add    DWORD PTR [rax],eax
  403e0a:	00 00                	add    BYTE PTR [rax],al
  403e0c:	00 00                	add    BYTE PTR [rax],al
  403e0e:	00 00                	add    BYTE PTR [rax],al
  403e10:	26 00 00             	es add BYTE PTR [rax],al
  403e13:	00 00                	add    BYTE PTR [rax],al
  403e15:	00 00                	add    BYTE PTR [rax],al
  403e17:	00 0c 00             	add    BYTE PTR [rax+rax*1],cl
  403e1a:	00 00                	add    BYTE PTR [rax],al
  403e1c:	00 00                	add    BYTE PTR [rax],al
  403e1e:	00 00                	add    BYTE PTR [rax],al
  403e20:	00 10                	add    BYTE PTR [rax],dl
  403e22:	40 00 00             	rex add BYTE PTR [rax],al
  403e25:	00 00                	add    BYTE PTR [rax],al
  403e27:	00 0d 00 00 00 00    	add    BYTE PTR [rip+0x0],cl        # 403e2d <gets@plt+0x2ddd>
  403e2d:	00 00                	add    BYTE PTR [rax],al
  403e2f:	00 c4                	add    ah,al
  403e31:	11 40 00             	adc    DWORD PTR [rax+0x0],eax
  403e34:	00 00                	add    BYTE PTR [rax],al
  403e36:	00 00                	add    BYTE PTR [rax],al
  403e38:	19 00                	sbb    DWORD PTR [rax],eax
  403e3a:	00 00                	add    BYTE PTR [rax],al
  403e3c:	00 00                	add    BYTE PTR [rax],al
  403e3e:	00 00                	add    BYTE PTR [rax],al
  403e40:	f8                   	clc
  403e41:	3d 40 00 00 00       	cmp    eax,0x40
  403e46:	00 00                	add    BYTE PTR [rax],al
  403e48:	1b 00                	sbb    eax,DWORD PTR [rax]
  403e4a:	00 00                	add    BYTE PTR [rax],al
  403e4c:	00 00                	add    BYTE PTR [rax],al
  403e4e:	00 00                	add    BYTE PTR [rax],al
  403e50:	08 00                	or     BYTE PTR [rax],al
  403e52:	00 00                	add    BYTE PTR [rax],al
  403e54:	00 00                	add    BYTE PTR [rax],al
  403e56:	00 00                	add    BYTE PTR [rax],al
  403e58:	1a 00                	sbb    al,BYTE PTR [rax]
  403e5a:	00 00                	add    BYTE PTR [rax],al
  403e5c:	00 00                	add    BYTE PTR [rax],al
  403e5e:	00 00                	add    BYTE PTR [rax],al
  403e60:	00 3e                	add    BYTE PTR [rsi],bh
  403e62:	40 00 00             	rex add BYTE PTR [rax],al
  403e65:	00 00                	add    BYTE PTR [rax],al
  403e67:	00 1c 00             	add    BYTE PTR [rax+rax*1],bl
  403e6a:	00 00                	add    BYTE PTR [rax],al
  403e6c:	00 00                	add    BYTE PTR [rax],al
  403e6e:	00 00                	add    BYTE PTR [rax],al
  403e70:	08 00                	or     BYTE PTR [rax],al
  403e72:	00 00                	add    BYTE PTR [rax],al
  403e74:	00 00                	add    BYTE PTR [rax],al
  403e76:	00 00                	add    BYTE PTR [rax],al
  403e78:	f5                   	cmc
  403e79:	fe                   	(bad)
  403e7a:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
  403e7d:	00 00                	add    BYTE PTR [rax],al
  403e7f:	00 a0 03 40 00 00    	add    BYTE PTR [rax+0x4003],ah
  403e85:	00 00                	add    BYTE PTR [rax],al
  403e87:	00 05 00 00 00 00    	add    BYTE PTR [rip+0x0],al        # 403e8d <gets@plt+0x2e3d>
  403e8d:	00 00                	add    BYTE PTR [rax],al
  403e8f:	00 50 04             	add    BYTE PTR [rax+0x4],dl
  403e92:	40 00 00             	rex add BYTE PTR [rax],al
  403e95:	00 00                	add    BYTE PTR [rax],al
  403e97:	00 06                	add    BYTE PTR [rsi],al
  403e99:	00 00                	add    BYTE PTR [rax],al
  403e9b:	00 00                	add    BYTE PTR [rax],al
  403e9d:	00 00                	add    BYTE PTR [rax],al
  403e9f:	00 c0                	add    al,al
  403ea1:	03 40 00             	add    eax,DWORD PTR [rax+0x0]
  403ea4:	00 00                	add    BYTE PTR [rax],al
  403ea6:	00 00                	add    BYTE PTR [rax],al
  403ea8:	0a 00                	or     al,BYTE PTR [rax]
  403eaa:	00 00                	add    BYTE PTR [rax],al
  403eac:	00 00                	add    BYTE PTR [rax],al
  403eae:	00 00                	add    BYTE PTR [rax],al
  403eb0:	56                   	push   rsi
  403eb1:	00 00                	add    BYTE PTR [rax],al
  403eb3:	00 00                	add    BYTE PTR [rax],al
  403eb5:	00 00                	add    BYTE PTR [rax],al
  403eb7:	00 0b                	add    BYTE PTR [rbx],cl
  403eb9:	00 00                	add    BYTE PTR [rax],al
  403ebb:	00 00                	add    BYTE PTR [rax],al
  403ebd:	00 00                	add    BYTE PTR [rax],al
  403ebf:	00 18                	add    BYTE PTR [rax],bl
  403ec1:	00 00                	add    BYTE PTR [rax],al
  403ec3:	00 00                	add    BYTE PTR [rax],al
  403ec5:	00 00                	add    BYTE PTR [rax],al
  403ec7:	00 15 00 00 00 00    	add    BYTE PTR [rip+0x0],dl        # 403ecd <gets@plt+0x2e7d>
	...
  403ed5:	00 00                	add    BYTE PTR [rax],al
  403ed7:	00 03                	add    BYTE PTR [rbx],al
  403ed9:	00 00                	add    BYTE PTR [rax],al
  403edb:	00 00                	add    BYTE PTR [rax],al
  403edd:	00 00                	add    BYTE PTR [rax],al
  403edf:	00 e8                	add    al,ch
  403ee1:	3f                   	(bad)
  403ee2:	40 00 00             	rex add BYTE PTR [rax],al
  403ee5:	00 00                	add    BYTE PTR [rax],al
  403ee7:	00 02                	add    BYTE PTR [rdx],al
  403ee9:	00 00                	add    BYTE PTR [rax],al
  403eeb:	00 00                	add    BYTE PTR [rax],al
  403eed:	00 00                	add    BYTE PTR [rax],al
  403eef:	00 48 00             	add    BYTE PTR [rax+0x0],cl
  403ef2:	00 00                	add    BYTE PTR [rax],al
  403ef4:	00 00                	add    BYTE PTR [rax],al
  403ef6:	00 00                	add    BYTE PTR [rax],al
  403ef8:	14 00                	adc    al,0x0
  403efa:	00 00                	add    BYTE PTR [rax],al
  403efc:	00 00                	add    BYTE PTR [rax],al
  403efe:	00 00                	add    BYTE PTR [rax],al
  403f00:	07                   	(bad)
  403f01:	00 00                	add    BYTE PTR [rax],al
  403f03:	00 00                	add    BYTE PTR [rax],al
  403f05:	00 00                	add    BYTE PTR [rax],al
  403f07:	00 17                	add    BYTE PTR [rdi],dl
  403f09:	00 00                	add    BYTE PTR [rax],al
  403f0b:	00 00                	add    BYTE PTR [rax],al
  403f0d:	00 00                	add    BYTE PTR [rax],al
  403f0f:	00 18                	add    BYTE PTR [rax],bl
  403f11:	05 40 00 00 00       	add    eax,0x40
  403f16:	00 00                	add    BYTE PTR [rax],al
  403f18:	07                   	(bad)
  403f19:	00 00                	add    BYTE PTR [rax],al
  403f1b:	00 00                	add    BYTE PTR [rax],al
  403f1d:	00 00                	add    BYTE PTR [rax],al
  403f1f:	00 e8                	add    al,ch
  403f21:	04 40                	add    al,0x40
  403f23:	00 00                	add    BYTE PTR [rax],al
  403f25:	00 00                	add    BYTE PTR [rax],al
  403f27:	00 08                	add    BYTE PTR [rax],cl
  403f29:	00 00                	add    BYTE PTR [rax],al
  403f2b:	00 00                	add    BYTE PTR [rax],al
  403f2d:	00 00                	add    BYTE PTR [rax],al
  403f2f:	00 30                	add    BYTE PTR [rax],dh
  403f31:	00 00                	add    BYTE PTR [rax],al
  403f33:	00 00                	add    BYTE PTR [rax],al
  403f35:	00 00                	add    BYTE PTR [rax],al
  403f37:	00 09                	add    BYTE PTR [rcx],cl
  403f39:	00 00                	add    BYTE PTR [rax],al
  403f3b:	00 00                	add    BYTE PTR [rax],al
  403f3d:	00 00                	add    BYTE PTR [rax],al
  403f3f:	00 18                	add    BYTE PTR [rax],bl
  403f41:	00 00                	add    BYTE PTR [rax],al
  403f43:	00 00                	add    BYTE PTR [rax],al
  403f45:	00 00                	add    BYTE PTR [rax],al
  403f47:	00 fe                	add    dh,bh
  403f49:	ff                   	(bad)
  403f4a:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
  403f4d:	00 00                	add    BYTE PTR [rax],al
  403f4f:	00 b8 04 40 00 00    	add    BYTE PTR [rax+0x4004],bh
  403f55:	00 00                	add    BYTE PTR [rax],al
  403f57:	00 ff                	add    bh,bh
  403f59:	ff                   	(bad)
  403f5a:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
  403f5d:	00 00                	add    BYTE PTR [rax],al
  403f5f:	00 01                	add    BYTE PTR [rcx],al
  403f61:	00 00                	add    BYTE PTR [rax],al
  403f63:	00 00                	add    BYTE PTR [rax],al
  403f65:	00 00                	add    BYTE PTR [rax],al
  403f67:	00 f0                	add    al,dh
  403f69:	ff                   	(bad)
  403f6a:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
  403f6d:	00 00                	add    BYTE PTR [rax],al
  403f6f:	00 a6 04 40 00 00    	add    BYTE PTR [rsi+0x4004],ah
	...

Disassembly of section .got:

0000000000403fd8 <.got>:
	...
			403fd8: R_X86_64_GLOB_DAT	__libc_start_main@GLIBC_2.34
			403fe0: R_X86_64_GLOB_DAT	__gmon_start__@Base

Disassembly of section .got.plt:

0000000000403fe8 <.got.plt>:
  403fe8:	08 3e                	or     BYTE PTR [rsi],bh
  403fea:	40 00 00             	rex add BYTE PTR [rax],al
	...
  403ffd:	00 00                	add    BYTE PTR [rax],al
  403fff:	00 36                	add    BYTE PTR [rsi],dh
			404000: *unknown*	printf@GLIBC_2.2.5
  404001:	10 40 00             	adc    BYTE PTR [rax+0x0],al
  404004:	00 00                	add    BYTE PTR [rax],al
  404006:	00 00                	add    BYTE PTR [rax],al
  404008:	46 10 40 00          	rex.RX adc BYTE PTR [rax+0x0],r8b
			404008: *unknown*	execve@GLIBC_2.2.5
  40400c:	00 00                	add    BYTE PTR [rax],al
  40400e:	00 00                	add    BYTE PTR [rax],al
  404010:	56                   	push   rsi
			404010: *unknown*	gets@GLIBC_2.2.5
  404011:	10 40 00             	adc    BYTE PTR [rax+0x0],al
  404014:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .data:

0000000000404018 <.data>:
	...

Disassembly of section .comment:

0000000000000000 <.comment>:
   0:	47                   	rex.RXB
   1:	43                   	rex.XB
   2:	43 3a 20             	rex.XB cmp spl,BYTE PTR [r8]
   5:	28 55 62             	sub    BYTE PTR [rbp+0x62],dl
   8:	75 6e                	jne    78 <printf@plt-0x400fb8>
   a:	74 75                	je     81 <printf@plt-0x400faf>
   c:	20 31                	and    BYTE PTR [rcx],dh
   e:	34 2e                	xor    al,0x2e
  10:	32 2e                	xor    ch,BYTE PTR [rsi]
  12:	30 2d 34 75 62 75    	xor    BYTE PTR [rip+0x75627534],ch        # 7562754c <gets@plt+0x752264fc>
  18:	6e                   	outs   dx,BYTE PTR ds:[rsi]
  19:	74 75                	je     90 <printf@plt-0x400fa0>
  1b:	32 7e 32             	xor    bh,BYTE PTR [rsi+0x32]
  1e:	34 2e                	xor    al,0x2e
  20:	30 34 29             	xor    BYTE PTR [rcx+rbp*1],dh
  23:	20 31                	and    BYTE PTR [rcx],dh
  25:	34 2e                	xor    al,0x2e
  27:	32 2e                	xor    ch,BYTE PTR [rsi]
  29:	30 00                	xor    BYTE PTR [rax],al
  2b:	55                   	push   rbp
  2c:	62 75 6e 74 75       	(bad)
  31:	20 63 6c             	and    BYTE PTR [rbx+0x6c],ah
  34:	61                   	(bad)
  35:	6e                   	outs   dx,BYTE PTR ds:[rsi]
  36:	67 20 76 65          	and    BYTE PTR [esi+0x65],dh
  3a:	72 73                	jb     af <printf@plt-0x400f81>
  3c:	69 6f 6e 20 31 38 2e 	imul   ebp,DWORD PTR [rdi+0x6e],0x2e383120
  43:	31 2e                	xor    DWORD PTR [rsi],ebp
  45:	33 20                	xor    esp,DWORD PTR [rax]
  47:	28 31                	sub    BYTE PTR [rcx],dh
  49:	75 62                	jne    ad <printf@plt-0x400f83>
  4b:	75 6e                	jne    bb <printf@plt-0x400f75>
  4d:	74 75                	je     c4 <printf@plt-0x400f6c>
  4f:	31 29                	xor    DWORD PTR [rcx],ebp
	...
