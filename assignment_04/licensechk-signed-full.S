
licensechk-signed:     file format elf64-x86-64
licensechk-signed
architecture: i386:x86-64, flags 0x00000150:
HAS_SYMS, DYNAMIC, D_PAGED
start address 0x00000000000010e0

Program Header:
    PHDR off    0x0000000000000040 vaddr 0x0000000000000040 paddr 0x0000000000000040 align 2**3
         filesz 0x00000000000002d8 memsz 0x00000000000002d8 flags r--
  INTERP off    0x0000000000000318 vaddr 0x0000000000000318 paddr 0x0000000000000318 align 2**0
         filesz 0x000000000000001c memsz 0x000000000000001c flags r--
    LOAD off    0x0000000000000000 vaddr 0x0000000000000000 paddr 0x0000000000000000 align 2**12
         filesz 0x0000000000000780 memsz 0x0000000000000780 flags r--
    LOAD off    0x0000000000001000 vaddr 0x0000000000001000 paddr 0x0000000000001000 align 2**12
         filesz 0x0000000000000331 memsz 0x0000000000000331 flags r-x
    LOAD off    0x0000000000002000 vaddr 0x0000000000002000 paddr 0x0000000000002000 align 2**12
         filesz 0x00000000000001c4 memsz 0x00000000000001c4 flags r--
    LOAD off    0x0000000000002d88 vaddr 0x0000000000003d88 paddr 0x0000000000003d88 align 2**12
         filesz 0x0000000000000290 memsz 0x0000000000000298 flags rw-
 DYNAMIC off    0x0000000000002d98 vaddr 0x0000000000003d98 paddr 0x0000000000003d98 align 2**3
         filesz 0x0000000000000200 memsz 0x0000000000000200 flags rw-
    NOTE off    0x0000000000000338 vaddr 0x0000000000000338 paddr 0x0000000000000338 align 2**3
         filesz 0x0000000000000030 memsz 0x0000000000000030 flags r--
    NOTE off    0x0000000000000368 vaddr 0x0000000000000368 paddr 0x0000000000000368 align 2**2
         filesz 0x0000000000000044 memsz 0x0000000000000044 flags r--
0x6474e553 off    0x0000000000000338 vaddr 0x0000000000000338 paddr 0x0000000000000338 align 2**3
         filesz 0x0000000000000030 memsz 0x0000000000000030 flags r--
EH_FRAME off    0x000000000000206c vaddr 0x000000000000206c paddr 0x000000000000206c align 2**2
         filesz 0x000000000000004c memsz 0x000000000000004c flags r--
   STACK off    0x0000000000000000 vaddr 0x0000000000000000 paddr 0x0000000000000000 align 2**4
         filesz 0x0000000000000000 memsz 0x0000000000000000 flags rw-
   RELRO off    0x0000000000002d88 vaddr 0x0000000000003d88 paddr 0x0000000000003d88 align 2**0
         filesz 0x0000000000000278 memsz 0x0000000000000278 flags r--

Dynamic Section:
  NEEDED               libgrading.so
  NEEDED               libc.so.6
  INIT                 0x0000000000001000
  FINI                 0x0000000000001324
  INIT_ARRAY           0x0000000000003d88
  INIT_ARRAYSZ         0x0000000000000008
  FINI_ARRAY           0x0000000000003d90
  FINI_ARRAYSZ         0x0000000000000008
  GNU_HASH             0x00000000000003b0
  STRTAB               0x00000000000004e0
  SYMTAB               0x00000000000003d8
  STRSZ                0x00000000000000e7
  SYMENT               0x0000000000000018
  DEBUG                0x0000000000000000
  PLTGOT               0x0000000000003f98
  PLTRELSZ             0x0000000000000078
  PLTREL               0x0000000000000007
  JMPREL               0x0000000000000708
  RELA                 0x0000000000000630
  RELASZ               0x00000000000000d8
  RELAENT              0x0000000000000018
  FLAGS                0x0000000000000008
  FLAGS_1              0x0000000008000001
  VERNEED              0x00000000000005e0
  VERNEEDNUM           0x0000000000000001
  VERSYM               0x00000000000005c8
  RELACOUNT            0x0000000000000004

Version References:
  required from libc.so.6:
    0x0d696917 0x00 05 GLIBC_2.7
    0x0d696914 0x00 04 GLIBC_2.4
    0x09691a75 0x00 03 GLIBC_2.2.5
    0x069691b4 0x00 02 GLIBC_2.34

Sections:
Idx Name          Size      VMA               LMA               File off  Algn
  0 .interp       0000001c  0000000000000318  0000000000000318  00000318  2**0
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  1 .note.gnu.property 00000030  0000000000000338  0000000000000338  00000338  2**3
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  2 .note.gnu.build-id 00000024  0000000000000368  0000000000000368  00000368  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  3 .note.ABI-tag 00000020  000000000000038c  000000000000038c  0000038c  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  4 .gnu.hash     00000024  00000000000003b0  00000000000003b0  000003b0  2**3
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  5 .dynsym       00000108  00000000000003d8  00000000000003d8  000003d8  2**3
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  6 .dynstr       000000e7  00000000000004e0  00000000000004e0  000004e0  2**0
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  7 .gnu.version  00000016  00000000000005c8  00000000000005c8  000005c8  2**1
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  8 .gnu.version_r 00000050  00000000000005e0  00000000000005e0  000005e0  2**3
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  9 .rela.dyn     000000d8  0000000000000630  0000000000000630  00000630  2**3
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
 10 .rela.plt     00000078  0000000000000708  0000000000000708  00000708  2**3
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
 11 .init         0000001b  0000000000001000  0000000000001000  00001000  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
 12 .plt          00000060  0000000000001020  0000000000001020  00001020  2**4
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
 13 .plt.got      00000010  0000000000001080  0000000000001080  00001080  2**4
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
 14 .plt.sec      00000050  0000000000001090  0000000000001090  00001090  2**4
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
 15 .text         00000242  00000000000010e0  00000000000010e0  000010e0  2**4
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
 16 .fini         0000000d  0000000000001324  0000000000001324  00001324  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
 17 .rodata       0000006b  0000000000002000  0000000000002000  00002000  2**3
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
 18 .eh_frame_hdr 0000004c  000000000000206c  000000000000206c  0000206c  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
 19 .eh_frame     0000010c  00000000000020b8  00000000000020b8  000020b8  2**3
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
 20 .init_array   00000008  0000000000003d88  0000000000003d88  00002d88  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 21 .fini_array   00000008  0000000000003d90  0000000000003d90  00002d90  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 22 .dynamic      00000200  0000000000003d98  0000000000003d98  00002d98  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 23 .got          00000068  0000000000003f98  0000000000003f98  00002f98  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 24 .data         00000018  0000000000004000  0000000000004000  00003000  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 25 .bss          00000008  0000000000004018  0000000000004018  00003018  2**0
                  ALLOC
 26 .comment      0000002b  0000000000000000  0000000000000000  00003018  2**0
                  CONTENTS, READONLY
 27 .signature    00000100  0000000000000000  0000000000000000  00003043  2**0
                  CONTENTS, READONLY
SYMBOL TABLE:
0000000000000000 l    df *ABS*	0000000000000000              Scrt1.o
000000000000038c l     O .note.ABI-tag	0000000000000020              __abi_tag
0000000000000000 l    df *ABS*	0000000000000000              crtstuff.c
0000000000001110 l     F .text	0000000000000000              deregister_tm_clones
0000000000001140 l     F .text	0000000000000000              register_tm_clones
0000000000001180 l     F .text	0000000000000000              __do_global_dtors_aux
0000000000004018 l     O .bss	0000000000000001              completed.0
0000000000003d90 l     O .fini_array	0000000000000000              __do_global_dtors_aux_fini_array_entry
00000000000011c0 l     F .text	0000000000000000              frame_dummy
0000000000003d88 l     O .init_array	0000000000000000              __frame_dummy_init_array_entry
0000000000000000 l    df *ABS*	0000000000000000              license.c
0000000000000000 l    df *ABS*	0000000000000000              licensechk.c
0000000000000000 l    df *ABS*	0000000000000000              crtstuff.c
00000000000021c0 l     O .eh_frame	0000000000000000              __FRAME_END__
0000000000000000 l    df *ABS*	0000000000000000              
0000000000003d98 l     O .dynamic	0000000000000000              _DYNAMIC
000000000000206c l       .eh_frame_hdr	0000000000000000              __GNU_EH_FRAME_HDR
0000000000003f98 l     O .got	0000000000000000              _GLOBAL_OFFSET_TABLE_
0000000000000000       F *UND*	0000000000000000              __libc_start_main@GLIBC_2.34
0000000000000000  w      *UND*	0000000000000000              _ITM_deregisterTMCloneTable
0000000000004000  w      .data	0000000000000000              data_start
0000000000000000       F *UND*	0000000000000000              puts@GLIBC_2.2.5
00000000000011c9 g     F .text	000000000000003c              do_license_check_v1
0000000000004018 g       .data	0000000000000000              _edata
0000000000001324 g     F .fini	0000000000000000              .hidden _fini
0000000000000000       F *UND*	0000000000000000              __stack_chk_fail@GLIBC_2.4
0000000000000000       F *UND*	0000000000000000              license_check_ok
000000000000130b g     F .text	0000000000000017              do_nothing
0000000000004000 g       .data	0000000000000000              __data_start
0000000000000000       F *UND*	0000000000000000              strcmp@GLIBC_2.2.5
0000000000000000  w      *UND*	0000000000000000              __gmon_start__
0000000000004008 g     O .data	0000000000000000              .hidden __dso_handle
0000000000002000 g     O .rodata	0000000000000004              _IO_stdin_used
0000000000004020 g       .bss	0000000000000000              _end
00000000000010e0 g     F .text	0000000000000026              _start
0000000000001205 g     F .text	000000000000003c              do_license_check_v2
0000000000004018 g       .bss	0000000000000000              __bss_start
0000000000001241 g     F .text	00000000000000ca              main
0000000000004010 g     O .data	0000000000000008              check_license
0000000000000000       F *UND*	0000000000000000              __isoc99_scanf@GLIBC_2.7
0000000000004018 g     O .data	0000000000000000              .hidden __TMC_END__
0000000000000000  w      *UND*	0000000000000000              _ITM_registerTMCloneTable
0000000000000000  w    F *UND*	0000000000000000              __cxa_finalize@GLIBC_2.2.5
0000000000001000 g     F .init	0000000000000000              .hidden _init


Contents of section .interp:
 0318 2f6c6962 36342f6c 642d6c69 6e75782d  /lib64/ld-linux-
 0328 7838362d 36342e73 6f2e3200           x86-64.so.2.    
Contents of section .note.gnu.property:
 0338 04000000 20000000 05000000 474e5500  .... .......GNU.
 0348 020000c0 04000000 03000000 00000000  ................
 0358 028000c0 04000000 01000000 00000000  ................
Contents of section .note.gnu.build-id:
 0368 04000000 14000000 03000000 474e5500  ............GNU.
 0378 07a090e3 e36baf98 48db3d00 aa840466  .....k..H.=....f
 0388 6831491a                             h1I.            
Contents of section .note.ABI-tag:
 038c 04000000 10000000 01000000 474e5500  ............GNU.
 039c 00000000 03000000 02000000 00000000  ................
Contents of section .gnu.hash:
 03b0 02000000 0a000000 01000000 06000000  ................
 03c0 00008100 00000000 0a000000 00000000  ................
 03d0 d165ce6d                             .e.m            
Contents of section .dynsym:
 03d8 00000000 00000000 00000000 00000000  ................
 03e8 00000000 00000000 6d000000 12000000  ........m.......
 03f8 00000000 00000000 00000000 00000000  ................
 0408 01000000 20000000 00000000 00000000  .... ...........
 0418 00000000 00000000 57000000 12000000  ........W.......
 0428 00000000 00000000 00000000 00000000  ................
 0438 5c000000 12000000 00000000 00000000  \...............
 0448 00000000 00000000 46000000 12000000  ........F.......
 0458 00000000 00000000 00000000 00000000  ................
 0468 9d000000 12000000 00000000 00000000  ................
 0478 00000000 00000000 1d000000 20000000  ............ ...
 0488 00000000 00000000 00000000 00000000  ................
 0498 8e000000 12000000 00000000 00000000  ................
 04a8 00000000 00000000 2c000000 20000000  ........,... ...
 04b8 00000000 00000000 00000000 00000000  ................
 04c8 7f000000 22000000 00000000 00000000  ...."...........
 04d8 00000000 00000000                    ........        
Contents of section .dynstr:
 04e0 005f4954 4d5f6465 72656769 73746572  ._ITM_deregister
 04f0 544d436c 6f6e6554 61626c65 005f5f67  TMCloneTable.__g
 0500 6d6f6e5f 73746172 745f5f00 5f49544d  mon_start__._ITM
 0510 5f726567 69737465 72544d43 6c6f6e65  _registerTMClone
 0520 5461626c 65006c69 63656e73 655f6368  Table.license_ch
 0530 65636b5f 6f6b0070 75747300 5f5f7374  eck_ok.puts.__st
 0540 61636b5f 63686b5f 6661696c 005f5f6c  ack_chk_fail.__l
 0550 6962635f 73746172 745f6d61 696e005f  ibc_start_main._
 0560 5f637861 5f66696e 616c697a 65005f5f  _cxa_finalize.__
 0570 69736f63 39395f73 63616e66 00737472  isoc99_scanf.str
 0580 636d7000 6c696267 72616469 6e672e73  cmp.libgrading.s
 0590 6f006c69 62632e73 6f2e3600 474c4942  o.libc.so.6.GLIB
 05a0 435f322e 3700474c 4942435f 322e3400  C_2.7.GLIBC_2.4.
 05b0 474c4942 435f322e 322e3500 474c4942  GLIBC_2.2.5.GLIB
 05c0 435f322e 333400                      C_2.34.         
Contents of section .gnu.version:
 05c8 00000200 01000300 04000100 03000100  ................
 05d8 05000100 0300                        ......          
Contents of section .gnu.version_r:
 05e0 01000400 b2000000 10000000 00000000  ................
 05f0 1769690d 00000500 bc000000 10000000  .ii.............
 0600 1469690d 00000400 c6000000 10000000  .ii.............
 0610 751a6909 00000300 d0000000 10000000  u.i.............
 0620 b4919606 00000200 dc000000 00000000  ................
Contents of section .rela.dyn:
 0630 883d0000 00000000 08000000 00000000  .=..............
 0640 c0110000 00000000 903d0000 00000000  .........=......
 0650 08000000 00000000 80110000 00000000  ................
 0660 08400000 00000000 08000000 00000000  .@..............
 0670 08400000 00000000 10400000 00000000  .@.......@......
 0680 08000000 00000000 05120000 00000000  ................
 0690 d83f0000 00000000 06000000 01000000  .?..............
 06a0 00000000 00000000 e03f0000 00000000  .........?......
 06b0 06000000 02000000 00000000 00000000  ................
 06c0 e83f0000 00000000 06000000 07000000  .?..............
 06d0 00000000 00000000 f03f0000 00000000  .........?......
 06e0 06000000 09000000 00000000 00000000  ................
 06f0 f83f0000 00000000 06000000 0a000000  .?..............
 0700 00000000 00000000                    ........        
Contents of section .rela.plt:
 0708 b03f0000 00000000 07000000 03000000  .?..............
 0718 00000000 00000000 b83f0000 00000000  .........?......
 0728 07000000 04000000 00000000 00000000  ................
 0738 c03f0000 00000000 07000000 05000000  .?..............
 0748 00000000 00000000 c83f0000 00000000  .........?......
 0758 07000000 06000000 00000000 00000000  ................
 0768 d03f0000 00000000 07000000 08000000  .?..............
 0778 00000000 00000000                    ........        
Contents of section .init:
 1000 f30f1efa 4883ec08 488b05d9 2f000048  ....H...H.../..H
 1010 85c07402 ffd04883 c408c3             ..t...H....     
Contents of section .plt:
 1020 ff357a2f 0000ff25 7c2f0000 0f1f4000  .5z/...%|/....@.
 1030 f30f1efa 68000000 00e9e2ff ffff6690  ....h.........f.
 1040 f30f1efa 68010000 00e9d2ff ffff6690  ....h.........f.
 1050 f30f1efa 68020000 00e9c2ff ffff6690  ....h.........f.
 1060 f30f1efa 68030000 00e9b2ff ffff6690  ....h.........f.
 1070 f30f1efa 68040000 00e9a2ff ffff6690  ....h.........f.
Contents of section .plt.got:
 1080 f30f1efa ff256e2f 0000660f 1f440000  .....%n/..f..D..
Contents of section .plt.sec:
 1090 f30f1efa ff25162f 0000660f 1f440000  .....%./..f..D..
 10a0 f30f1efa ff250e2f 0000660f 1f440000  .....%./..f..D..
 10b0 f30f1efa ff25062f 0000660f 1f440000  .....%./..f..D..
 10c0 f30f1efa ff25fe2e 0000660f 1f440000  .....%....f..D..
 10d0 f30f1efa ff25f62e 0000660f 1f440000  .....%....f..D..
Contents of section .text:
 10e0 f30f1efa 31ed4989 d15e4889 e24883e4  ....1.I..^H..H..
 10f0 f0505445 31c031c9 488d3d42 010000ff  .PTE1.1.H.=B....
 1100 15d32e00 00f4662e 0f1f8400 00000000  ......f.........
 1110 488d3d01 2f000048 8d05fa2e 00004839  H.=./..H......H9
 1120 f8741548 8b05b62e 00004885 c07409ff  .t.H......H..t..
 1130 e00f1f80 00000000 c30f1f80 00000000  ................
 1140 488d3dd1 2e000048 8d35ca2e 00004829  H.=....H.5....H)
 1150 fe4889f0 48c1ee3f 48c1f803 4801c648  .H..H..?H...H..H
 1160 d1fe7414 488b0585 2e000048 85c07408  ..t.H......H..t.
 1170 ffe0660f 1f440000 c30f1f80 00000000  ..f..D..........
 1180 f30f1efa 803d8d2e 00000075 2b554883  .....=.....u+UH.
 1190 3d622e00 00004889 e5740c48 8b3d662e  =b....H..t.H.=f.
 11a0 0000e8d9 feffffe8 64ffffff c605652e  ........d.....e.
 11b0 0000015d c30f1f00 c30f1f80 00000000  ...]............
 11c0 f30f1efa e977ffff fff30f1e fa554889  .....w.......UH.
 11d0 e54883ec 1048897d f8488975 f0488b45  .H...H.}.H.u.H.E
 11e0 f84889c6 488d0519 0e000048 89c7e8cd  .H..H......H....
 11f0 feffff85 c07407b8 ffffffff eb05b800  .....t..........
 1200 000000c9 c3f30f1e fa554889 e54883ec  .........UH..H..
 1210 1048897d f8488975 f0488b45 f84889c6  .H.}.H.u.H.E.H..
 1220 488d05f7 0d000048 89c7e891 feffff85  H......H........
 1230 c07407b8 ffffffff eb05b800 000000c9  .t..............
 1240 c3f30f1e fa554889 e54883ec 50897dbc  .....UH..H..P.}.
 1250 488975b0 64488b04 25280000 00488945  H.u.dH..%(...H.E
 1260 f831c048 8d05ce0d 00004889 c7e81efe  .1.H......H.....
 1270 ffff48c7 45d00000 000048c7 45d80000  ..H.E.....H.E...
 1280 000048c7 45e00000 000048c7 45e80000  ..H.E.....H.E...
 1290 0000488d 45d04889 c6488d05 b80d0000  ..H.E.H..H......
 12a0 4889c7b8 00000000 e823feff ff488b15  H........#...H..
 12b0 5c2d0000 488d45d0 be200000 004889c7  \-..H.E.. ...H..
 12c0 ffd28945 cc837dcc 00741148 8d058b0d  ...E..}..t.H....
 12d0 00004889 c7e8b6fd ffffeb14 488d0582  ..H.........H...
 12e0 0d000048 89c7e8a5 fdffffe8 c0fdffff  ...H............
 12f0 b8000000 00488b55 f864482b 14252800  .....H.U.dH+.%(.
 1300 00007405 e897fdff ffc9c3f3 0f1efa55  ..t............U
 1310 4889e548 897df848 8975f0b8 00000000  H..H.}.H.u......
 1320 5dc3                                 ].              
Contents of section .fini:
 1324 f30f1efa 4883ec08 4883c408 c3        ....H...H....   
Contents of section .rodata:
 2000 01000200 74686973 5f69735f 615f7661  ....this_is_a_va
 2010 6c69645f 6c696365 6e73655f 31007468  lid_license_1.th
 2020 69735f69 735f615f 76616c69 645f6c69  is_is_a_valid_li
 2030 63656e73 655f3200 506c6561 73652065  cense_2.Please e
 2040 6e746572 206c6963 656e7365 20636f64  nter license cod
 2050 65202876 32293a00 25333073 00494e56  e (v2):.%30s.INV
 2060 414c4944 0056414c 494400             ALID.VALID.     
Contents of section .eh_frame_hdr:
 206c 011b033b 48000000 08000000 b4efffff  ...;H...........
 207c 7c000000 14f0ffff a4000000 24f0ffff  |...........$...
 208c bc000000 74f0ffff 64000000 5df1ffff  ....t...d...]...
 209c d4000000 99f1ffff f4000000 d5f1ffff  ................
 20ac 14010000 9ff2ffff 34010000           ........4...    
Contents of section .eh_frame:
 20b8 14000000 00000000 017a5200 01781001  .........zR..x..
 20c8 1b0c0708 90010000 14000000 1c000000  ................
 20d8 08f0ffff 26000000 00440710 00000000  ....&....D......
 20e8 24000000 34000000 30efffff 60000000  $...4...0...`...
 20f8 000e1046 0e184a0f 0b770880 003f1a39  ...F..J..w...?.9
 2108 2a332422 00000000 14000000 5c000000  *3$"........\...
 2118 68efffff 10000000 00000000 00000000  h...............
 2128 14000000 74000000 60efffff 50000000  ....t...`...P...
 2138 00000000 00000000 1c000000 8c000000  ................
 2148 81f0ffff 3c000000 00450e10 8602430d  ....<....E....C.
 2158 06730c07 08000000 1c000000 ac000000  .s..............
 2168 9df0ffff 3c000000 00450e10 8602430d  ....<....E....C.
 2178 06730c07 08000000 1c000000 cc000000  .s..............
 2188 b9f0ffff ca000000 00450e10 8602430d  .........E....C.
 2198 0602c10c 07080000 1c000000 ec000000  ................
 21a8 63f1ffff 17000000 00450e10 8602430d  c........E....C.
 21b8 064e0c07 08000000 00000000           .N..........    
Contents of section .init_array:
 3d88 c0110000 00000000                    ........        
Contents of section .fini_array:
 3d90 80110000 00000000                    ........        
Contents of section .dynamic:
 3d98 01000000 00000000 a4000000 00000000  ................
 3da8 01000000 00000000 b2000000 00000000  ................
 3db8 0c000000 00000000 00100000 00000000  ................
 3dc8 0d000000 00000000 24130000 00000000  ........$.......
 3dd8 19000000 00000000 883d0000 00000000  .........=......
 3de8 1b000000 00000000 08000000 00000000  ................
 3df8 1a000000 00000000 903d0000 00000000  .........=......
 3e08 1c000000 00000000 08000000 00000000  ................
 3e18 f5feff6f 00000000 b0030000 00000000  ...o............
 3e28 05000000 00000000 e0040000 00000000  ................
 3e38 06000000 00000000 d8030000 00000000  ................
 3e48 0a000000 00000000 e7000000 00000000  ................
 3e58 0b000000 00000000 18000000 00000000  ................
 3e68 15000000 00000000 00000000 00000000  ................
 3e78 03000000 00000000 983f0000 00000000  .........?......
 3e88 02000000 00000000 78000000 00000000  ........x.......
 3e98 14000000 00000000 07000000 00000000  ................
 3ea8 17000000 00000000 08070000 00000000  ................
 3eb8 07000000 00000000 30060000 00000000  ........0.......
 3ec8 08000000 00000000 d8000000 00000000  ................
 3ed8 09000000 00000000 18000000 00000000  ................
 3ee8 1e000000 00000000 08000000 00000000  ................
 3ef8 fbffff6f 00000000 01000008 00000000  ...o............
 3f08 feffff6f 00000000 e0050000 00000000  ...o............
 3f18 ffffff6f 00000000 01000000 00000000  ...o............
 3f28 f0ffff6f 00000000 c8050000 00000000  ...o............
 3f38 f9ffff6f 00000000 04000000 00000000  ...o............
 3f48 00000000 00000000 00000000 00000000  ................
 3f58 00000000 00000000 00000000 00000000  ................
 3f68 00000000 00000000 00000000 00000000  ................
 3f78 00000000 00000000 00000000 00000000  ................
 3f88 00000000 00000000 00000000 00000000  ................
Contents of section .got:
 3f98 983d0000 00000000 00000000 00000000  .=..............
 3fa8 00000000 00000000 30100000 00000000  ........0.......
 3fb8 40100000 00000000 50100000 00000000  @.......P.......
 3fc8 60100000 00000000 70100000 00000000  `.......p.......
 3fd8 00000000 00000000 00000000 00000000  ................
 3fe8 00000000 00000000 00000000 00000000  ................
 3ff8 00000000 00000000                    ........        
Contents of section .data:
 4000 00000000 00000000 08400000 00000000  .........@......
 4010 05120000 00000000                    ........        
Contents of section .comment:
 0000 4743433a 20285562 756e7475 2031332e  GCC: (Ubuntu 13.
 0010 332e302d 36756275 6e747532 7e32342e  3.0-6ubuntu2~24.
 0020 30342920 31332e33 2e3000             04) 13.3.0.     
Contents of section .signature:
 0000 5c3b3cd4 5c0f3ed5 def2bc96 2f0b7b9d  \;<.\.>...../.{.
 0010 6963e009 3595b196 a482fcda f7bcdcb4  ic..5...........
 0020 e0ca281e 0bcb1091 5b13b979 41af0f70  ..(.....[..yA..p
 0030 542ed33b d58b4acd 44a25367 30224212  T..;..J.D.Sg0"B.
 0040 b31bae33 82469d8c e625d777 7df88e30  ...3.F...%.w}..0
 0050 0a2cdf31 9be44929 5dd1b35a f6cfd97c  .,.1..I)]..Z...|
 0060 231a5585 faf69357 21fbcd8d f051253b  #.U....W!....Q%;
 0070 6159626d 9841b13e 5b9e3733 8e3234d0  aYbm.A.>[.73.24.
 0080 637f9afb 9c5f1b38 67cf0834 0aff4751  c...._.8g..4..GQ
 0090 6da009f4 000eed3b 4f836576 53ea5f6d  m......;O.evS._m
 00a0 d524d751 737689fe 498471b5 a18a9742  .$.Qsv..I.q....B
 00b0 5e86d52e 8eac3d6e 72db0b65 ce079569  ^.....=nr..e...i
 00c0 f201ef00 f85fa56e ec9fe410 46a1b5c2  ....._.n....F...
 00d0 f106026f 4f56686c d1e74ad1 8e0e9de1  ...oOVhl..J.....
 00e0 643e6a82 43215e99 d987bc06 da1bbe45  d>j.C!^........E
 00f0 42125f80 eb7648eb 098953fe aebba00d  B._..vH...S.....

Disassembly of section .interp:

0000000000000318 <.interp>:
 318:	2f                   	(bad)
 319:	6c                   	insb   (%dx),%es:(%rdi)
 31a:	69 62 36 34 2f 6c 64 	imul   $0x646c2f34,0x36(%rdx),%esp
 321:	2d 6c 69 6e 75       	sub    $0x756e696c,%eax
 326:	78 2d                	js     355 <__abi_tag-0x37>
 328:	78 38                	js     362 <__abi_tag-0x2a>
 32a:	36 2d 36 34 2e 73    	ss sub $0x732e3436,%eax
 330:	6f                   	outsl  %ds:(%rsi),(%dx)
 331:	2e 32 00             	cs xor (%rax),%al

Disassembly of section .note.gnu.property:

0000000000000338 <.note.gnu.property>:
 338:	04 00                	add    $0x0,%al
 33a:	00 00                	add    %al,(%rax)
 33c:	20 00                	and    %al,(%rax)
 33e:	00 00                	add    %al,(%rax)
 340:	05 00 00 00 47       	add    $0x47000000,%eax
 345:	4e 55                	rex.WRX push %rbp
 347:	00 02                	add    %al,(%rdx)
 349:	00 00                	add    %al,(%rax)
 34b:	c0 04 00 00          	rolb   $0x0,(%rax,%rax,1)
 34f:	00 03                	add    %al,(%rbx)
 351:	00 00                	add    %al,(%rax)
 353:	00 00                	add    %al,(%rax)
 355:	00 00                	add    %al,(%rax)
 357:	00 02                	add    %al,(%rdx)
 359:	80 00 c0             	addb   $0xc0,(%rax)
 35c:	04 00                	add    $0x0,%al
 35e:	00 00                	add    %al,(%rax)
 360:	01 00                	add    %eax,(%rax)
 362:	00 00                	add    %al,(%rax)
 364:	00 00                	add    %al,(%rax)
	...

Disassembly of section .note.gnu.build-id:

0000000000000368 <.note.gnu.build-id>:
 368:	04 00                	add    $0x0,%al
 36a:	00 00                	add    %al,(%rax)
 36c:	14 00                	adc    $0x0,%al
 36e:	00 00                	add    %al,(%rax)
 370:	03 00                	add    (%rax),%eax
 372:	00 00                	add    %al,(%rax)
 374:	47                   	rex.RXB
 375:	4e 55                	rex.WRX push %rbp
 377:	00 07                	add    %al,(%rdi)
 379:	a0 90 e3 e3 6b af 98 	movabs 0xdb4898af6be3e390,%al
 380:	48 db 
 382:	3d 00 aa 84 04       	cmp    $0x484aa00,%eax
 387:	66 68 31 49          	pushw  $0x4931
 38b:	1a                   	.byte 0x1a

Disassembly of section .note.ABI-tag:

000000000000038c <__abi_tag>:
 38c:	04 00                	add    $0x0,%al
 38e:	00 00                	add    %al,(%rax)
 390:	10 00                	adc    %al,(%rax)
 392:	00 00                	add    %al,(%rax)
 394:	01 00                	add    %eax,(%rax)
 396:	00 00                	add    %al,(%rax)
 398:	47                   	rex.RXB
 399:	4e 55                	rex.WRX push %rbp
 39b:	00 00                	add    %al,(%rax)
 39d:	00 00                	add    %al,(%rax)
 39f:	00 03                	add    %al,(%rbx)
 3a1:	00 00                	add    %al,(%rax)
 3a3:	00 02                	add    %al,(%rdx)
 3a5:	00 00                	add    %al,(%rax)
 3a7:	00 00                	add    %al,(%rax)
 3a9:	00 00                	add    %al,(%rax)
	...

Disassembly of section .gnu.hash:

00000000000003b0 <.gnu.hash>:
 3b0:	02 00                	add    (%rax),%al
 3b2:	00 00                	add    %al,(%rax)
 3b4:	0a 00                	or     (%rax),%al
 3b6:	00 00                	add    %al,(%rax)
 3b8:	01 00                	add    %eax,(%rax)
 3ba:	00 00                	add    %al,(%rax)
 3bc:	06                   	(bad)
 3bd:	00 00                	add    %al,(%rax)
 3bf:	00 00                	add    %al,(%rax)
 3c1:	00 81 00 00 00 00    	add    %al,0x0(%rcx)
 3c7:	00 0a                	add    %cl,(%rdx)
 3c9:	00 00                	add    %al,(%rax)
 3cb:	00 00                	add    %al,(%rax)
 3cd:	00 00                	add    %al,(%rax)
 3cf:	00 d1                	add    %dl,%cl
 3d1:	65 ce                	gs (bad)
 3d3:	6d                   	insl   (%dx),%es:(%rdi)

Disassembly of section .dynsym:

00000000000003d8 <.dynsym>:
	...
 3f0:	6d                   	insl   (%dx),%es:(%rdi)
 3f1:	00 00                	add    %al,(%rax)
 3f3:	00 12                	add    %dl,(%rdx)
	...
 405:	00 00                	add    %al,(%rax)
 407:	00 01                	add    %al,(%rcx)
 409:	00 00                	add    %al,(%rax)
 40b:	00 20                	add    %ah,(%rax)
	...
 41d:	00 00                	add    %al,(%rax)
 41f:	00 57 00             	add    %dl,0x0(%rdi)
 422:	00 00                	add    %al,(%rax)
 424:	12 00                	adc    (%rax),%al
	...
 436:	00 00                	add    %al,(%rax)
 438:	5c                   	pop    %rsp
 439:	00 00                	add    %al,(%rax)
 43b:	00 12                	add    %dl,(%rdx)
	...
 44d:	00 00                	add    %al,(%rax)
 44f:	00 46 00             	add    %al,0x0(%rsi)
 452:	00 00                	add    %al,(%rax)
 454:	12 00                	adc    (%rax),%al
	...
 466:	00 00                	add    %al,(%rax)
 468:	9d                   	popf
 469:	00 00                	add    %al,(%rax)
 46b:	00 12                	add    %dl,(%rdx)
	...
 47d:	00 00                	add    %al,(%rax)
 47f:	00 1d 00 00 00 20    	add    %bl,0x20000000(%rip)        # 20000485 <_end+0x1fffc465>
	...
 495:	00 00                	add    %al,(%rax)
 497:	00 8e 00 00 00 12    	add    %cl,0x12000000(%rsi)
	...
 4ad:	00 00                	add    %al,(%rax)
 4af:	00 2c 00             	add    %ch,(%rax,%rax,1)
 4b2:	00 00                	add    %al,(%rax)
 4b4:	20 00                	and    %al,(%rax)
	...
 4c6:	00 00                	add    %al,(%rax)
 4c8:	7f 00                	jg     4ca <__abi_tag+0x13e>
 4ca:	00 00                	add    %al,(%rax)
 4cc:	22 00                	and    (%rax),%al
	...

Disassembly of section .dynstr:

00000000000004e0 <.dynstr>:
 4e0:	00 5f 49             	add    %bl,0x49(%rdi)
 4e3:	54                   	push   %rsp
 4e4:	4d 5f                	rex.WRB pop %r15
 4e6:	64 65 72 65          	fs gs jb 54f <__abi_tag+0x1c3>
 4ea:	67 69 73 74 65 72 54 	imul   $0x4d547265,0x74(%ebx),%esi
 4f1:	4d 
 4f2:	43 6c                	rex.XB insb (%dx),%es:(%rdi)
 4f4:	6f                   	outsl  %ds:(%rsi),(%dx)
 4f5:	6e                   	outsb  %ds:(%rsi),(%dx)
 4f6:	65 54                	gs push %rsp
 4f8:	61                   	(bad)
 4f9:	62 6c 65             	(bad)
 4fc:	00 5f 5f             	add    %bl,0x5f(%rdi)
 4ff:	67 6d                	insl   (%dx),%es:(%edi)
 501:	6f                   	outsl  %ds:(%rsi),(%dx)
 502:	6e                   	outsb  %ds:(%rsi),(%dx)
 503:	5f                   	pop    %rdi
 504:	73 74                	jae    57a <__abi_tag+0x1ee>
 506:	61                   	(bad)
 507:	72 74                	jb     57d <__abi_tag+0x1f1>
 509:	5f                   	pop    %rdi
 50a:	5f                   	pop    %rdi
 50b:	00 5f 49             	add    %bl,0x49(%rdi)
 50e:	54                   	push   %rsp
 50f:	4d 5f                	rex.WRB pop %r15
 511:	72 65                	jb     578 <__abi_tag+0x1ec>
 513:	67 69 73 74 65 72 54 	imul   $0x4d547265,0x74(%ebx),%esi
 51a:	4d 
 51b:	43 6c                	rex.XB insb (%dx),%es:(%rdi)
 51d:	6f                   	outsl  %ds:(%rsi),(%dx)
 51e:	6e                   	outsb  %ds:(%rsi),(%dx)
 51f:	65 54                	gs push %rsp
 521:	61                   	(bad)
 522:	62 6c 65             	(bad)
 525:	00 6c 69 63          	add    %ch,0x63(%rcx,%rbp,2)
 529:	65 6e                	outsb  %gs:(%rsi),(%dx)
 52b:	73 65                	jae    592 <__abi_tag+0x206>
 52d:	5f                   	pop    %rdi
 52e:	63 68 65             	movsxd 0x65(%rax),%ebp
 531:	63 6b 5f             	movsxd 0x5f(%rbx),%ebp
 534:	6f                   	outsl  %ds:(%rsi),(%dx)
 535:	6b 00 70             	imul   $0x70,(%rax),%eax
 538:	75 74                	jne    5ae <__abi_tag+0x222>
 53a:	73 00                	jae    53c <__abi_tag+0x1b0>
 53c:	5f                   	pop    %rdi
 53d:	5f                   	pop    %rdi
 53e:	73 74                	jae    5b4 <__abi_tag+0x228>
 540:	61                   	(bad)
 541:	63 6b 5f             	movsxd 0x5f(%rbx),%ebp
 544:	63 68 6b             	movsxd 0x6b(%rax),%ebp
 547:	5f                   	pop    %rdi
 548:	66 61                	data16 (bad)
 54a:	69 6c 00 5f 5f 6c 69 	imul   $0x62696c5f,0x5f(%rax,%rax,1),%ebp
 551:	62 
 552:	63 5f 73             	movsxd 0x73(%rdi),%ebx
 555:	74 61                	je     5b8 <__abi_tag+0x22c>
 557:	72 74                	jb     5cd <__abi_tag+0x241>
 559:	5f                   	pop    %rdi
 55a:	6d                   	insl   (%dx),%es:(%rdi)
 55b:	61                   	(bad)
 55c:	69 6e 00 5f 5f 63 78 	imul   $0x78635f5f,0x0(%rsi),%ebp
 563:	61                   	(bad)
 564:	5f                   	pop    %rdi
 565:	66 69 6e 61 6c 69    	imul   $0x696c,0x61(%rsi),%bp
 56b:	7a 65                	jp     5d2 <__abi_tag+0x246>
 56d:	00 5f 5f             	add    %bl,0x5f(%rdi)
 570:	69 73 6f 63 39 39 5f 	imul   $0x5f393963,0x6f(%rbx),%esi
 577:	73 63                	jae    5dc <__abi_tag+0x250>
 579:	61                   	(bad)
 57a:	6e                   	outsb  %ds:(%rsi),(%dx)
 57b:	66 00 73 74          	data16 add %dh,0x74(%rbx)
 57f:	72 63                	jb     5e4 <__abi_tag+0x258>
 581:	6d                   	insl   (%dx),%es:(%rdi)
 582:	70 00                	jo     584 <__abi_tag+0x1f8>
 584:	6c                   	insb   (%dx),%es:(%rdi)
 585:	69 62 67 72 61 64 69 	imul   $0x69646172,0x67(%rdx),%esp
 58c:	6e                   	outsb  %ds:(%rsi),(%dx)
 58d:	67 2e 73 6f          	addr32 jae,pn 600 <__abi_tag+0x274>
 591:	00 6c 69 62          	add    %ch,0x62(%rcx,%rbp,2)
 595:	63 2e                	movsxd (%rsi),%ebp
 597:	73 6f                	jae    608 <__abi_tag+0x27c>
 599:	2e 36 00 47 4c       	cs ss add %al,0x4c(%rdi)
 59e:	49                   	rex.WB
 59f:	42                   	rex.X
 5a0:	43 5f                	rex.XB pop %r15
 5a2:	32 2e                	xor    (%rsi),%ch
 5a4:	37                   	(bad)
 5a5:	00 47 4c             	add    %al,0x4c(%rdi)
 5a8:	49                   	rex.WB
 5a9:	42                   	rex.X
 5aa:	43 5f                	rex.XB pop %r15
 5ac:	32 2e                	xor    (%rsi),%ch
 5ae:	34 00                	xor    $0x0,%al
 5b0:	47                   	rex.RXB
 5b1:	4c                   	rex.WR
 5b2:	49                   	rex.WB
 5b3:	42                   	rex.X
 5b4:	43 5f                	rex.XB pop %r15
 5b6:	32 2e                	xor    (%rsi),%ch
 5b8:	32 2e                	xor    (%rsi),%ch
 5ba:	35 00 47 4c 49       	xor    $0x494c4700,%eax
 5bf:	42                   	rex.X
 5c0:	43 5f                	rex.XB pop %r15
 5c2:	32 2e                	xor    (%rsi),%ch
 5c4:	33 34 00             	xor    (%rax,%rax,1),%esi

Disassembly of section .gnu.version:

00000000000005c8 <.gnu.version>:
 5c8:	00 00                	add    %al,(%rax)
 5ca:	02 00                	add    (%rax),%al
 5cc:	01 00                	add    %eax,(%rax)
 5ce:	03 00                	add    (%rax),%eax
 5d0:	04 00                	add    $0x0,%al
 5d2:	01 00                	add    %eax,(%rax)
 5d4:	03 00                	add    (%rax),%eax
 5d6:	01 00                	add    %eax,(%rax)
 5d8:	05 00 01 00 03       	add    $0x3000100,%eax
	...

Disassembly of section .gnu.version_r:

00000000000005e0 <.gnu.version_r>:
 5e0:	01 00                	add    %eax,(%rax)
 5e2:	04 00                	add    $0x0,%al
 5e4:	b2 00                	mov    $0x0,%dl
 5e6:	00 00                	add    %al,(%rax)
 5e8:	10 00                	adc    %al,(%rax)
 5ea:	00 00                	add    %al,(%rax)
 5ec:	00 00                	add    %al,(%rax)
 5ee:	00 00                	add    %al,(%rax)
 5f0:	17                   	(bad)
 5f1:	69 69 0d 00 00 05 00 	imul   $0x50000,0xd(%rcx),%ebp
 5f8:	bc 00 00 00 10       	mov    $0x10000000,%esp
 5fd:	00 00                	add    %al,(%rax)
 5ff:	00 14 69             	add    %dl,(%rcx,%rbp,2)
 602:	69 0d 00 00 04 00 c6 	imul   $0xc6,0x40000(%rip),%ecx        # 4060c <_end+0x3c5ec>
 609:	00 00 00 
 60c:	10 00                	adc    %al,(%rax)
 60e:	00 00                	add    %al,(%rax)
 610:	75 1a                	jne    62c <__abi_tag+0x2a0>
 612:	69 09 00 00 03 00    	imul   $0x30000,(%rcx),%ecx
 618:	d0 00                	rolb   $1,(%rax)
 61a:	00 00                	add    %al,(%rax)
 61c:	10 00                	adc    %al,(%rax)
 61e:	00 00                	add    %al,(%rax)
 620:	b4 91                	mov    $0x91,%ah
 622:	96                   	xchg   %eax,%esi
 623:	06                   	(bad)
 624:	00 00                	add    %al,(%rax)
 626:	02 00                	add    (%rax),%al
 628:	dc 00                	faddl  (%rax)
 62a:	00 00                	add    %al,(%rax)
 62c:	00 00                	add    %al,(%rax)
	...

Disassembly of section .rela.dyn:

0000000000000630 <.rela.dyn>:
 630:	88 3d 00 00 00 00    	mov    %bh,0x0(%rip)        # 636 <__abi_tag+0x2aa>
 636:	00 00                	add    %al,(%rax)
 638:	08 00                	or     %al,(%rax)
 63a:	00 00                	add    %al,(%rax)
 63c:	00 00                	add    %al,(%rax)
 63e:	00 00                	add    %al,(%rax)
 640:	c0 11 00             	rclb   $0x0,(%rcx)
 643:	00 00                	add    %al,(%rax)
 645:	00 00                	add    %al,(%rax)
 647:	00 90 3d 00 00 00    	add    %dl,0x3d(%rax)
 64d:	00 00                	add    %al,(%rax)
 64f:	00 08                	add    %cl,(%rax)
 651:	00 00                	add    %al,(%rax)
 653:	00 00                	add    %al,(%rax)
 655:	00 00                	add    %al,(%rax)
 657:	00 80 11 00 00 00    	add    %al,0x11(%rax)
 65d:	00 00                	add    %al,(%rax)
 65f:	00 08                	add    %cl,(%rax)
 661:	40 00 00             	rex add %al,(%rax)
 664:	00 00                	add    %al,(%rax)
 666:	00 00                	add    %al,(%rax)
 668:	08 00                	or     %al,(%rax)
 66a:	00 00                	add    %al,(%rax)
 66c:	00 00                	add    %al,(%rax)
 66e:	00 00                	add    %al,(%rax)
 670:	08 40 00             	or     %al,0x0(%rax)
 673:	00 00                	add    %al,(%rax)
 675:	00 00                	add    %al,(%rax)
 677:	00 10                	add    %dl,(%rax)
 679:	40 00 00             	rex add %al,(%rax)
 67c:	00 00                	add    %al,(%rax)
 67e:	00 00                	add    %al,(%rax)
 680:	08 00                	or     %al,(%rax)
 682:	00 00                	add    %al,(%rax)
 684:	00 00                	add    %al,(%rax)
 686:	00 00                	add    %al,(%rax)
 688:	05 12 00 00 00       	add    $0x12,%eax
 68d:	00 00                	add    %al,(%rax)
 68f:	00 d8                	add    %bl,%al
 691:	3f                   	(bad)
 692:	00 00                	add    %al,(%rax)
 694:	00 00                	add    %al,(%rax)
 696:	00 00                	add    %al,(%rax)
 698:	06                   	(bad)
 699:	00 00                	add    %al,(%rax)
 69b:	00 01                	add    %al,(%rcx)
	...
 6a5:	00 00                	add    %al,(%rax)
 6a7:	00 e0                	add    %ah,%al
 6a9:	3f                   	(bad)
 6aa:	00 00                	add    %al,(%rax)
 6ac:	00 00                	add    %al,(%rax)
 6ae:	00 00                	add    %al,(%rax)
 6b0:	06                   	(bad)
 6b1:	00 00                	add    %al,(%rax)
 6b3:	00 02                	add    %al,(%rdx)
	...
 6bd:	00 00                	add    %al,(%rax)
 6bf:	00 e8                	add    %ch,%al
 6c1:	3f                   	(bad)
 6c2:	00 00                	add    %al,(%rax)
 6c4:	00 00                	add    %al,(%rax)
 6c6:	00 00                	add    %al,(%rax)
 6c8:	06                   	(bad)
 6c9:	00 00                	add    %al,(%rax)
 6cb:	00 07                	add    %al,(%rdi)
	...
 6d5:	00 00                	add    %al,(%rax)
 6d7:	00 f0                	add    %dh,%al
 6d9:	3f                   	(bad)
 6da:	00 00                	add    %al,(%rax)
 6dc:	00 00                	add    %al,(%rax)
 6de:	00 00                	add    %al,(%rax)
 6e0:	06                   	(bad)
 6e1:	00 00                	add    %al,(%rax)
 6e3:	00 09                	add    %cl,(%rcx)
	...
 6ed:	00 00                	add    %al,(%rax)
 6ef:	00 f8                	add    %bh,%al
 6f1:	3f                   	(bad)
 6f2:	00 00                	add    %al,(%rax)
 6f4:	00 00                	add    %al,(%rax)
 6f6:	00 00                	add    %al,(%rax)
 6f8:	06                   	(bad)
 6f9:	00 00                	add    %al,(%rax)
 6fb:	00 0a                	add    %cl,(%rdx)
	...

Disassembly of section .rela.plt:

0000000000000708 <.rela.plt>:
 708:	b0 3f                	mov    $0x3f,%al
 70a:	00 00                	add    %al,(%rax)
 70c:	00 00                	add    %al,(%rax)
 70e:	00 00                	add    %al,(%rax)
 710:	07                   	(bad)
 711:	00 00                	add    %al,(%rax)
 713:	00 03                	add    %al,(%rbx)
	...
 71d:	00 00                	add    %al,(%rax)
 71f:	00 b8 3f 00 00 00    	add    %bh,0x3f(%rax)
 725:	00 00                	add    %al,(%rax)
 727:	00 07                	add    %al,(%rdi)
 729:	00 00                	add    %al,(%rax)
 72b:	00 04 00             	add    %al,(%rax,%rax,1)
	...
 736:	00 00                	add    %al,(%rax)
 738:	c0 3f 00             	sarb   $0x0,(%rdi)
 73b:	00 00                	add    %al,(%rax)
 73d:	00 00                	add    %al,(%rax)
 73f:	00 07                	add    %al,(%rdi)
 741:	00 00                	add    %al,(%rax)
 743:	00 05 00 00 00 00    	add    %al,0x0(%rip)        # 749 <__abi_tag+0x3bd>
 749:	00 00                	add    %al,(%rax)
 74b:	00 00                	add    %al,(%rax)
 74d:	00 00                	add    %al,(%rax)
 74f:	00 c8                	add    %cl,%al
 751:	3f                   	(bad)
 752:	00 00                	add    %al,(%rax)
 754:	00 00                	add    %al,(%rax)
 756:	00 00                	add    %al,(%rax)
 758:	07                   	(bad)
 759:	00 00                	add    %al,(%rax)
 75b:	00 06                	add    %al,(%rsi)
	...
 765:	00 00                	add    %al,(%rax)
 767:	00 d0                	add    %dl,%al
 769:	3f                   	(bad)
 76a:	00 00                	add    %al,(%rax)
 76c:	00 00                	add    %al,(%rax)
 76e:	00 00                	add    %al,(%rax)
 770:	07                   	(bad)
 771:	00 00                	add    %al,(%rax)
 773:	00 08                	add    %cl,(%rax)
	...

Disassembly of section .init:

0000000000001000 <_init>:
    1000:	f3 0f 1e fa          	endbr64
    1004:	48 83 ec 08          	sub    $0x8,%rsp
    1008:	48 8b 05 d9 2f 00 00 	mov    0x2fd9(%rip),%rax        # 3fe8 <__gmon_start__@Base>
    100f:	48 85 c0             	test   %rax,%rax
    1012:	74 02                	je     1016 <_init+0x16>
    1014:	ff d0                	call   *%rax
    1016:	48 83 c4 08          	add    $0x8,%rsp
    101a:	c3                   	ret

Disassembly of section .plt:

0000000000001020 <.plt>:
    1020:	ff 35 7a 2f 00 00    	push   0x2f7a(%rip)        # 3fa0 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	ff 25 7c 2f 00 00    	jmp    *0x2f7c(%rip)        # 3fa8 <_GLOBAL_OFFSET_TABLE_+0x10>
    102c:	0f 1f 40 00          	nopl   0x0(%rax)
    1030:	f3 0f 1e fa          	endbr64
    1034:	68 00 00 00 00       	push   $0x0
    1039:	e9 e2 ff ff ff       	jmp    1020 <_init+0x20>
    103e:	66 90                	xchg   %ax,%ax
    1040:	f3 0f 1e fa          	endbr64
    1044:	68 01 00 00 00       	push   $0x1
    1049:	e9 d2 ff ff ff       	jmp    1020 <_init+0x20>
    104e:	66 90                	xchg   %ax,%ax
    1050:	f3 0f 1e fa          	endbr64
    1054:	68 02 00 00 00       	push   $0x2
    1059:	e9 c2 ff ff ff       	jmp    1020 <_init+0x20>
    105e:	66 90                	xchg   %ax,%ax
    1060:	f3 0f 1e fa          	endbr64
    1064:	68 03 00 00 00       	push   $0x3
    1069:	e9 b2 ff ff ff       	jmp    1020 <_init+0x20>
    106e:	66 90                	xchg   %ax,%ax
    1070:	f3 0f 1e fa          	endbr64
    1074:	68 04 00 00 00       	push   $0x4
    1079:	e9 a2 ff ff ff       	jmp    1020 <_init+0x20>
    107e:	66 90                	xchg   %ax,%ax

Disassembly of section .plt.got:

0000000000001080 <__cxa_finalize@plt>:
    1080:	f3 0f 1e fa          	endbr64
    1084:	ff 25 6e 2f 00 00    	jmp    *0x2f6e(%rip)        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    108a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

Disassembly of section .plt.sec:

0000000000001090 <puts@plt>:
    1090:	f3 0f 1e fa          	endbr64
    1094:	ff 25 16 2f 00 00    	jmp    *0x2f16(%rip)        # 3fb0 <puts@GLIBC_2.2.5>
    109a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

00000000000010a0 <__stack_chk_fail@plt>:
    10a0:	f3 0f 1e fa          	endbr64
    10a4:	ff 25 0e 2f 00 00    	jmp    *0x2f0e(%rip)        # 3fb8 <__stack_chk_fail@GLIBC_2.4>
    10aa:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

00000000000010b0 <license_check_ok@plt>:
    10b0:	f3 0f 1e fa          	endbr64
    10b4:	ff 25 06 2f 00 00    	jmp    *0x2f06(%rip)        # 3fc0 <license_check_ok@Base>
    10ba:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

00000000000010c0 <strcmp@plt>:
    10c0:	f3 0f 1e fa          	endbr64
    10c4:	ff 25 fe 2e 00 00    	jmp    *0x2efe(%rip)        # 3fc8 <strcmp@GLIBC_2.2.5>
    10ca:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

00000000000010d0 <__isoc99_scanf@plt>:
    10d0:	f3 0f 1e fa          	endbr64
    10d4:	ff 25 f6 2e 00 00    	jmp    *0x2ef6(%rip)        # 3fd0 <__isoc99_scanf@GLIBC_2.7>
    10da:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

Disassembly of section .text:

00000000000010e0 <_start>:
    10e0:	f3 0f 1e fa          	endbr64
    10e4:	31 ed                	xor    %ebp,%ebp
    10e6:	49 89 d1             	mov    %rdx,%r9
    10e9:	5e                   	pop    %rsi
    10ea:	48 89 e2             	mov    %rsp,%rdx
    10ed:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
    10f1:	50                   	push   %rax
    10f2:	54                   	push   %rsp
    10f3:	45 31 c0             	xor    %r8d,%r8d
    10f6:	31 c9                	xor    %ecx,%ecx
    10f8:	48 8d 3d 42 01 00 00 	lea    0x142(%rip),%rdi        # 1241 <main>
    10ff:	ff 15 d3 2e 00 00    	call   *0x2ed3(%rip)        # 3fd8 <__libc_start_main@GLIBC_2.34>
    1105:	f4                   	hlt
    1106:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
    110d:	00 00 00 

0000000000001110 <deregister_tm_clones>:
    1110:	48 8d 3d 01 2f 00 00 	lea    0x2f01(%rip),%rdi        # 4018 <__TMC_END__>
    1117:	48 8d 05 fa 2e 00 00 	lea    0x2efa(%rip),%rax        # 4018 <__TMC_END__>
    111e:	48 39 f8             	cmp    %rdi,%rax
    1121:	74 15                	je     1138 <deregister_tm_clones+0x28>
    1123:	48 8b 05 b6 2e 00 00 	mov    0x2eb6(%rip),%rax        # 3fe0 <_ITM_deregisterTMCloneTable@Base>
    112a:	48 85 c0             	test   %rax,%rax
    112d:	74 09                	je     1138 <deregister_tm_clones+0x28>
    112f:	ff e0                	jmp    *%rax
    1131:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    1138:	c3                   	ret
    1139:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001140 <register_tm_clones>:
    1140:	48 8d 3d d1 2e 00 00 	lea    0x2ed1(%rip),%rdi        # 4018 <__TMC_END__>
    1147:	48 8d 35 ca 2e 00 00 	lea    0x2eca(%rip),%rsi        # 4018 <__TMC_END__>
    114e:	48 29 fe             	sub    %rdi,%rsi
    1151:	48 89 f0             	mov    %rsi,%rax
    1154:	48 c1 ee 3f          	shr    $0x3f,%rsi
    1158:	48 c1 f8 03          	sar    $0x3,%rax
    115c:	48 01 c6             	add    %rax,%rsi
    115f:	48 d1 fe             	sar    $1,%rsi
    1162:	74 14                	je     1178 <register_tm_clones+0x38>
    1164:	48 8b 05 85 2e 00 00 	mov    0x2e85(%rip),%rax        # 3ff0 <_ITM_registerTMCloneTable@Base>
    116b:	48 85 c0             	test   %rax,%rax
    116e:	74 08                	je     1178 <register_tm_clones+0x38>
    1170:	ff e0                	jmp    *%rax
    1172:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1178:	c3                   	ret
    1179:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001180 <__do_global_dtors_aux>:
    1180:	f3 0f 1e fa          	endbr64
    1184:	80 3d 8d 2e 00 00 00 	cmpb   $0x0,0x2e8d(%rip)        # 4018 <__TMC_END__>
    118b:	75 2b                	jne    11b8 <__do_global_dtors_aux+0x38>
    118d:	55                   	push   %rbp
    118e:	48 83 3d 62 2e 00 00 	cmpq   $0x0,0x2e62(%rip)        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    1195:	00 
    1196:	48 89 e5             	mov    %rsp,%rbp
    1199:	74 0c                	je     11a7 <__do_global_dtors_aux+0x27>
    119b:	48 8b 3d 66 2e 00 00 	mov    0x2e66(%rip),%rdi        # 4008 <__dso_handle>
    11a2:	e8 d9 fe ff ff       	call   1080 <__cxa_finalize@plt>
    11a7:	e8 64 ff ff ff       	call   1110 <deregister_tm_clones>
    11ac:	c6 05 65 2e 00 00 01 	movb   $0x1,0x2e65(%rip)        # 4018 <__TMC_END__>
    11b3:	5d                   	pop    %rbp
    11b4:	c3                   	ret
    11b5:	0f 1f 00             	nopl   (%rax)
    11b8:	c3                   	ret
    11b9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

00000000000011c0 <frame_dummy>:
    11c0:	f3 0f 1e fa          	endbr64
    11c4:	e9 77 ff ff ff       	jmp    1140 <register_tm_clones>

00000000000011c9 <do_license_check_v1>:
    11c9:	f3 0f 1e fa          	endbr64
    11cd:	55                   	push   %rbp
    11ce:	48 89 e5             	mov    %rsp,%rbp
    11d1:	48 83 ec 10          	sub    $0x10,%rsp
    11d5:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    11d9:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    11dd:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    11e1:	48 89 c6             	mov    %rax,%rsi
    11e4:	48 8d 05 19 0e 00 00 	lea    0xe19(%rip),%rax        # 2004 <_IO_stdin_used+0x4>
    11eb:	48 89 c7             	mov    %rax,%rdi
    11ee:	e8 cd fe ff ff       	call   10c0 <strcmp@plt>
    11f3:	85 c0                	test   %eax,%eax
    11f5:	74 07                	je     11fe <do_license_check_v1+0x35>
    11f7:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    11fc:	eb 05                	jmp    1203 <do_license_check_v1+0x3a>
    11fe:	b8 00 00 00 00       	mov    $0x0,%eax
    1203:	c9                   	leave
    1204:	c3                   	ret

0000000000001205 <do_license_check_v2>:
    1205:	f3 0f 1e fa          	endbr64
    1209:	55                   	push   %rbp
    120a:	48 89 e5             	mov    %rsp,%rbp
    120d:	48 83 ec 10          	sub    $0x10,%rsp
    1211:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    1215:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    1219:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    121d:	48 89 c6             	mov    %rax,%rsi
    1220:	48 8d 05 f7 0d 00 00 	lea    0xdf7(%rip),%rax        # 201e <_IO_stdin_used+0x1e>
    1227:	48 89 c7             	mov    %rax,%rdi
    122a:	e8 91 fe ff ff       	call   10c0 <strcmp@plt>
    122f:	85 c0                	test   %eax,%eax
    1231:	74 07                	je     123a <do_license_check_v2+0x35>
    1233:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    1238:	eb 05                	jmp    123f <do_license_check_v2+0x3a>
    123a:	b8 00 00 00 00       	mov    $0x0,%eax
    123f:	c9                   	leave
    1240:	c3                   	ret

0000000000001241 <main>:
    1241:	f3 0f 1e fa          	endbr64
    1245:	55                   	push   %rbp
    1246:	48 89 e5             	mov    %rsp,%rbp
    1249:	48 83 ec 50          	sub    $0x50,%rsp
    124d:	89 7d bc             	mov    %edi,-0x44(%rbp)
    1250:	48 89 75 b0          	mov    %rsi,-0x50(%rbp)
    1254:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    125b:	00 00 
    125d:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    1261:	31 c0                	xor    %eax,%eax
    1263:	48 8d 05 ce 0d 00 00 	lea    0xdce(%rip),%rax        # 2038 <_IO_stdin_used+0x38>
    126a:	48 89 c7             	mov    %rax,%rdi
    126d:	e8 1e fe ff ff       	call   1090 <puts@plt>
    1272:	48 c7 45 d0 00 00 00 	movq   $0x0,-0x30(%rbp)
    1279:	00 
    127a:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    1281:	00 
    1282:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
    1289:	00 
    128a:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    1291:	00 
    1292:	48 8d 45 d0          	lea    -0x30(%rbp),%rax
    1296:	48 89 c6             	mov    %rax,%rsi
    1299:	48 8d 05 b8 0d 00 00 	lea    0xdb8(%rip),%rax        # 2058 <_IO_stdin_used+0x58>
    12a0:	48 89 c7             	mov    %rax,%rdi
    12a3:	b8 00 00 00 00       	mov    $0x0,%eax
    12a8:	e8 23 fe ff ff       	call   10d0 <__isoc99_scanf@plt>
    12ad:	48 8b 15 5c 2d 00 00 	mov    0x2d5c(%rip),%rdx        # 4010 <check_license>
    12b4:	48 8d 45 d0          	lea    -0x30(%rbp),%rax
    12b8:	be 20 00 00 00       	mov    $0x20,%esi
    12bd:	48 89 c7             	mov    %rax,%rdi
    12c0:	ff d2                	call   *%rdx
    12c2:	89 45 cc             	mov    %eax,-0x34(%rbp)
    12c5:	83 7d cc 00          	cmpl   $0x0,-0x34(%rbp)
    12c9:	74 11                	je     12dc <main+0x9b>
    12cb:	48 8d 05 8b 0d 00 00 	lea    0xd8b(%rip),%rax        # 205d <_IO_stdin_used+0x5d>
    12d2:	48 89 c7             	mov    %rax,%rdi
    12d5:	e8 b6 fd ff ff       	call   1090 <puts@plt>
    12da:	eb 14                	jmp    12f0 <main+0xaf>
    12dc:	48 8d 05 82 0d 00 00 	lea    0xd82(%rip),%rax        # 2065 <_IO_stdin_used+0x65>
    12e3:	48 89 c7             	mov    %rax,%rdi
    12e6:	e8 a5 fd ff ff       	call   1090 <puts@plt>
    12eb:	e8 c0 fd ff ff       	call   10b0 <license_check_ok@plt>
    12f0:	b8 00 00 00 00       	mov    $0x0,%eax
    12f5:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    12f9:	64 48 2b 14 25 28 00 	sub    %fs:0x28,%rdx
    1300:	00 00 
    1302:	74 05                	je     1309 <main+0xc8>
    1304:	e8 97 fd ff ff       	call   10a0 <__stack_chk_fail@plt>
    1309:	c9                   	leave
    130a:	c3                   	ret

000000000000130b <do_nothing>:
    130b:	f3 0f 1e fa          	endbr64
    130f:	55                   	push   %rbp
    1310:	48 89 e5             	mov    %rsp,%rbp
    1313:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    1317:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
    131b:	b8 00 00 00 00       	mov    $0x0,%eax
    1320:	5d                   	pop    %rbp
    1321:	c3                   	ret

Disassembly of section .fini:

0000000000001324 <_fini>:
    1324:	f3 0f 1e fa          	endbr64
    1328:	48 83 ec 08          	sub    $0x8,%rsp
    132c:	48 83 c4 08          	add    $0x8,%rsp
    1330:	c3                   	ret

Disassembly of section .rodata:

0000000000002000 <_IO_stdin_used>:
    2000:	01 00                	add    %eax,(%rax)
    2002:	02 00                	add    (%rax),%al
    2004:	74 68                	je     206e <__GNU_EH_FRAME_HDR+0x2>
    2006:	69 73 5f 69 73 5f 61 	imul   $0x615f7369,0x5f(%rbx),%esi
    200d:	5f                   	pop    %rdi
    200e:	76 61                	jbe    2071 <__GNU_EH_FRAME_HDR+0x5>
    2010:	6c                   	insb   (%dx),%es:(%rdi)
    2011:	69 64 5f 6c 69 63 65 	imul   $0x6e656369,0x6c(%rdi,%rbx,2),%esp
    2018:	6e 
    2019:	73 65                	jae    2080 <__GNU_EH_FRAME_HDR+0x14>
    201b:	5f                   	pop    %rdi
    201c:	31 00                	xor    %eax,(%rax)
    201e:	74 68                	je     2088 <__GNU_EH_FRAME_HDR+0x1c>
    2020:	69 73 5f 69 73 5f 61 	imul   $0x615f7369,0x5f(%rbx),%esi
    2027:	5f                   	pop    %rdi
    2028:	76 61                	jbe    208b <__GNU_EH_FRAME_HDR+0x1f>
    202a:	6c                   	insb   (%dx),%es:(%rdi)
    202b:	69 64 5f 6c 69 63 65 	imul   $0x6e656369,0x6c(%rdi,%rbx,2),%esp
    2032:	6e 
    2033:	73 65                	jae    209a <__GNU_EH_FRAME_HDR+0x2e>
    2035:	5f                   	pop    %rdi
    2036:	32 00                	xor    (%rax),%al
    2038:	50                   	push   %rax
    2039:	6c                   	insb   (%dx),%es:(%rdi)
    203a:	65 61                	gs (bad)
    203c:	73 65                	jae    20a3 <__GNU_EH_FRAME_HDR+0x37>
    203e:	20 65 6e             	and    %ah,0x6e(%rbp)
    2041:	74 65                	je     20a8 <__GNU_EH_FRAME_HDR+0x3c>
    2043:	72 20                	jb     2065 <_IO_stdin_used+0x65>
    2045:	6c                   	insb   (%dx),%es:(%rdi)
    2046:	69 63 65 6e 73 65 20 	imul   $0x2065736e,0x65(%rbx),%esp
    204d:	63 6f 64             	movsxd 0x64(%rdi),%ebp
    2050:	65 20 28             	and    %ch,%gs:(%rax)
    2053:	76 32                	jbe    2087 <__GNU_EH_FRAME_HDR+0x1b>
    2055:	29 3a                	sub    %edi,(%rdx)
    2057:	00 25 33 30 73 00    	add    %ah,0x733033(%rip)        # 735090 <_end+0x731070>
    205d:	49                   	rex.WB
    205e:	4e 56                	rex.WRX push %rsi
    2060:	41                   	rex.B
    2061:	4c                   	rex.WR
    2062:	49                   	rex.WB
    2063:	44 00 56 41          	add    %r10b,0x41(%rsi)
    2067:	4c                   	rex.WR
    2068:	49                   	rex.WB
    2069:	44                   	rex.R
	...

Disassembly of section .eh_frame_hdr:

000000000000206c <__GNU_EH_FRAME_HDR>:
    206c:	01 1b                	add    %ebx,(%rbx)
    206e:	03 3b                	add    (%rbx),%edi
    2070:	48 00 00             	rex.W add %al,(%rax)
    2073:	00 08                	add    %cl,(%rax)
    2075:	00 00                	add    %al,(%rax)
    2077:	00 b4 ef ff ff 7c 00 	add    %dh,0x7cffff(%rdi,%rbp,8)
    207e:	00 00                	add    %al,(%rax)
    2080:	14 f0                	adc    $0xf0,%al
    2082:	ff                   	(bad)
    2083:	ff a4 00 00 00 24 f0 	jmp    *-0xfdc0000(%rax,%rax,1)
    208a:	ff                   	(bad)
    208b:	ff                   	(bad)
    208c:	bc 00 00 00 74       	mov    $0x74000000,%esp
    2091:	f0 ff                	lock (bad)
    2093:	ff 64 00 00          	jmp    *0x0(%rax,%rax,1)
    2097:	00 5d f1             	add    %bl,-0xf(%rbp)
    209a:	ff                   	(bad)
    209b:	ff d4                	call   *%rsp
    209d:	00 00                	add    %al,(%rax)
    209f:	00 99 f1 ff ff f4    	add    %bl,-0xb00000f(%rcx)
    20a5:	00 00                	add    %al,(%rax)
    20a7:	00 d5                	add    %dl,%ch
    20a9:	f1                   	int1
    20aa:	ff                   	(bad)
    20ab:	ff 14 01             	call   *(%rcx,%rax,1)
    20ae:	00 00                	add    %al,(%rax)
    20b0:	9f                   	lahf
    20b1:	f2 ff                	repnz (bad)
    20b3:	ff 34 01             	push   (%rcx,%rax,1)
	...

Disassembly of section .eh_frame:

00000000000020b8 <__FRAME_END__-0x108>:
    20b8:	14 00                	adc    $0x0,%al
    20ba:	00 00                	add    %al,(%rax)
    20bc:	00 00                	add    %al,(%rax)
    20be:	00 00                	add    %al,(%rax)
    20c0:	01 7a 52             	add    %edi,0x52(%rdx)
    20c3:	00 01                	add    %al,(%rcx)
    20c5:	78 10                	js     20d7 <__GNU_EH_FRAME_HDR+0x6b>
    20c7:	01 1b                	add    %ebx,(%rbx)
    20c9:	0c 07                	or     $0x7,%al
    20cb:	08 90 01 00 00 14    	or     %dl,0x14000001(%rax)
    20d1:	00 00                	add    %al,(%rax)
    20d3:	00 1c 00             	add    %bl,(%rax,%rax,1)
    20d6:	00 00                	add    %al,(%rax)
    20d8:	08 f0                	or     %dh,%al
    20da:	ff                   	(bad)
    20db:	ff 26                	jmp    *(%rsi)
    20dd:	00 00                	add    %al,(%rax)
    20df:	00 00                	add    %al,(%rax)
    20e1:	44 07                	rex.R (bad)
    20e3:	10 00                	adc    %al,(%rax)
    20e5:	00 00                	add    %al,(%rax)
    20e7:	00 24 00             	add    %ah,(%rax,%rax,1)
    20ea:	00 00                	add    %al,(%rax)
    20ec:	34 00                	xor    $0x0,%al
    20ee:	00 00                	add    %al,(%rax)
    20f0:	30 ef                	xor    %ch,%bh
    20f2:	ff                   	(bad)
    20f3:	ff 60 00             	jmp    *0x0(%rax)
    20f6:	00 00                	add    %al,(%rax)
    20f8:	00 0e                	add    %cl,(%rsi)
    20fa:	10 46 0e             	adc    %al,0xe(%rsi)
    20fd:	18 4a 0f             	sbb    %cl,0xf(%rdx)
    2100:	0b 77 08             	or     0x8(%rdi),%esi
    2103:	80 00 3f             	addb   $0x3f,(%rax)
    2106:	1a 39                	sbb    (%rcx),%bh
    2108:	2a 33                	sub    (%rbx),%dh
    210a:	24 22                	and    $0x22,%al
    210c:	00 00                	add    %al,(%rax)
    210e:	00 00                	add    %al,(%rax)
    2110:	14 00                	adc    $0x0,%al
    2112:	00 00                	add    %al,(%rax)
    2114:	5c                   	pop    %rsp
    2115:	00 00                	add    %al,(%rax)
    2117:	00 68 ef             	add    %ch,-0x11(%rax)
    211a:	ff                   	(bad)
    211b:	ff 10                	call   *(%rax)
	...
    2125:	00 00                	add    %al,(%rax)
    2127:	00 14 00             	add    %dl,(%rax,%rax,1)
    212a:	00 00                	add    %al,(%rax)
    212c:	74 00                	je     212e <__GNU_EH_FRAME_HDR+0xc2>
    212e:	00 00                	add    %al,(%rax)
    2130:	60                   	(bad)
    2131:	ef                   	out    %eax,(%dx)
    2132:	ff                   	(bad)
    2133:	ff 50 00             	call   *0x0(%rax)
	...
    213e:	00 00                	add    %al,(%rax)
    2140:	1c 00                	sbb    $0x0,%al
    2142:	00 00                	add    %al,(%rax)
    2144:	8c 00                	mov    %es,(%rax)
    2146:	00 00                	add    %al,(%rax)
    2148:	81 f0 ff ff 3c 00    	xor    $0x3cffff,%eax
    214e:	00 00                	add    %al,(%rax)
    2150:	00 45 0e             	add    %al,0xe(%rbp)
    2153:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
    2159:	73 0c                	jae    2167 <__GNU_EH_FRAME_HDR+0xfb>
    215b:	07                   	(bad)
    215c:	08 00                	or     %al,(%rax)
    215e:	00 00                	add    %al,(%rax)
    2160:	1c 00                	sbb    $0x0,%al
    2162:	00 00                	add    %al,(%rax)
    2164:	ac                   	lods   %ds:(%rsi),%al
    2165:	00 00                	add    %al,(%rax)
    2167:	00 9d f0 ff ff 3c    	add    %bl,0x3cfffff0(%rbp)
    216d:	00 00                	add    %al,(%rax)
    216f:	00 00                	add    %al,(%rax)
    2171:	45 0e                	rex.RB (bad)
    2173:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
    2179:	73 0c                	jae    2187 <__GNU_EH_FRAME_HDR+0x11b>
    217b:	07                   	(bad)
    217c:	08 00                	or     %al,(%rax)
    217e:	00 00                	add    %al,(%rax)
    2180:	1c 00                	sbb    $0x0,%al
    2182:	00 00                	add    %al,(%rax)
    2184:	cc                   	int3
    2185:	00 00                	add    %al,(%rax)
    2187:	00 b9 f0 ff ff ca    	add    %bh,-0x35000010(%rcx)
    218d:	00 00                	add    %al,(%rax)
    218f:	00 00                	add    %al,(%rax)
    2191:	45 0e                	rex.RB (bad)
    2193:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
    2199:	02 c1                	add    %cl,%al
    219b:	0c 07                	or     $0x7,%al
    219d:	08 00                	or     %al,(%rax)
    219f:	00 1c 00             	add    %bl,(%rax,%rax,1)
    21a2:	00 00                	add    %al,(%rax)
    21a4:	ec                   	in     (%dx),%al
    21a5:	00 00                	add    %al,(%rax)
    21a7:	00 63 f1             	add    %ah,-0xf(%rbx)
    21aa:	ff                   	(bad)
    21ab:	ff 17                	call   *(%rdi)
    21ad:	00 00                	add    %al,(%rax)
    21af:	00 00                	add    %al,(%rax)
    21b1:	45 0e                	rex.RB (bad)
    21b3:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
    21b9:	4e 0c 07             	rex.WRX or $0x7,%al
    21bc:	08 00                	or     %al,(%rax)
	...

00000000000021c0 <__FRAME_END__>:
    21c0:	00 00                	add    %al,(%rax)
	...

Disassembly of section .init_array:

0000000000003d88 <__frame_dummy_init_array_entry>:
    3d88:	c0 11 00             	rclb   $0x0,(%rcx)
    3d8b:	00 00                	add    %al,(%rax)
    3d8d:	00 00                	add    %al,(%rax)
	...

Disassembly of section .fini_array:

0000000000003d90 <__do_global_dtors_aux_fini_array_entry>:
    3d90:	80 11 00             	adcb   $0x0,(%rcx)
    3d93:	00 00                	add    %al,(%rax)
    3d95:	00 00                	add    %al,(%rax)
	...

Disassembly of section .dynamic:

0000000000003d98 <_DYNAMIC>:
    3d98:	01 00                	add    %eax,(%rax)
    3d9a:	00 00                	add    %al,(%rax)
    3d9c:	00 00                	add    %al,(%rax)
    3d9e:	00 00                	add    %al,(%rax)
    3da0:	a4                   	movsb  %ds:(%rsi),%es:(%rdi)
    3da1:	00 00                	add    %al,(%rax)
    3da3:	00 00                	add    %al,(%rax)
    3da5:	00 00                	add    %al,(%rax)
    3da7:	00 01                	add    %al,(%rcx)
    3da9:	00 00                	add    %al,(%rax)
    3dab:	00 00                	add    %al,(%rax)
    3dad:	00 00                	add    %al,(%rax)
    3daf:	00 b2 00 00 00 00    	add    %dh,0x0(%rdx)
    3db5:	00 00                	add    %al,(%rax)
    3db7:	00 0c 00             	add    %cl,(%rax,%rax,1)
    3dba:	00 00                	add    %al,(%rax)
    3dbc:	00 00                	add    %al,(%rax)
    3dbe:	00 00                	add    %al,(%rax)
    3dc0:	00 10                	add    %dl,(%rax)
    3dc2:	00 00                	add    %al,(%rax)
    3dc4:	00 00                	add    %al,(%rax)
    3dc6:	00 00                	add    %al,(%rax)
    3dc8:	0d 00 00 00 00       	or     $0x0,%eax
    3dcd:	00 00                	add    %al,(%rax)
    3dcf:	00 24 13             	add    %ah,(%rbx,%rdx,1)
    3dd2:	00 00                	add    %al,(%rax)
    3dd4:	00 00                	add    %al,(%rax)
    3dd6:	00 00                	add    %al,(%rax)
    3dd8:	19 00                	sbb    %eax,(%rax)
    3dda:	00 00                	add    %al,(%rax)
    3ddc:	00 00                	add    %al,(%rax)
    3dde:	00 00                	add    %al,(%rax)
    3de0:	88 3d 00 00 00 00    	mov    %bh,0x0(%rip)        # 3de6 <_DYNAMIC+0x4e>
    3de6:	00 00                	add    %al,(%rax)
    3de8:	1b 00                	sbb    (%rax),%eax
    3dea:	00 00                	add    %al,(%rax)
    3dec:	00 00                	add    %al,(%rax)
    3dee:	00 00                	add    %al,(%rax)
    3df0:	08 00                	or     %al,(%rax)
    3df2:	00 00                	add    %al,(%rax)
    3df4:	00 00                	add    %al,(%rax)
    3df6:	00 00                	add    %al,(%rax)
    3df8:	1a 00                	sbb    (%rax),%al
    3dfa:	00 00                	add    %al,(%rax)
    3dfc:	00 00                	add    %al,(%rax)
    3dfe:	00 00                	add    %al,(%rax)
    3e00:	90                   	nop
    3e01:	3d 00 00 00 00       	cmp    $0x0,%eax
    3e06:	00 00                	add    %al,(%rax)
    3e08:	1c 00                	sbb    $0x0,%al
    3e0a:	00 00                	add    %al,(%rax)
    3e0c:	00 00                	add    %al,(%rax)
    3e0e:	00 00                	add    %al,(%rax)
    3e10:	08 00                	or     %al,(%rax)
    3e12:	00 00                	add    %al,(%rax)
    3e14:	00 00                	add    %al,(%rax)
    3e16:	00 00                	add    %al,(%rax)
    3e18:	f5                   	cmc
    3e19:	fe                   	(bad)
    3e1a:	ff 6f 00             	ljmp   *0x0(%rdi)
    3e1d:	00 00                	add    %al,(%rax)
    3e1f:	00 b0 03 00 00 00    	add    %dh,0x3(%rax)
    3e25:	00 00                	add    %al,(%rax)
    3e27:	00 05 00 00 00 00    	add    %al,0x0(%rip)        # 3e2d <_DYNAMIC+0x95>
    3e2d:	00 00                	add    %al,(%rax)
    3e2f:	00 e0                	add    %ah,%al
    3e31:	04 00                	add    $0x0,%al
    3e33:	00 00                	add    %al,(%rax)
    3e35:	00 00                	add    %al,(%rax)
    3e37:	00 06                	add    %al,(%rsi)
    3e39:	00 00                	add    %al,(%rax)
    3e3b:	00 00                	add    %al,(%rax)
    3e3d:	00 00                	add    %al,(%rax)
    3e3f:	00 d8                	add    %bl,%al
    3e41:	03 00                	add    (%rax),%eax
    3e43:	00 00                	add    %al,(%rax)
    3e45:	00 00                	add    %al,(%rax)
    3e47:	00 0a                	add    %cl,(%rdx)
    3e49:	00 00                	add    %al,(%rax)
    3e4b:	00 00                	add    %al,(%rax)
    3e4d:	00 00                	add    %al,(%rax)
    3e4f:	00 e7                	add    %ah,%bh
    3e51:	00 00                	add    %al,(%rax)
    3e53:	00 00                	add    %al,(%rax)
    3e55:	00 00                	add    %al,(%rax)
    3e57:	00 0b                	add    %cl,(%rbx)
    3e59:	00 00                	add    %al,(%rax)
    3e5b:	00 00                	add    %al,(%rax)
    3e5d:	00 00                	add    %al,(%rax)
    3e5f:	00 18                	add    %bl,(%rax)
    3e61:	00 00                	add    %al,(%rax)
    3e63:	00 00                	add    %al,(%rax)
    3e65:	00 00                	add    %al,(%rax)
    3e67:	00 15 00 00 00 00    	add    %dl,0x0(%rip)        # 3e6d <_DYNAMIC+0xd5>
	...
    3e75:	00 00                	add    %al,(%rax)
    3e77:	00 03                	add    %al,(%rbx)
    3e79:	00 00                	add    %al,(%rax)
    3e7b:	00 00                	add    %al,(%rax)
    3e7d:	00 00                	add    %al,(%rax)
    3e7f:	00 98 3f 00 00 00    	add    %bl,0x3f(%rax)
    3e85:	00 00                	add    %al,(%rax)
    3e87:	00 02                	add    %al,(%rdx)
    3e89:	00 00                	add    %al,(%rax)
    3e8b:	00 00                	add    %al,(%rax)
    3e8d:	00 00                	add    %al,(%rax)
    3e8f:	00 78 00             	add    %bh,0x0(%rax)
    3e92:	00 00                	add    %al,(%rax)
    3e94:	00 00                	add    %al,(%rax)
    3e96:	00 00                	add    %al,(%rax)
    3e98:	14 00                	adc    $0x0,%al
    3e9a:	00 00                	add    %al,(%rax)
    3e9c:	00 00                	add    %al,(%rax)
    3e9e:	00 00                	add    %al,(%rax)
    3ea0:	07                   	(bad)
    3ea1:	00 00                	add    %al,(%rax)
    3ea3:	00 00                	add    %al,(%rax)
    3ea5:	00 00                	add    %al,(%rax)
    3ea7:	00 17                	add    %dl,(%rdi)
    3ea9:	00 00                	add    %al,(%rax)
    3eab:	00 00                	add    %al,(%rax)
    3ead:	00 00                	add    %al,(%rax)
    3eaf:	00 08                	add    %cl,(%rax)
    3eb1:	07                   	(bad)
    3eb2:	00 00                	add    %al,(%rax)
    3eb4:	00 00                	add    %al,(%rax)
    3eb6:	00 00                	add    %al,(%rax)
    3eb8:	07                   	(bad)
    3eb9:	00 00                	add    %al,(%rax)
    3ebb:	00 00                	add    %al,(%rax)
    3ebd:	00 00                	add    %al,(%rax)
    3ebf:	00 30                	add    %dh,(%rax)
    3ec1:	06                   	(bad)
    3ec2:	00 00                	add    %al,(%rax)
    3ec4:	00 00                	add    %al,(%rax)
    3ec6:	00 00                	add    %al,(%rax)
    3ec8:	08 00                	or     %al,(%rax)
    3eca:	00 00                	add    %al,(%rax)
    3ecc:	00 00                	add    %al,(%rax)
    3ece:	00 00                	add    %al,(%rax)
    3ed0:	d8 00                	fadds  (%rax)
    3ed2:	00 00                	add    %al,(%rax)
    3ed4:	00 00                	add    %al,(%rax)
    3ed6:	00 00                	add    %al,(%rax)
    3ed8:	09 00                	or     %eax,(%rax)
    3eda:	00 00                	add    %al,(%rax)
    3edc:	00 00                	add    %al,(%rax)
    3ede:	00 00                	add    %al,(%rax)
    3ee0:	18 00                	sbb    %al,(%rax)
    3ee2:	00 00                	add    %al,(%rax)
    3ee4:	00 00                	add    %al,(%rax)
    3ee6:	00 00                	add    %al,(%rax)
    3ee8:	1e                   	(bad)
    3ee9:	00 00                	add    %al,(%rax)
    3eeb:	00 00                	add    %al,(%rax)
    3eed:	00 00                	add    %al,(%rax)
    3eef:	00 08                	add    %cl,(%rax)
    3ef1:	00 00                	add    %al,(%rax)
    3ef3:	00 00                	add    %al,(%rax)
    3ef5:	00 00                	add    %al,(%rax)
    3ef7:	00 fb                	add    %bh,%bl
    3ef9:	ff                   	(bad)
    3efa:	ff 6f 00             	ljmp   *0x0(%rdi)
    3efd:	00 00                	add    %al,(%rax)
    3eff:	00 01                	add    %al,(%rcx)
    3f01:	00 00                	add    %al,(%rax)
    3f03:	08 00                	or     %al,(%rax)
    3f05:	00 00                	add    %al,(%rax)
    3f07:	00 fe                	add    %bh,%dh
    3f09:	ff                   	(bad)
    3f0a:	ff 6f 00             	ljmp   *0x0(%rdi)
    3f0d:	00 00                	add    %al,(%rax)
    3f0f:	00 e0                	add    %ah,%al
    3f11:	05 00 00 00 00       	add    $0x0,%eax
    3f16:	00 00                	add    %al,(%rax)
    3f18:	ff                   	(bad)
    3f19:	ff                   	(bad)
    3f1a:	ff 6f 00             	ljmp   *0x0(%rdi)
    3f1d:	00 00                	add    %al,(%rax)
    3f1f:	00 01                	add    %al,(%rcx)
    3f21:	00 00                	add    %al,(%rax)
    3f23:	00 00                	add    %al,(%rax)
    3f25:	00 00                	add    %al,(%rax)
    3f27:	00 f0                	add    %dh,%al
    3f29:	ff                   	(bad)
    3f2a:	ff 6f 00             	ljmp   *0x0(%rdi)
    3f2d:	00 00                	add    %al,(%rax)
    3f2f:	00 c8                	add    %cl,%al
    3f31:	05 00 00 00 00       	add    $0x0,%eax
    3f36:	00 00                	add    %al,(%rax)
    3f38:	f9                   	stc
    3f39:	ff                   	(bad)
    3f3a:	ff 6f 00             	ljmp   *0x0(%rdi)
    3f3d:	00 00                	add    %al,(%rax)
    3f3f:	00 04 00             	add    %al,(%rax,%rax,1)
	...

Disassembly of section .got:

0000000000003f98 <_GLOBAL_OFFSET_TABLE_>:
    3f98:	98                   	cwtl
    3f99:	3d 00 00 00 00       	cmp    $0x0,%eax
	...
    3fae:	00 00                	add    %al,(%rax)
    3fb0:	30 10                	xor    %dl,(%rax)
    3fb2:	00 00                	add    %al,(%rax)
    3fb4:	00 00                	add    %al,(%rax)
    3fb6:	00 00                	add    %al,(%rax)
    3fb8:	40 10 00             	rex adc %al,(%rax)
    3fbb:	00 00                	add    %al,(%rax)
    3fbd:	00 00                	add    %al,(%rax)
    3fbf:	00 50 10             	add    %dl,0x10(%rax)
    3fc2:	00 00                	add    %al,(%rax)
    3fc4:	00 00                	add    %al,(%rax)
    3fc6:	00 00                	add    %al,(%rax)
    3fc8:	60                   	(bad)
    3fc9:	10 00                	adc    %al,(%rax)
    3fcb:	00 00                	add    %al,(%rax)
    3fcd:	00 00                	add    %al,(%rax)
    3fcf:	00 70 10             	add    %dh,0x10(%rax)
	...

Disassembly of section .data:

0000000000004000 <__data_start>:
	...

0000000000004008 <__dso_handle>:
    4008:	08 40 00             	or     %al,0x0(%rax)
    400b:	00 00                	add    %al,(%rax)
    400d:	00 00                	add    %al,(%rax)
	...

0000000000004010 <check_license>:
    4010:	05 12 00 00 00       	add    $0x12,%eax
    4015:	00 00                	add    %al,(%rax)
	...

Disassembly of section .comment:

0000000000000000 <.comment>:
   0:	47                   	rex.RXB
   1:	43                   	rex.XB
   2:	43 3a 20             	rex.XB cmp (%r8),%spl
   5:	28 55 62             	sub    %dl,0x62(%rbp)
   8:	75 6e                	jne    78 <__abi_tag-0x314>
   a:	74 75                	je     81 <__abi_tag-0x30b>
   c:	20 31                	and    %dh,(%rcx)
   e:	33 2e                	xor    (%rsi),%ebp
  10:	33 2e                	xor    (%rsi),%ebp
  12:	30 2d 36 75 62 75    	xor    %ch,0x75627536(%rip)        # 7562754e <_end+0x7562352e>
  18:	6e                   	outsb  %ds:(%rsi),(%dx)
  19:	74 75                	je     90 <__abi_tag-0x2fc>
  1b:	32 7e 32             	xor    0x32(%rsi),%bh
  1e:	34 2e                	xor    $0x2e,%al
  20:	30 34 29             	xor    %dh,(%rcx,%rbp,1)
  23:	20 31                	and    %dh,(%rcx)
  25:	33 2e                	xor    (%rsi),%ebp
  27:	33 2e                	xor    (%rsi),%ebp
  29:	30 00                	xor    %al,(%rax)

Disassembly of section .signature:

0000000000000000 <.signature>:
   0:	5c                   	pop    %rsp
   1:	3b 3c d4             	cmp    (%rsp,%rdx,8),%edi
   4:	5c                   	pop    %rsp
   5:	0f 3e                	(bad)
   7:	d5 de f2 bc 96 2f 0b 	{rex2 0xde} pslld -0x6284f4d1(%r22,%r10,4),%mm7
   e:	7b 9d 
  10:	69 63 e0 09 35 95 b1 	imul   $0xb1953509,-0x20(%rbx),%esp
  17:	96                   	xchg   %eax,%esi
  18:	a4                   	movsb  %ds:(%rsi),%es:(%rdi)
  19:	82                   	(bad)
  1a:	fc                   	cld
  1b:	da f7                	(bad)
  1d:	bc dc b4 e0 ca       	mov    $0xcae0b4dc,%esp
  22:	28 1e                	sub    %bl,(%rsi)
  24:	0b cb                	or     %ebx,%ecx
  26:	10 91 5b 13 b9 79    	adc    %dl,0x79b9135b(%rcx)
  2c:	41 af                	rex.B scas %es:(%rdi),%eax
  2e:	0f 70 54 2e d3 3b    	pshufw $0x3b,-0x2d(%rsi,%rbp,1),%mm2
  34:	d5 8b 4a cd          	{rex2 0x8b} cmovp %r13,%rcx
  38:	44 a2 53 67 30 22 42 	rex.R movabs %al,0x1bb3124222306753
  3f:	12 b3 1b 
  42:	ae                   	scas   %es:(%rdi),%al
  43:	33 82 46 9d 8c e6    	xor    -0x197362ba(%rdx),%eax
  49:	25 d7 77 7d f8       	and    $0xf87d77d7,%eax
  4e:	8e 30                	mov    (%rax),%?
  50:	0a 2c df             	or     (%rdi,%rbx,8),%ch
  53:	31 9b e4 49 29 5d    	xor    %ebx,0x5d2949e4(%rbx)
  59:	d1 b3 5a f6 cf d9    	shll   $1,-0x263009a6(%rbx)
  5f:	7c 23                	jl     84 <__abi_tag-0x308>
  61:	1a 55 85             	sbb    -0x7b(%rbp),%dl
  64:	fa                   	cli
  65:	f6 93 57 21 fb cd    	notb   -0x3204dea9(%rbx)
  6b:	8d                   	lea    (bad),%esi
  6c:	f0 51                	lock push %rcx
  6e:	25 3b 61 59 62       	and    $0x6259613b,%eax
  73:	6d                   	insl   (%dx),%es:(%rdi)
  74:	98                   	cwtl
  75:	41 b1 3e             	mov    $0x3e,%r9b
  78:	5b                   	pop    %rbx
  79:	9e                   	sahf
  7a:	37                   	(bad)
  7b:	33 8e 32 34 d0 63    	xor    0x63d03432(%rsi),%ecx
  81:	7f 9a                	jg     1d <__abi_tag-0x36f>
  83:	fb                   	sti
  84:	9c                   	pushf
  85:	5f                   	pop    %rdi
  86:	1b 38                	sbb    (%rax),%edi
  88:	67 cf                	addr32 iret
  8a:	08 34 0a             	or     %dh,(%rdx,%rcx,1)
  8d:	ff 47 51             	incl   0x51(%rdi)
  90:	6d                   	insl   (%dx),%es:(%rdi)
  91:	a0 09 f4 00 0e ed 3b 	movabs 0x834f3bed0e00f409,%al
  98:	4f 83 
  9a:	65 76 53             	gs jbe f0 <__abi_tag-0x29c>
  9d:	ea                   	(bad)
  9e:	5f                   	pop    %rdi
  9f:	6d                   	insl   (%dx),%es:(%rdi)
  a0:	d5 24 d7             	{rex2 0x24} xlat %ds:(%rbx)
  a3:	51                   	push   %rcx
  a4:	73 76                	jae    11c <__abi_tag-0x270>
  a6:	89 fe                	mov    %edi,%esi
  a8:	49 84 71 b5          	rex.WB test %sil,-0x4b(%r9)
  ac:	a1 8a 97 42 5e 86 d5 	movabs 0x8e2ed5865e42978a,%eax
  b3:	2e 8e 
  b5:	ac                   	lods   %ds:(%rsi),%al
  b6:	3d 6e 72 db 0b       	cmp    $0xbdb726e,%eax
  bb:	65 ce                	gs (bad)
  bd:	07                   	(bad)
  be:	95                   	xchg   %eax,%ebp
  bf:	69 f2 01 ef 00 f8    	imul   $0xf800ef01,%edx,%esi
  c5:	5f                   	pop    %rdi
  c6:	a5                   	movsl  %ds:(%rsi),%es:(%rdi)
  c7:	6e                   	outsb  %ds:(%rsi),(%dx)
  c8:	ec                   	in     (%dx),%al
  c9:	9f                   	lahf
  ca:	e4 10                	in     $0x10,%al
  cc:	46 a1 b5 c2 f1 06 02 	rex.RX movabs 0x564f6f0206f1c2b5,%eax
  d3:	6f 4f 56 
  d6:	68 6c d1 e7 4a       	push   $0x4ae7d16c
  db:	d1 8e 0e 9d e1 64    	rorl   $1,0x64e19d0e(%rsi)
  e1:	3e 6a 82             	ds push $0xffffffffffffff82
  e4:	43 21 5e 99          	rex.XB and %ebx,-0x67(%r14)
  e8:	d9 87 bc 06 da 1b    	flds   0x1bda06bc(%rdi)
  ee:	be 45 42 12 5f       	mov    $0x5f124245,%esi
  f3:	80 eb 76             	sub    $0x76,%bl
  f6:	48 eb 09             	rex.W jmp 102 <__abi_tag-0x28a>
  f9:	89 53 fe             	mov    %edx,-0x2(%rbx)
  fc:	ae                   	scas   %es:(%rdi),%al
  fd:	bb                   	.byte 0xbb
  fe:	a0                   	.byte 0xa0
  ff:	0d                   	.byte 0xd
