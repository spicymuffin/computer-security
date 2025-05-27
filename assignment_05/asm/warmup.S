
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



Disassembly of section .interp:

0000000000400318 <.interp>:
  400318:	2f                   	(bad)
  400319:	6c                   	insb   (%dx),%es:(%rdi)
  40031a:	69 62 36 34 2f 6c 64 	imul   $0x646c2f34,0x36(%rdx),%esp
  400321:	2d 6c 69 6e 75       	sub    $0x756e696c,%eax
  400326:	78 2d                	js     400355 <printf@plt-0xcdb>
  400328:	78 38                	js     400362 <printf@plt-0xcce>
  40032a:	36 2d 36 34 2e 73    	ss sub $0x732e3436,%eax
  400330:	6f                   	outsl  %ds:(%rsi),(%dx)
  400331:	2e 32 00             	cs xor (%rax),%al

Disassembly of section .note.gnu.property:

0000000000400338 <.note.gnu.property>:
  400338:	04 00                	add    $0x0,%al
  40033a:	00 00                	add    %al,(%rax)
  40033c:	10 00                	adc    %al,(%rax)
  40033e:	00 00                	add    %al,(%rax)
  400340:	05 00 00 00 47       	add    $0x47000000,%eax
  400345:	4e 55                	rex.WRX push %rbp
  400347:	00 02                	add    %al,(%rdx)
  400349:	80 00 c0             	addb   $0xc0,(%rax)
  40034c:	04 00                	add    $0x0,%al
  40034e:	00 00                	add    %al,(%rax)
  400350:	01 00                	add    %eax,(%rax)
  400352:	00 00                	add    %al,(%rax)
  400354:	00 00                	add    %al,(%rax)
	...

Disassembly of section .note.gnu.build-id:

0000000000400358 <.note.gnu.build-id>:
  400358:	04 00                	add    $0x0,%al
  40035a:	00 00                	add    %al,(%rax)
  40035c:	14 00                	adc    $0x0,%al
  40035e:	00 00                	add    %al,(%rax)
  400360:	03 00                	add    (%rax),%eax
  400362:	00 00                	add    %al,(%rax)
  400364:	47                   	rex.RXB
  400365:	4e 55                	rex.WRX push %rbp
  400367:	00 26                	add    %ah,(%rsi)
  400369:	bb 55 ef cf d9       	mov    $0xd9cfef55,%ebx
  40036e:	dc d5                	(bad)
  400370:	f2 1b 29             	repnz sbb (%rcx),%ebp
  400373:	f6 93 ef 06 17 31    	notb   0x311706ef(%rbx)
  400379:	95                   	xchg   %eax,%ebp
  40037a:	27                   	(bad)
  40037b:	2c                   	.byte 0x2c

Disassembly of section .note.ABI-tag:

000000000040037c <.note.ABI-tag>:
  40037c:	04 00                	add    $0x0,%al
  40037e:	00 00                	add    %al,(%rax)
  400380:	10 00                	adc    %al,(%rax)
  400382:	00 00                	add    %al,(%rax)
  400384:	01 00                	add    %eax,(%rax)
  400386:	00 00                	add    %al,(%rax)
  400388:	47                   	rex.RXB
  400389:	4e 55                	rex.WRX push %rbp
  40038b:	00 00                	add    %al,(%rax)
  40038d:	00 00                	add    %al,(%rax)
  40038f:	00 03                	add    %al,(%rbx)
  400391:	00 00                	add    %al,(%rax)
  400393:	00 02                	add    %al,(%rdx)
  400395:	00 00                	add    %al,(%rax)
  400397:	00 00                	add    %al,(%rax)
  400399:	00 00                	add    %al,(%rax)
	...

Disassembly of section .gnu.hash:

00000000004003a0 <.gnu.hash>:
  4003a0:	01 00                	add    %eax,(%rax)
  4003a2:	00 00                	add    %al,(%rax)
  4003a4:	01 00                	add    %eax,(%rax)
  4003a6:	00 00                	add    %al,(%rax)
  4003a8:	01 00                	add    %eax,(%rax)
	...

Disassembly of section .dynsym:

00000000004003c0 <.dynsym>:
	...
  4003d8:	0d 00 00 00 12       	or     $0x12000000,%eax
	...
  4003ed:	00 00                	add    %al,(%rax)
  4003ef:	00 1f                	add    %bl,(%rdi)
  4003f1:	00 00                	add    %al,(%rax)
  4003f3:	00 12                	add    %dl,(%rdx)
	...
  400405:	00 00                	add    %al,(%rax)
  400407:	00 06                	add    %al,(%rsi)
  400409:	00 00                	add    %al,(%rax)
  40040b:	00 12                	add    %dl,(%rdx)
	...
  40041d:	00 00                	add    %al,(%rax)
  40041f:	00 47 00             	add    %al,0x0(%rdi)
  400422:	00 00                	add    %al,(%rax)
  400424:	20 00                	and    %al,(%rax)
	...
  400436:	00 00                	add    %al,(%rax)
  400438:	01 00                	add    %eax,(%rax)
  40043a:	00 00                	add    %al,(%rax)
  40043c:	12 00                	adc    (%rax),%al
	...

Disassembly of section .dynstr:

0000000000400450 <.dynstr>:
  400450:	00 67 65             	add    %ah,0x65(%rdi)
  400453:	74 73                	je     4004c8 <printf@plt-0xb68>
  400455:	00 65 78             	add    %ah,0x78(%rbp)
  400458:	65 63 76 65          	movsxd %gs:0x65(%rsi),%esi
  40045c:	00 5f 5f             	add    %bl,0x5f(%rdi)
  40045f:	6c                   	insb   (%dx),%es:(%rdi)
  400460:	69 62 63 5f 73 74 61 	imul   $0x6174735f,0x63(%rdx),%esp
  400467:	72 74                	jb     4004dd <printf@plt-0xb53>
  400469:	5f                   	pop    %rdi
  40046a:	6d                   	insl   (%dx),%es:(%rdi)
  40046b:	61                   	(bad)
  40046c:	69 6e 00 70 72 69 6e 	imul   $0x6e697270,0x0(%rsi),%ebp
  400473:	74 66                	je     4004db <printf@plt-0xb55>
  400475:	00 6c 69 62          	add    %ch,0x62(%rcx,%rbp,2)
  400479:	63 2e                	movsxd (%rsi),%ebp
  40047b:	73 6f                	jae    4004ec <printf@plt-0xb44>
  40047d:	2e 36 00 47 4c       	cs ss add %al,0x4c(%rdi)
  400482:	49                   	rex.WB
  400483:	42                   	rex.X
  400484:	43 5f                	rex.XB pop %r15
  400486:	32 2e                	xor    (%rsi),%ch
  400488:	32 2e                	xor    (%rsi),%ch
  40048a:	35 00 47 4c 49       	xor    $0x494c4700,%eax
  40048f:	42                   	rex.X
  400490:	43 5f                	rex.XB pop %r15
  400492:	32 2e                	xor    (%rsi),%ch
  400494:	33 34 00             	xor    (%rax,%rax,1),%esi
  400497:	5f                   	pop    %rdi
  400498:	5f                   	pop    %rdi
  400499:	67 6d                	insl   (%dx),%es:(%edi)
  40049b:	6f                   	outsl  %ds:(%rsi),(%dx)
  40049c:	6e                   	outsb  %ds:(%rsi),(%dx)
  40049d:	5f                   	pop    %rdi
  40049e:	73 74                	jae    400514 <printf@plt-0xb1c>
  4004a0:	61                   	(bad)
  4004a1:	72 74                	jb     400517 <printf@plt-0xb19>
  4004a3:	5f                   	pop    %rdi
  4004a4:	5f                   	pop    %rdi
	...

Disassembly of section .gnu.version:

00000000004004a6 <.gnu.version>:
  4004a6:	00 00                	add    %al,(%rax)
  4004a8:	02 00                	add    (%rax),%al
  4004aa:	03 00                	add    (%rax),%eax
  4004ac:	03 00                	add    (%rax),%eax
  4004ae:	01 00                	add    %eax,(%rax)
  4004b0:	03 00                	add    (%rax),%eax

Disassembly of section .gnu.version_r:

00000000004004b8 <.gnu.version_r>:
  4004b8:	01 00                	add    %eax,(%rax)
  4004ba:	02 00                	add    (%rax),%al
  4004bc:	26 00 00             	es add %al,(%rax)
  4004bf:	00 10                	add    %dl,(%rax)
  4004c1:	00 00                	add    %al,(%rax)
  4004c3:	00 00                	add    %al,(%rax)
  4004c5:	00 00                	add    %al,(%rax)
  4004c7:	00 75 1a             	add    %dh,0x1a(%rbp)
  4004ca:	69 09 00 00 03 00    	imul   $0x30000,(%rcx),%ecx
  4004d0:	30 00                	xor    %al,(%rax)
  4004d2:	00 00                	add    %al,(%rax)
  4004d4:	10 00                	adc    %al,(%rax)
  4004d6:	00 00                	add    %al,(%rax)
  4004d8:	b4 91                	mov    $0x91,%ah
  4004da:	96                   	xchg   %eax,%esi
  4004db:	06                   	(bad)
  4004dc:	00 00                	add    %al,(%rax)
  4004de:	02 00                	add    (%rax),%al
  4004e0:	3c 00                	cmp    $0x0,%al
  4004e2:	00 00                	add    %al,(%rax)
  4004e4:	00 00                	add    %al,(%rax)
	...

Disassembly of section .rela.dyn:

00000000004004e8 <.rela.dyn>:
  4004e8:	d8 3f                	fdivrs (%rdi)
  4004ea:	40 00 00             	rex add %al,(%rax)
  4004ed:	00 00                	add    %al,(%rax)
  4004ef:	00 06                	add    %al,(%rsi)
  4004f1:	00 00                	add    %al,(%rax)
  4004f3:	00 01                	add    %al,(%rcx)
	...
  4004fd:	00 00                	add    %al,(%rax)
  4004ff:	00 e0                	add    %ah,%al
  400501:	3f                   	(bad)
  400502:	40 00 00             	rex add %al,(%rax)
  400505:	00 00                	add    %al,(%rax)
  400507:	00 06                	add    %al,(%rsi)
  400509:	00 00                	add    %al,(%rax)
  40050b:	00 04 00             	add    %al,(%rax,%rax,1)
	...

Disassembly of section .rela.plt:

0000000000400518 <.rela.plt>:
  400518:	00 40 40             	add    %al,0x40(%rax)
  40051b:	00 00                	add    %al,(%rax)
  40051d:	00 00                	add    %al,(%rax)
  40051f:	00 07                	add    %al,(%rdi)
  400521:	00 00                	add    %al,(%rax)
  400523:	00 02                	add    %al,(%rdx)
	...
  40052d:	00 00                	add    %al,(%rax)
  40052f:	00 08                	add    %cl,(%rax)
  400531:	40                   	rex
  400532:	40 00 00             	rex add %al,(%rax)
  400535:	00 00                	add    %al,(%rax)
  400537:	00 07                	add    %al,(%rdi)
  400539:	00 00                	add    %al,(%rax)
  40053b:	00 03                	add    %al,(%rbx)
	...
  400545:	00 00                	add    %al,(%rax)
  400547:	00 10                	add    %dl,(%rax)
  400549:	40                   	rex
  40054a:	40 00 00             	rex add %al,(%rax)
  40054d:	00 00                	add    %al,(%rax)
  40054f:	00 07                	add    %al,(%rdi)
  400551:	00 00                	add    %al,(%rax)
  400553:	00 05 00 00 00 00    	add    %al,0x0(%rip)        # 400559 <printf@plt-0xad7>
  400559:	00 00                	add    %al,(%rax)
  40055b:	00 00                	add    %al,(%rax)
  40055d:	00 00                	add    %al,(%rax)
	...

Disassembly of section .init:

0000000000401000 <.init>:
  401000:	f3 0f 1e fa          	endbr64
  401004:	48 83 ec 08          	sub    $0x8,%rsp
  401008:	48 8b 05 d1 2f 00 00 	mov    0x2fd1(%rip),%rax        # 403fe0 <gets@plt+0x2f90>
  40100f:	48 85 c0             	test   %rax,%rax
  401012:	74 02                	je     401016 <printf@plt-0x1a>
  401014:	ff d0                	call   *%rax
  401016:	48 83 c4 08          	add    $0x8,%rsp
  40101a:	c3                   	ret

Disassembly of section .plt:

0000000000401020 <printf@plt-0x10>:
  401020:	ff 35 ca 2f 00 00    	push   0x2fca(%rip)        # 403ff0 <gets@plt+0x2fa0>
  401026:	ff 25 cc 2f 00 00    	jmp    *0x2fcc(%rip)        # 403ff8 <gets@plt+0x2fa8>
  40102c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000401030 <printf@plt>:
  401030:	ff 25 ca 2f 00 00    	jmp    *0x2fca(%rip)        # 404000 <gets@plt+0x2fb0>
  401036:	68 00 00 00 00       	push   $0x0
  40103b:	e9 e0 ff ff ff       	jmp    401020 <printf@plt-0x10>

0000000000401040 <execve@plt>:
  401040:	ff 25 c2 2f 00 00    	jmp    *0x2fc2(%rip)        # 404008 <gets@plt+0x2fb8>
  401046:	68 01 00 00 00       	push   $0x1
  40104b:	e9 d0 ff ff ff       	jmp    401020 <printf@plt-0x10>

0000000000401050 <gets@plt>:
  401050:	ff 25 ba 2f 00 00    	jmp    *0x2fba(%rip)        # 404010 <gets@plt+0x2fc0>
  401056:	68 02 00 00 00       	push   $0x2
  40105b:	e9 c0 ff ff ff       	jmp    401020 <printf@plt-0x10>

Disassembly of section .text:

0000000000401060 <.text>:
  401060:	f3 0f 1e fa          	endbr64
  401064:	31 ed                	xor    %ebp,%ebp
  401066:	49 89 d1             	mov    %rdx,%r9
  401069:	5e                   	pop    %rsi
  40106a:	48 89 e2             	mov    %rsp,%rdx
  40106d:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
  401071:	50                   	push   %rax
  401072:	54                   	push   %rsp
  401073:	45 31 c0             	xor    %r8d,%r8d
  401076:	31 c9                	xor    %ecx,%ecx
  401078:	48 c7 c7 a0 11 40 00 	mov    $0x4011a0,%rdi
  40107f:	ff 15 53 2f 00 00    	call   *0x2f53(%rip)        # 403fd8 <gets@plt+0x2f88>        Enter name:
  401085:	f4                   	hlt
  401086:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
  40108d:	00 00 00 
  401090:	f3 0f 1e fa          	endbr64
  401094:	c3                   	ret
  401095:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
  40109c:	00 00 00 
  40109f:	90                   	nop
  4010a0:	b8 28 40 40 00       	mov    $0x404028,%eax
  4010a5:	48 3d 28 40 40 00    	cmp    $0x404028,%rax
  4010ab:	74 13                	je     4010c0 <gets@plt+0x70>
  4010ad:	b8 00 00 00 00       	mov    $0x0,%eax
  4010b2:	48 85 c0             	test   %rax,%rax
  4010b5:	74 09                	je     4010c0 <gets@plt+0x70>
  4010b7:	bf 28 40 40 00       	mov    $0x404028,%edi
  4010bc:	ff e0                	jmp    *%rax
  4010be:	66 90                	xchg   %ax,%ax
  4010c0:	c3                   	ret
  4010c1:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
  4010c8:	00 00 00 00 
  4010cc:	0f 1f 40 00          	nopl   0x0(%rax)
  4010d0:	be 28 40 40 00       	mov    $0x404028,%esi
  4010d5:	48 81 ee 28 40 40 00 	sub    $0x404028,%rsi
  4010dc:	48 89 f0             	mov    %rsi,%rax
  4010df:	48 c1 ee 3f          	shr    $0x3f,%rsi
  4010e3:	48 c1 f8 03          	sar    $0x3,%rax
  4010e7:	48 01 c6             	add    %rax,%rsi
  4010ea:	48 d1 fe             	sar    $1,%rsi
  4010ed:	74 11                	je     401100 <gets@plt+0xb0>
  4010ef:	b8 00 00 00 00       	mov    $0x0,%eax
  4010f4:	48 85 c0             	test   %rax,%rax
  4010f7:	74 07                	je     401100 <gets@plt+0xb0>
  4010f9:	bf 28 40 40 00       	mov    $0x404028,%edi
  4010fe:	ff e0                	jmp    *%rax
  401100:	c3                   	ret
  401101:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
  401108:	00 00 00 00 
  40110c:	0f 1f 40 00          	nopl   0x0(%rax)
  401110:	f3 0f 1e fa          	endbr64
  401114:	80 3d 0d 2f 00 00 00 	cmpb   $0x0,0x2f0d(%rip)        # 404028 <gets@plt+0x2fd8>
  40111b:	75 13                	jne    401130 <gets@plt+0xe0>
  40111d:	55                   	push   %rbp
  40111e:	48 89 e5             	mov    %rsp,%rbp
  401121:	e8 7a ff ff ff       	call   4010a0 <gets@plt+0x50>
  401126:	c6 05 fb 2e 00 00 01 	movb   $0x1,0x2efb(%rip)        # 404028 <gets@plt+0x2fd8>
  40112d:	5d                   	pop    %rbp
  40112e:	c3                   	ret
  40112f:	90                   	nop
  401130:	c3                   	ret
  401131:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
  401138:	00 00 00 00 
  40113c:	0f 1f 40 00          	nopl   0x0(%rax)
  401140:	f3 0f 1e fa          	endbr64
  401144:	eb 8a                	jmp    4010d0 <gets@plt+0x80>
  401146:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
  40114d:	00 00 00 
  401150:	55                   	push   %rbp
  401151:	48 89 e5             	mov    %rsp,%rbp
  401154:	48 8d 3d a9 0e 00 00 	lea    0xea9(%rip),%rdi        # 402004 <gets@plt+0xfb4>
  40115b:	31 c0                	xor    %eax,%eax
  40115d:	89 c2                	mov    %eax,%edx
  40115f:	48 89 d6             	mov    %rdx,%rsi
  401162:	e8 d9 fe ff ff       	call   401040 <execve@plt>
  401167:	5d                   	pop    %rbp
  401168:	c3                   	ret
  401169:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
  401170:	55                   	push   %rbp
  401171:	48 89 e5             	mov    %rsp,%rbp
  401174:	48 83 ec 10          	sub    $0x10,%rsp
  401178:	48 8d 3d 8d 0e 00 00 	lea    0xe8d(%rip),%rdi        # 40200c <gets@plt+0xfbc>
  40117f:	b0 00                	mov    $0x0,%al
  401181:	e8 aa fe ff ff       	call   401030 <printf@plt>
  401186:	48 8d 7d f4          	lea    -0xc(%rbp),%rdi
  40118a:	e8 c1 fe ff ff       	call   401050 <gets@plt>
  40118f:	48 83 c4 10          	add    $0x10,%rsp
  401193:	5d                   	pop    %rbp
  401194:	c3                   	ret
  401195:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
  40119c:	00 00 00 00 
  4011a0:	55                   	push   %rbp
  4011a1:	48 89 e5             	mov    %rsp,%rbp
  4011a4:	48 83 ec 10          	sub    $0x10,%rsp
  4011a8:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  4011af:	89 7d f8             	mov    %edi,-0x8(%rbp)
  4011b2:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
  4011b6:	e8 b5 ff ff ff       	call   401170 <gets@plt+0x120>
  4011bb:	31 c0                	xor    %eax,%eax
  4011bd:	48 83 c4 10          	add    $0x10,%rsp
  4011c1:	5d                   	pop    %rbp
  4011c2:	c3                   	ret

Disassembly of section .fini:

00000000004011c4 <.fini>:
  4011c4:	f3 0f 1e fa          	endbr64
  4011c8:	48 83 ec 08          	sub    $0x8,%rsp
  4011cc:	48 83 c4 08          	add    $0x8,%rsp
  4011d0:	c3                   	ret

Disassembly of section .rodata:

0000000000402000 <.rodata>:
  402000:	01 00                	add    %eax,(%rax)
  402002:	02 00                	add    (%rax),%al
  402004:	2f                   	(bad)
  402005:	62 69 6e 2f 73       	(bad)
  40200a:	68 00 45 6e 74       	push   $0x746e4500
  40200f:	65 72 20             	gs jb  402032 <gets@plt+0xfe2>
  402012:	6e                   	outsb  %ds:(%rsi),(%dx)
  402013:	61                   	(bad)
  402014:	6d                   	insl   (%dx),%es:(%rdi)
  402015:	65 3a 0a             	cmp    %gs:(%rdx),%cl
	...

Disassembly of section .eh_frame_hdr:

000000000040201c <.eh_frame_hdr>:
  40201c:	01 1b                	add    %ebx,(%rbx)
  40201e:	03 3b                	add    (%rbx),%edi
  402020:	38 00                	cmp    %al,(%rax)
  402022:	00 00                	add    %al,(%rax)
  402024:	06                   	(bad)
  402025:	00 00                	add    %al,(%rax)
  402027:	00 04 f0             	add    %al,(%rax,%rsi,8)
  40202a:	ff                   	(bad)
  40202b:	ff                   	(bad)
  40202c:	7c 00                	jl     40202e <gets@plt+0xfde>
  40202e:	00 00                	add    %al,(%rax)
  402030:	44                   	rex.R
  402031:	f0 ff                	lock (bad)
  402033:	ff 54 00 00          	call   *0x0(%rax,%rax,1)
  402037:	00 74 f0 ff          	add    %dh,-0x1(%rax,%rsi,8)
  40203b:	ff 68 00             	ljmp   *0x0(%rax)
  40203e:	00 00                	add    %al,(%rax)
  402040:	34 f1                	xor    $0xf1,%al
  402042:	ff                   	(bad)
  402043:	ff a4 00 00 00 54 f1 	jmp    *-0xeac0000(%rax,%rax,1)
  40204a:	ff                   	(bad)
  40204b:	ff c4                	inc    %esp
  40204d:	00 00                	add    %al,(%rax)
  40204f:	00 84 f1 ff ff e4 00 	add    %al,0xe4ffff(%rcx,%rsi,8)
	...

Disassembly of section .eh_frame:

0000000000402058 <.eh_frame>:
  402058:	14 00                	adc    $0x0,%al
  40205a:	00 00                	add    %al,(%rax)
  40205c:	00 00                	add    %al,(%rax)
  40205e:	00 00                	add    %al,(%rax)
  402060:	01 7a 52             	add    %edi,0x52(%rdx)
  402063:	00 01                	add    %al,(%rcx)
  402065:	78 10                	js     402077 <gets@plt+0x1027>
  402067:	01 1b                	add    %ebx,(%rbx)
  402069:	0c 07                	or     $0x7,%al
  40206b:	08 90 01 00 00 10    	or     %dl,0x10000001(%rax)
  402071:	00 00                	add    %al,(%rax)
  402073:	00 1c 00             	add    %bl,(%rax,%rax,1)
  402076:	00 00                	add    %al,(%rax)
  402078:	e8 ef ff ff 26       	call   2740206c <gets@plt+0x2700101c>
  40207d:	00 00                	add    %al,(%rax)
  40207f:	00 00                	add    %al,(%rax)
  402081:	44 07                	rex.R (bad)
  402083:	10 10                	adc    %dl,(%rax)
  402085:	00 00                	add    %al,(%rax)
  402087:	00 30                	add    %dh,(%rax)
  402089:	00 00                	add    %al,(%rax)
  40208b:	00 04 f0             	add    %al,(%rax,%rsi,8)
  40208e:	ff                   	(bad)
  40208f:	ff 05 00 00 00 00    	incl   0x0(%rip)        # 402095 <gets@plt+0x1045>
  402095:	00 00                	add    %al,(%rax)
  402097:	00 24 00             	add    %ah,(%rax,%rax,1)
  40209a:	00 00                	add    %al,(%rax)
  40209c:	44 00 00             	add    %r8b,(%rax)
  40209f:	00 80 ef ff ff 40    	add    %al,0x40ffffef(%rax)
  4020a5:	00 00                	add    %al,(%rax)
  4020a7:	00 00                	add    %al,(%rax)
  4020a9:	0e                   	(bad)
  4020aa:	10 46 0e             	adc    %al,0xe(%rsi)
  4020ad:	18 4a 0f             	sbb    %cl,0xf(%rdx)
  4020b0:	0b 77 08             	or     0x8(%rdi),%esi
  4020b3:	80 00 3f             	addb   $0x3f,(%rax)
  4020b6:	1a 3b                	sbb    (%rbx),%bh
  4020b8:	2a 33                	sub    (%rbx),%dh
  4020ba:	24 22                	and    $0x22,%al
  4020bc:	00 00                	add    %al,(%rax)
  4020be:	00 00                	add    %al,(%rax)
  4020c0:	1c 00                	sbb    $0x0,%al
  4020c2:	00 00                	add    %al,(%rax)
  4020c4:	6c                   	insb   (%dx),%es:(%rdi)
  4020c5:	00 00                	add    %al,(%rax)
  4020c7:	00 88 f0 ff ff 19    	add    %cl,0x19fffff0(%rax)
  4020cd:	00 00                	add    %al,(%rax)
  4020cf:	00 00                	add    %al,(%rax)
  4020d1:	41 0e                	rex.B (bad)
  4020d3:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
  4020d9:	54                   	push   %rsp
  4020da:	0c 07                	or     $0x7,%al
  4020dc:	08 00                	or     %al,(%rax)
  4020de:	00 00                	add    %al,(%rax)
  4020e0:	1c 00                	sbb    $0x0,%al
  4020e2:	00 00                	add    %al,(%rax)
  4020e4:	8c 00                	mov    %es,(%rax)
  4020e6:	00 00                	add    %al,(%rax)
  4020e8:	88 f0                	mov    %dh,%al
  4020ea:	ff                   	(bad)
  4020eb:	ff 25 00 00 00 00    	jmp    *0x0(%rip)        # 4020f1 <gets@plt+0x10a1>
  4020f1:	41 0e                	rex.B (bad)
  4020f3:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
  4020f9:	60                   	(bad)
  4020fa:	0c 07                	or     $0x7,%al
  4020fc:	08 00                	or     %al,(%rax)
  4020fe:	00 00                	add    %al,(%rax)
  402100:	1c 00                	sbb    $0x0,%al
  402102:	00 00                	add    %al,(%rax)
  402104:	ac                   	lods   %ds:(%rsi),%al
  402105:	00 00                	add    %al,(%rax)
  402107:	00 98 f0 ff ff 23    	add    %bl,0x23fffff0(%rax)
  40210d:	00 00                	add    %al,(%rax)
  40210f:	00 00                	add    %al,(%rax)
  402111:	41 0e                	rex.B (bad)
  402113:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
  402119:	5e                   	pop    %rsi
  40211a:	0c 07                	or     $0x7,%al
  40211c:	08 00                	or     %al,(%rax)
  40211e:	00 00                	add    %al,(%rax)
  402120:	00 00                	add    %al,(%rax)
	...

Disassembly of section .init_array:

0000000000403df8 <.init_array>:
  403df8:	40 11 40 00          	rex adc %eax,0x0(%rax)
  403dfc:	00 00                	add    %al,(%rax)
	...

Disassembly of section .fini_array:

0000000000403e00 <.fini_array>:
  403e00:	10 11                	adc    %dl,(%rcx)
  403e02:	40 00 00             	rex add %al,(%rax)
  403e05:	00 00                	add    %al,(%rax)
	...

Disassembly of section .dynamic:

0000000000403e08 <.dynamic>:
  403e08:	01 00                	add    %eax,(%rax)
  403e0a:	00 00                	add    %al,(%rax)
  403e0c:	00 00                	add    %al,(%rax)
  403e0e:	00 00                	add    %al,(%rax)
  403e10:	26 00 00             	es add %al,(%rax)
  403e13:	00 00                	add    %al,(%rax)
  403e15:	00 00                	add    %al,(%rax)
  403e17:	00 0c 00             	add    %cl,(%rax,%rax,1)
  403e1a:	00 00                	add    %al,(%rax)
  403e1c:	00 00                	add    %al,(%rax)
  403e1e:	00 00                	add    %al,(%rax)
  403e20:	00 10                	add    %dl,(%rax)
  403e22:	40 00 00             	rex add %al,(%rax)
  403e25:	00 00                	add    %al,(%rax)
  403e27:	00 0d 00 00 00 00    	add    %cl,0x0(%rip)        # 403e2d <gets@plt+0x2ddd>
  403e2d:	00 00                	add    %al,(%rax)
  403e2f:	00 c4                	add    %al,%ah
  403e31:	11 40 00             	adc    %eax,0x0(%rax)
  403e34:	00 00                	add    %al,(%rax)
  403e36:	00 00                	add    %al,(%rax)
  403e38:	19 00                	sbb    %eax,(%rax)
  403e3a:	00 00                	add    %al,(%rax)
  403e3c:	00 00                	add    %al,(%rax)
  403e3e:	00 00                	add    %al,(%rax)
  403e40:	f8                   	clc
  403e41:	3d 40 00 00 00       	cmp    $0x40,%eax
  403e46:	00 00                	add    %al,(%rax)
  403e48:	1b 00                	sbb    (%rax),%eax
  403e4a:	00 00                	add    %al,(%rax)
  403e4c:	00 00                	add    %al,(%rax)
  403e4e:	00 00                	add    %al,(%rax)
  403e50:	08 00                	or     %al,(%rax)
  403e52:	00 00                	add    %al,(%rax)
  403e54:	00 00                	add    %al,(%rax)
  403e56:	00 00                	add    %al,(%rax)
  403e58:	1a 00                	sbb    (%rax),%al
  403e5a:	00 00                	add    %al,(%rax)
  403e5c:	00 00                	add    %al,(%rax)
  403e5e:	00 00                	add    %al,(%rax)
  403e60:	00 3e                	add    %bh,(%rsi)
  403e62:	40 00 00             	rex add %al,(%rax)
  403e65:	00 00                	add    %al,(%rax)
  403e67:	00 1c 00             	add    %bl,(%rax,%rax,1)
  403e6a:	00 00                	add    %al,(%rax)
  403e6c:	00 00                	add    %al,(%rax)
  403e6e:	00 00                	add    %al,(%rax)
  403e70:	08 00                	or     %al,(%rax)
  403e72:	00 00                	add    %al,(%rax)
  403e74:	00 00                	add    %al,(%rax)
  403e76:	00 00                	add    %al,(%rax)
  403e78:	f5                   	cmc
  403e79:	fe                   	(bad)
  403e7a:	ff 6f 00             	ljmp   *0x0(%rdi)
  403e7d:	00 00                	add    %al,(%rax)
  403e7f:	00 a0 03 40 00 00    	add    %ah,0x4003(%rax)
  403e85:	00 00                	add    %al,(%rax)
  403e87:	00 05 00 00 00 00    	add    %al,0x0(%rip)        # 403e8d <gets@plt+0x2e3d>
  403e8d:	00 00                	add    %al,(%rax)
  403e8f:	00 50 04             	add    %dl,0x4(%rax)
  403e92:	40 00 00             	rex add %al,(%rax)
  403e95:	00 00                	add    %al,(%rax)
  403e97:	00 06                	add    %al,(%rsi)
  403e99:	00 00                	add    %al,(%rax)
  403e9b:	00 00                	add    %al,(%rax)
  403e9d:	00 00                	add    %al,(%rax)
  403e9f:	00 c0                	add    %al,%al
  403ea1:	03 40 00             	add    0x0(%rax),%eax
  403ea4:	00 00                	add    %al,(%rax)
  403ea6:	00 00                	add    %al,(%rax)
  403ea8:	0a 00                	or     (%rax),%al
  403eaa:	00 00                	add    %al,(%rax)
  403eac:	00 00                	add    %al,(%rax)
  403eae:	00 00                	add    %al,(%rax)
  403eb0:	56                   	push   %rsi
  403eb1:	00 00                	add    %al,(%rax)
  403eb3:	00 00                	add    %al,(%rax)
  403eb5:	00 00                	add    %al,(%rax)
  403eb7:	00 0b                	add    %cl,(%rbx)
  403eb9:	00 00                	add    %al,(%rax)
  403ebb:	00 00                	add    %al,(%rax)
  403ebd:	00 00                	add    %al,(%rax)
  403ebf:	00 18                	add    %bl,(%rax)
  403ec1:	00 00                	add    %al,(%rax)
  403ec3:	00 00                	add    %al,(%rax)
  403ec5:	00 00                	add    %al,(%rax)
  403ec7:	00 15 00 00 00 00    	add    %dl,0x0(%rip)        # 403ecd <gets@plt+0x2e7d>
	...
  403ed5:	00 00                	add    %al,(%rax)
  403ed7:	00 03                	add    %al,(%rbx)
  403ed9:	00 00                	add    %al,(%rax)
  403edb:	00 00                	add    %al,(%rax)
  403edd:	00 00                	add    %al,(%rax)
  403edf:	00 e8                	add    %ch,%al
  403ee1:	3f                   	(bad)
  403ee2:	40 00 00             	rex add %al,(%rax)
  403ee5:	00 00                	add    %al,(%rax)
  403ee7:	00 02                	add    %al,(%rdx)
  403ee9:	00 00                	add    %al,(%rax)
  403eeb:	00 00                	add    %al,(%rax)
  403eed:	00 00                	add    %al,(%rax)
  403eef:	00 48 00             	add    %cl,0x0(%rax)
  403ef2:	00 00                	add    %al,(%rax)
  403ef4:	00 00                	add    %al,(%rax)
  403ef6:	00 00                	add    %al,(%rax)
  403ef8:	14 00                	adc    $0x0,%al
  403efa:	00 00                	add    %al,(%rax)
  403efc:	00 00                	add    %al,(%rax)
  403efe:	00 00                	add    %al,(%rax)
  403f00:	07                   	(bad)
  403f01:	00 00                	add    %al,(%rax)
  403f03:	00 00                	add    %al,(%rax)
  403f05:	00 00                	add    %al,(%rax)
  403f07:	00 17                	add    %dl,(%rdi)
  403f09:	00 00                	add    %al,(%rax)
  403f0b:	00 00                	add    %al,(%rax)
  403f0d:	00 00                	add    %al,(%rax)
  403f0f:	00 18                	add    %bl,(%rax)
  403f11:	05 40 00 00 00       	add    $0x40,%eax
  403f16:	00 00                	add    %al,(%rax)
  403f18:	07                   	(bad)
  403f19:	00 00                	add    %al,(%rax)
  403f1b:	00 00                	add    %al,(%rax)
  403f1d:	00 00                	add    %al,(%rax)
  403f1f:	00 e8                	add    %ch,%al
  403f21:	04 40                	add    $0x40,%al
  403f23:	00 00                	add    %al,(%rax)
  403f25:	00 00                	add    %al,(%rax)
  403f27:	00 08                	add    %cl,(%rax)
  403f29:	00 00                	add    %al,(%rax)
  403f2b:	00 00                	add    %al,(%rax)
  403f2d:	00 00                	add    %al,(%rax)
  403f2f:	00 30                	add    %dh,(%rax)
  403f31:	00 00                	add    %al,(%rax)
  403f33:	00 00                	add    %al,(%rax)
  403f35:	00 00                	add    %al,(%rax)
  403f37:	00 09                	add    %cl,(%rcx)
  403f39:	00 00                	add    %al,(%rax)
  403f3b:	00 00                	add    %al,(%rax)
  403f3d:	00 00                	add    %al,(%rax)
  403f3f:	00 18                	add    %bl,(%rax)
  403f41:	00 00                	add    %al,(%rax)
  403f43:	00 00                	add    %al,(%rax)
  403f45:	00 00                	add    %al,(%rax)
  403f47:	00 fe                	add    %bh,%dh
  403f49:	ff                   	(bad)
  403f4a:	ff 6f 00             	ljmp   *0x0(%rdi)
  403f4d:	00 00                	add    %al,(%rax)
  403f4f:	00 b8 04 40 00 00    	add    %bh,0x4004(%rax)
  403f55:	00 00                	add    %al,(%rax)
  403f57:	00 ff                	add    %bh,%bh
  403f59:	ff                   	(bad)
  403f5a:	ff 6f 00             	ljmp   *0x0(%rdi)
  403f5d:	00 00                	add    %al,(%rax)
  403f5f:	00 01                	add    %al,(%rcx)
  403f61:	00 00                	add    %al,(%rax)
  403f63:	00 00                	add    %al,(%rax)
  403f65:	00 00                	add    %al,(%rax)
  403f67:	00 f0                	add    %dh,%al
  403f69:	ff                   	(bad)
  403f6a:	ff 6f 00             	ljmp   *0x0(%rdi)
  403f6d:	00 00                	add    %al,(%rax)
  403f6f:	00 a6 04 40 00 00    	add    %ah,0x4004(%rsi)
	...

Disassembly of section .got:

0000000000403fd8 <.got>:
	...

Disassembly of section .got.plt:

0000000000403fe8 <.got.plt>:
  403fe8:	08 3e                	or     %bh,(%rsi)
  403fea:	40 00 00             	rex add %al,(%rax)
	...
  403ffd:	00 00                	add    %al,(%rax)
  403fff:	00 36                	add    %dh,(%rsi)
  404001:	10 40 00             	adc    %al,0x0(%rax)
  404004:	00 00                	add    %al,(%rax)
  404006:	00 00                	add    %al,(%rax)
  404008:	46 10 40 00          	rex.RX adc %r8b,0x0(%rax)
  40400c:	00 00                	add    %al,(%rax)
  40400e:	00 00                	add    %al,(%rax)
  404010:	56                   	push   %rsi
  404011:	10 40 00             	adc    %al,0x0(%rax)
  404014:	00 00                	add    %al,(%rax)
	...

Disassembly of section .data:

0000000000404018 <.data>:
	...

Disassembly of section .comment:

0000000000000000 <.comment>:
   0:	47                   	rex.RXB
   1:	43                   	rex.XB
   2:	43 3a 20             	rex.XB cmp (%r8),%spl
   5:	28 55 62             	sub    %dl,0x62(%rbp)
   8:	75 6e                	jne    78 <printf@plt-0x400fb8>
   a:	74 75                	je     81 <printf@plt-0x400faf>
   c:	20 31                	and    %dh,(%rcx)
   e:	34 2e                	xor    $0x2e,%al
  10:	32 2e                	xor    (%rsi),%ch
  12:	30 2d 34 75 62 75    	xor    %ch,0x75627534(%rip)        # 7562754c <gets@plt+0x752264fc>
  18:	6e                   	outsb  %ds:(%rsi),(%dx)
  19:	74 75                	je     90 <printf@plt-0x400fa0>
  1b:	32 7e 32             	xor    0x32(%rsi),%bh
  1e:	34 2e                	xor    $0x2e,%al
  20:	30 34 29             	xor    %dh,(%rcx,%rbp,1)
  23:	20 31                	and    %dh,(%rcx)
  25:	34 2e                	xor    $0x2e,%al
  27:	32 2e                	xor    (%rsi),%ch
  29:	30 00                	xor    %al,(%rax)
  2b:	55                   	push   %rbp
  2c:	62 75 6e 74 75       	(bad)
  31:	20 63 6c             	and    %ah,0x6c(%rbx)
  34:	61                   	(bad)
  35:	6e                   	outsb  %ds:(%rsi),(%dx)
  36:	67 20 76 65          	and    %dh,0x65(%esi)
  3a:	72 73                	jb     af <printf@plt-0x400f81>
  3c:	69 6f 6e 20 31 38 2e 	imul   $0x2e383120,0x6e(%rdi),%ebp
  43:	31 2e                	xor    %ebp,(%rsi)
  45:	33 20                	xor    (%rax),%esp
  47:	28 31                	sub    %dh,(%rcx)
  49:	75 62                	jne    ad <printf@plt-0x400f83>
  4b:	75 6e                	jne    bb <printf@plt-0x400f75>
  4d:	74 75                	je     c4 <printf@plt-0x400f6c>
  4f:	31 29                	xor    %ebp,(%rcx)
	...

