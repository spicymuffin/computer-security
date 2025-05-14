
licensechk-signed:     file format elf64-x86-64


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
