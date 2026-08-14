# nmmp-Fast
专门对nmmp进行多线程优化，还优化了c代码生成逻辑，速度可以快2-3倍

新增参数:
-j/--job
``` bash
java -jar nmmp.jar -jN/--jobN apk apkfile.apk
```

以下是原nmmp的README
# nmmp
基于dex-vm运行dalvik字节码从而对dex进行保护，增加反编译难度。
项目分为两部分nmm-protect是纯java项目，对dex进行转换，把dex里数据转为c结构体，opcode随机化生成ndk项目,编译后生成加固后的apk。nmmvm是一个安卓项目，包含dex-vm实现及各种dalvik指令的测试等。
# nmm-protect

+ 配置ndk及环境变量

不编译nmm-protect，可以直接看使用它生成项目及最后的apk，[一个对apk处理的例子](https://github.com/mcpackms/nmmp/releases/download/demo/demo.zip)。

例子在linux环境下测试的，windows也应该没问题,先安装好JDK及android sdk和ndk。

下载[vm-protect.jar](https://github.com/mcpackms/nmmp/releases/download/last/vm-protect-2023-07-08-0942.jar),配置好环境变量ANDROID_SDK_HOME、ANDROID_NDK_HOME:
``` bash
export ANDROID_SDK_HOME=/opt/android-sdk
export ANDROID_NDK_HOME=/opt/android-sdk/ndk/22.1.7171670
export CMAKE_PATH=/opt/android-sdk/cmake/3.18.1/   #可选，不配置的话直接使用/bin/cmake
```
+ apk加固
  
``` bash
java -jar vm-protect-xxx.jar apk input.apk convertRules.txt mapping.txt
```
执行完毕会在input.apk所在的目录下生成一个build目录，里面包含最后输出的apk(build/input-protect.apk)，完整的c项目dex2c(基于cmake)及处理过程中生成的.dex等。  
第一次运行后会在jar位置生成tools目录，里面有config.json可以编辑它配置安卓sdk，ndk相关路径。

有朋友写了个GUI界面，能更方便使用，需要的可以去试试，https://github.com/TimScriptov/nmmp

生成的apk需要使用zipalign对齐（新版本已使用zipflinger处理apk,可以不用使用单独的zipalign）及apksigner签名才能安装使用
``` bash
apksigner sign --ks ~/.myapp.jks build/input-protect-align.apk
```
+ aab加固
  
``` bash
java -jar vm-protect-xxx.jar aab test.aab convertRules.txt
```
之后需要使用jarsigner签名，也可以集成signflinger进行签名
``` bash
jarsigner -keystore ~/.myapp.jks -storepass pass -keypass pass test-protect.aab keyAlias
```

+ aar加固
``` bash
java -jar vm-protect-xxx.jar aar testModule.aar convertRules.txt
```

+ 输出 so 库名称

默认生成的 so 库名为 `libnmmp.so`（vm 子库为 `libnmmvm.so`），可按下面优先级（高→低）自定义：
1. 命令行参数:
``` bash
java -jar vm-protect-xxx.jar apk -libname=mymsp --vmlibname=myvm00 input.apk convertRules.txt mapping.txt
```
   同时支持 `--libname=` 长选项形式。
2. 环境变量:
   ``` bash
   export NMMP_LIB_NAME=mymsp
   export NMMP_VM_LIB_NAME=myvm
   ```
3. jar 旁的 `tools/config.json`（首次运行自动生成，也可手动编辑）中字段:
   ``` json
   "lib_name": "nmmp",
   "vm_lib_name": "nmmvm"
   ```
自定义后，CMake 库名、输出 `libxxx.so` 文件名及注入加载入口都会同步生效。

+ 并行编译

可用 `-j <n>` 或 `--jobs=<n>` 指定并行度（默认取 CPU 核数），体现在三处: 多 dex 同时转换、生成 C 代码拆分、多 ABI 的 CMake/ninja 并行编译。

+ C 代码文件拆分

为充分利用 ninja 并行编译并避免单文件过大，每个 dex 生成的 C 代码会拆分:
- 每个文件最多 500 个方法，最多 1000 个文件，超出部分自动落入最后一个文件;
- 每个 dex 生成 `<dex>_resolver.h/.c`（符号表/解析器）和一组 `<dex>_native_functions_<i>.c`，各为独立编译单元并行编译;
- 多个 dex 的同名符号均以 dex 名作前缀（如 `classes2_*`），可合并链接进同一个 so;
- 文件数和每个文件的方法数可在 `JniCodeGenerator` 中调整。

+ 下载及编译项目
``` bash
git clone https://github.com/mcpackms/nmmp.git
cd nmmp/nmm-protect
./gradlew arsc:build
./gradlew build
```
成功后会在build/libs生成可直接执行的fatjar。
+ 需要转换的类和方法规则

无转换规则文件，则会转换dex里所有class里的方法（除了构造方法和静态初始化方法）。规则只支持一些简单的情况：
``` java
//支持的规则比较简单，*只是被转成正则表达式的.*，支持一些简单的继承关系
class * extends android.app.Activity
class * implements java.io.Serializable
class my.package.AClass
class my.package.* { *; }
class * extends java.util.ArrayList {
  if*;
}


class A {
}
class B extends A {
}
class C extends B {
}
//比如'class * extends A' 只会匹配B而不会再匹配C
```


# nmmvm
nmmvm是dex虚拟机具体实现，入口就一个函数:
``` c
jvalue vmInterpret(
        JNIEnv *env,
        const vmCode *code,
        const vmResolver *dvmResolver
);

typedef struct {
    const u2 *insns;             //指令
    const u4 insnsSize;          //指令大小
    regptr_t *regs;                    //寄存器
    u1 *reg_flags;               //寄存器数据类型标记,主要标记是否为对象
    const u1 *triesHandlers;     //异常表
} vmCode;


typedef struct {

    const vmField *(*dvmResolveField)(JNIEnv *env, u4 idx, bool isStatic);

    const vmMethod *(*dvmResolveMethod)(JNIEnv *env, u4 idx, bool isStatic);

    //从类型常量池取得类型名
    const char *(*dvmResolveTypeUtf)(JNIEnv *env, u4 idx);

    //直接返回jclass对象,本地引用需要释放引用
    jclass (*dvmResolveClass)(JNIEnv *env, u4 idx);

    //根据类型名得到class
    jclass (*dvmFindClass)(JNIEnv *env, const char *type);

    //const_string指令加载的字符串对象
    jstring (*dvmConstantString)(JNIEnv *env, u4 idx);

} vmResolver;

```
vmCode提供执行所需要的指令、异常表及寄存器空间，vmResolver包含一组函数指针，提供运行时的符号，比如field，method等。通过自定义这两个参数来实现不同的加固方式，比如项目里的test.cpp有一个简单的基于libdex实现的vmResolver，它主要用于开发测试。而nmm-protect实现的是把.dex相关数据转换为c结构体，还包含了opcode随机化等，基本可实际使用。

# aar模块加固
目前已实现模块相关加固，用法同apk加固类似，如果有问题可以提issue。


# Licences
nmm-protect 以gpl协议发布,[nmm-protect licence](https://github.com/mcpackms/nmmp/blob/master/nmm-protect/LICENSE), dex-vm部分以Apache协议发布, [nmmvm licence](https://github.com/mcpackms/nmmp/blob/master/nmmvm/LICENSE). 只有vm部分会打包进apk中, nmm-protect只是转换dex,协议不影响生成的结果.
