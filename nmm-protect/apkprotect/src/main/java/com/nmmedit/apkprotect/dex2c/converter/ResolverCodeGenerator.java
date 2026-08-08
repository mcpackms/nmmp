package com.nmmedit.apkprotect.dex2c.converter;

import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.reference.FieldReference;
import com.android.tools.smali.dexlib2.iface.reference.MethodReference;
import com.android.tools.smali.dexlib2.util.MethodUtil;
import com.nmmedit.apkprotect.util.ModifiedUtf8;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.io.UTFDataFormatException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;

/**
 * 根据dex生成符号解析代码,比如字符串常量池,类型常量池这些
 *
 * <p>输出两个文件:
 * <ul>
 *   <li>{@code <dex>_resolver.h} — 类型定义、extern 声明、宏、函数声明,供所有 native functions 文件 include</li>
 *   <li>{@code <dex>_resolver.c} — 变量定义与函数实现,单独编译</li>
 * </ul>
 * 所有跨编译单元符号均以 dex 名前缀避免多 dex 链接冲突。
 */

public class ResolverCodeGenerator {


    private final References references;

    //当前 dex 的符号前缀,如 classes2,避免多个 dex 生成的符号在同一个 so 里冲突
    private String symbolPrefix;

    private Writer header;
    private Writer source;

    public ResolverCodeGenerator(DexBackedDexFile dexFile,
                                 @Nonnull ClassAnalyzer analyzer
    ) {

        references = new References(dexFile, analyzer);
    }

    public References getReferences() {
        return references;
    }

    public void generate(Writer headerWriter, Writer sourceWriter, @Nonnull String dexName) throws IOException {
        this.symbolPrefix = dexName;
        this.header = headerWriter;
        this.source = sourceWriter;

        String guard = (dexName + "_RESOLVER_H").toUpperCase().replaceAll("[^A-Z0-9_]", "_");

        // ===== 头文件:声明部分 =====
        headerWriter.write("#ifndef " + guard + "\n");
        headerWriter.write("#define " + guard + "\n\n");
        headerWriter.write("#include <jni.h>\n");
        headerWriter.write("#include \"vm.h\"\n");
        headerWriter.write("#include \"GlobalCache.h\"\n");
        headerWriter.write("#include \"ConstantPool.h\"\n\n\n");

        // ===== 源文件:定义部分 =====
        sourceWriter.write(String.format("#include \"%s_resolver.h\"\n", dexName));
        sourceWriter.write("#include <stdio.h>\n");
        sourceWriter.write("#include <stdlib.h>\n");
        sourceWriter.write("#include <string.h>\n");
        sourceWriter.write("#include <pthread.h>\n\n\n");

        generateStringPool();
        generateTypePool();

        //额外添加的,方便生成结构体
        generateClassNamePool();
        generateSignaturePool();

        generateFieldPool();

        generateMethodPool();

        generateStringConstants();

        //生成初始化函数及符号解析器结构体
        generateResolver();

        headerWriter.write("\n#endif //" + guard + "\n");
        headerWriter.flush();
        sourceWriter.flush();
    }

    /**
     * 带 dex 前缀的符号名
     */
    private String sym(String base) {
        return symbolPrefix + "_" + base;
    }

    //产生const-string*指令对应的缓存
    private void generateStringConstants() throws IOException {
        final References references = this.references;
        final List<String> constantStringPool = references.getConstantStringPool();

        final int[] constStringIds = new int[constantStringPool.size()];
        for (int i = 0; i < constantStringPool.size(); i++) {
            //把得到字符串索引
            constStringIds[i] = references.getStringItemIndex(constantStringPool.get(i));
        }

        //字符串常量索引缓存,const-string指令索引被重写，直接根据索引得到字符串索引，然后创建jstring
        header.write(
                "\n//字符串常量索引缓存,const-string指令索引被重写，直接根据索引得到字符串索引，然后创建jstring\n" +
                        "typedef struct {\n" +
                        "    u4 idx;\n" +
                        "} ConstStringId;\n\n"
        );
        header.write("extern const ConstStringId " + sym("gStringConstantIds") + "[];\n");
        header.write("extern jstring " + sym("gStringConstants") + "[];\n\n");

        source.write("extern const ConstStringId " + sym("gStringConstantIds") + "[] = {\n");
        for (int offset : constStringIds) {
            source.write(String.format("    {.idx=0x%04x},\n", offset));
        }
        source.write("};\n");

        source.write(String.format("jstring %s[%d];\n\n", sym("gStringConstants"), constStringIds.length));
    }

    private void generateResolver() throws IOException {
        //宏定义放头文件,供所有native functions文件使用
        header.write(
                "#define STRING_BY_ID(_idx) ((const char *) (" + sym("gBaseStrPtr") + " + " + sym("gStringIds") + "[_idx].off))\n" +
                        "\n" +
                        "#define STRING_BY_TYPE_ID(_idx) (STRING_BY_ID(" + sym("gTypeIds") + "[_idx].idx))\n" +
                        "\n" +
                        "#define STRING_BY_CLASS_ID(_idx) (STRING_BY_ID(" + sym("gClassIds") + "[_idx].idx))\n" +
                        "\n" +
                        "#define STRING_BY_SIGNATURE_ID(_idx) (STRING_BY_ID(" + sym("gSignatureIds") + "[_idx].idx))\n" +
                        "\n" +
                        "#define FIND_CLASS_BY_NAME(_className)                          \\\n" +
                        "    clazz = (*env)->FindClass(env, _className);                 \\\n" +
                        "    if (clazz == NULL) {                                        \\\n" +
                        "        /*转换异常类型,保持和正常java抛一样异常*/                   \\\n" +
                        "        (*env)->ExceptionClear(env);                            \\\n" +
                        "        " + sym("vmThrowNoClassDefFoundError") + "(env, _className); \\\n" +
                        "        return NULL;                                            \\\n" +
                        "    }\n" +
                        "\n\n"
        );

        //函数声明
        header.write(
                "void " + sym("resolver_init") + "(JNIEnv *env);\n" +
                        "\n" +
                        "void " + sym("vmThrowNoClassDefFoundError") + "(JNIEnv *env, const char *msg);\n" +
                        "\n" +
                        "void " + sym("vmThrowNoSuchFieldError") + "(JNIEnv *env, const char *msg);\n" +
                        "\n" +
                        "void " + sym("vmThrowNoSuchMethodError") + "(JNIEnv *env, const char *msg);\n" +
                        "\n" +
                        "const vmField *" + sym("dvmResolveField") + "(JNIEnv *env, u4 idx, bool isStatic);\n" +
                        "\n" +
                        "const vmMethod *" + sym("dvmResolveMethod") + "(JNIEnv *env, u4 idx, bool isStatic);\n" +
                        "\n" +
                        "jstring " + sym("dvmConstantString") + "(JNIEnv *env, u4 idx);\n" +
                        "\n" +
                        "const char *" + sym("dvmResolveTypeUtf") + "(JNIEnv *env, u4 idx);\n" +
                        "\n" +
                        "jclass " + sym("dvmResolveClass") + "(JNIEnv *env, u4 idx);\n" +
                        "\n" +
                        "jclass " + sym("dvmFindClass") + "(JNIEnv *env, const char *type);\n" +
                        "\n" +
                        "extern const vmResolver " + sym("dvmResolver") + ";\n" +
                        "\n\n"
        );

        source.write("void " + sym("resolver_init") + "(JNIEnv *env) {\n" +
                "    if(sizeof(" + sym("gFields") + ") == 0) return;\n" +
                "    if(sizeof(" + sym("gMethods") + ") == 0) return;\n" +
                "    if(sizeof(" + sym("gStringConstants") + ") == 0) return;\n" +
                "    memset(" + sym("gFields") + ", 0, sizeof(" + sym("gFields") + "));\n" +
                "    memset(" + sym("gMethods") + ", 0, sizeof(" + sym("gMethods") + "));\n" +
                "    memset(" + sym("gStringConstants") + ", 0, sizeof(" + sym("gStringConstants") + "));\n" +
                "}\n" +
                "\n" +
                "void " + sym("vmThrowNoClassDefFoundError") + "(JNIEnv *env, const char *msg) {\n" +
                "    (*env)->ThrowNew(env, gVm.exNoClassDefFoundError, msg);\n" +
                "}\n" +
                "\n" +
                "void " + sym("vmThrowNoSuchFieldError") + "(JNIEnv *env, const char *msg) {\n" +
                "    (*env)->ThrowNew(env, gVm.exNoSuchFieldError, msg);\n" +
                "}\n" +
                "\n" +
                "void " + sym("vmThrowNoSuchMethodError") + "(JNIEnv *env, const char *msg) {\n" +
                "    (*env)->ThrowNew(env, gVm.exNoSuchMethodError, msg);\n" +
                "}\n" +
                "\n" +
                "const vmField *" + sym("dvmResolveField") + "(JNIEnv *env, u4 idx, bool isStatic) {\n" +
                "    vmField *field = &" + sym("gFields") + "[idx];\n" +
                "    if (field->fieldId == NULL) {\n" +
                "        FieldId fieldId = " + sym("gFieldIds") + "[idx];\n" +
                "\n" +
                "        jclass clazz;\n" +
                "        FIND_CLASS_BY_NAME(STRING_BY_CLASS_ID(fieldId.classIdx));\n" +
                "\n" +
                "        const char *type = STRING_BY_TYPE_ID(fieldId.typeIdx);\n" +
                "        const char *name = STRING_BY_ID(fieldId.nameIdx);\n" +
                "\n" +
                "        field->classIdx = fieldId.classIdx;\n" +
                "        field->type = (*type == '[') ? 'L' : *type;\n" +
                "\n" +
                "        //和方法解析同理,最后赋值fieldId\n" +
                "        jfieldID fid;\n" +
                "        if (isStatic) {\n" +
                "            fid = (*env)->GetStaticFieldID(env, clazz, name, type);\n" +
                "        } else {\n" +
                "            fid = (*env)->GetFieldID(env, clazz, name, type);\n" +
                "        }\n" +
                "        if (fid == NULL) {\n" +
                "            (*env)->DeleteLocalRef(env, clazz);\n" +
                "\n" +
                "            (*env)->ExceptionClear(env);\n" +
                "            " + sym("vmThrowNoSuchFieldError") + "(env, name);\n" +
                "            return NULL;\n" +
                "        }\n" +
                "        (*env)->DeleteLocalRef(env, clazz);\n" +
                "\n" +
                "\n" +
                "        field->fieldId = fid;\n" +
                "\n" +
                "    }\n" +
                "    return field;\n" +
                "}\n" +
                "\n" +
                "const vmMethod *" + sym("dvmResolveMethod") + "(JNIEnv *env, u4 idx, bool isStatic) {\n" +
                "    vmMethod *method = &" + sym("gMethods") + "[idx];\n" +
                "    if (method->methodId == NULL) {\n" +
                "        MethodId methodId = " + sym("gMethodIds") + "[idx];\n" +
                "\n" +
                "        jclass clazz;\n" +
                "        FIND_CLASS_BY_NAME(STRING_BY_CLASS_ID(methodId.classIdx));\n" +
                "\n" +
                "        method->shorty = STRING_BY_ID(methodId.shortyIdx);\n" +
                "\n" +
                "        method->classIdx = methodId.classIdx;\n" +
                "\n" +
                "        const char *name = STRING_BY_ID(methodId.nameIdx);\n" +
                "        const char *sig = STRING_BY_SIGNATURE_ID(methodId.sigIdx);\n" +
                "\n" +
                "        jmethodID mid;\n" +
                "        if (isStatic) {\n" +
                "            mid = (*env)->GetStaticMethodID(env, clazz, name, sig);\n" +
                "        } else {\n" +
                "            mid = (*env)->GetMethodID(env, clazz, name, sig);\n" +
                "        }\n" +
                "        if (mid == NULL) {\n" +
                "            (*env)->DeleteLocalRef(env, clazz);\n" +
                "\n" +
                "            (*env)->ExceptionClear(env);\n" +
                "            " + sym("vmThrowNoSuchMethodError") + "(env, name);\n" +
                "            return NULL;\n" +
                "        }\n" +
                "        (*env)->DeleteLocalRef(env, clazz);\n" +
                "\n" +
                "        //只根据method->methodId判断是否需要解析,最后赋值为了防止结构体解析一半被其他线程使用从而导致错误\n" +
                "        //todo 赋值需为原子操作\n" +
                "\n" +
                "        method->methodId = mid;\n" +
                "\n" +
                "    }\n" +
                "    return method;\n" +
                "}\n" +
                "\n" +
                "static pthread_mutex_t str_mutex = PTHREAD_MUTEX_INITIALIZER;\n" +

                "jstring " + sym("dvmConstantString") + "(JNIEnv *env, u4 idx) {\n" +
                "    //先查找索引位置是否存在缓存,不用频繁创建string对象\n" +
                "    if (" + sym("gStringConstants") + "[idx] == NULL) {\n" +
                "        pthread_mutex_lock(&str_mutex);\n" +
                "        jstring str;\n" +
                "        if (" + sym("gStringConstants") + "[idx] == NULL) {\n" +
                "            str = (*env)->NewStringUTF(env, STRING_BY_ID(" + sym("gStringConstantIds") + "[idx].idx));\n" +
                "            " + sym("gStringConstants") + "[idx] = (*env)->NewGlobalRef(env, str);\n" +
                "        } else {\n" +
                "            str = (*env)->NewLocalRef(env, " + sym("gStringConstants") + "[idx]);\n" +
                "        }\n" +
                "        pthread_mutex_unlock(&str_mutex);\n" +
                "\n" +
                "        return str;\n" +
                "    } else {\n" +
                "        return (*env)->NewLocalRef(env, " + sym("gStringConstants") + "[idx]);\n" +
                "    }\n" +
                "}\n" +
                "\n" +
                "\n" +
                "const char *" + sym("dvmResolveTypeUtf") + "(JNIEnv *env, u4 idx) {\n" +
                "    return STRING_BY_TYPE_ID(idx);\n" +
                "}\n" +
                "\n" +
                "jclass " + sym("dvmResolveClass") + "(JNIEnv *env, u4 idx) {\n" +
                "    jclass clazz = getCacheClass(env, STRING_BY_TYPE_ID(idx));\n" +
                "    if (clazz != NULL) {\n" +
                "        return (jclass) (*env)->NewLocalRef(env, clazz);\n" +
                "    }\n" +
                "\n" +
                "    FIND_CLASS_BY_NAME(STRING_BY_CLASS_ID(idx));\n" +
                "\n" +
                "    return clazz;\n" +
                "}\n\n");

        //因为类型需要去掉开头的'L'和结尾的';',所以最大最大class名不需要再加1表示字符串结尾
        source.write(String.format(
                "jclass " + sym("dvmFindClass") + "(JNIEnv *env, const char *type) {\n" +
                        "    jclass clazz = getCacheClass(env, type);\n" +
                        "    if (clazz != NULL) {\n" +
                        "        return (jclass) (*env)->NewLocalRef(env, clazz);\n" +
                        "    }\n" +
                        "    if (*type == 'L') {\n" +
                        "        char clazzName[%d];\n" +
                        "        size_t len = strlen(type);\n" +
                        "        strncpy(clazzName, type + 1, len - 2);\n" +
                        "        clazzName[len - 2] = 0;\n" +
                        "\n" +
                        "        FIND_CLASS_BY_NAME(clazzName);\n" +
                        "\n" +
                        "        return clazz;\n" +
                        "    }\n" +
                        "\n" +
                        "    FIND_CLASS_BY_NAME(type);\n" +
                        "\n" +
                        "    return clazz;\n" +
                        "}\n\n", references.getMaxTypeLen()));
        source.write("extern const vmResolver " + sym("dvmResolver") + " = {\n" +
                "        .dvmResolveField = " + sym("dvmResolveField") + ",\n" +
                "        .dvmResolveMethod = " + sym("dvmResolveMethod") + ",\n" +
                "        .dvmResolveTypeUtf = " + sym("dvmResolveTypeUtf") + ",\n" +
                "        .dvmResolveClass = " + sym("dvmResolveClass") + ",\n" +
                "        .dvmFindClass = " + sym("dvmFindClass") + ",\n" +
                "        .dvmConstantString = " + sym("dvmConstantString") + ",\n" +
                "};\n" +
                "\n");
    }

    private void generateMethodPool() throws IOException {
        final References references = this.references;

        //类型声明放入头文件
        header.write(
                "\n" +
                        "typedef struct {\n" +
                        "    u2 classIdx;\n" +
                        "    u4 nameIdx;\n" +
                        "    u4 shortyIdx;\n" +
                        "    u4 sigIdx;\n" +
                        "} MethodId;\n\n");
        header.write("extern const MethodId " + sym("gMethodIds") + "[];\n");
        header.write("extern vmMethod " + sym("gMethods") + "[];\n\n");

        source.write("extern const MethodId " + sym("gMethodIds") + "[] = {\n");

        final List<MethodReference> methodPool = references.getMethodPool();
        for (MethodReference methodReference : methodPool) {
            String definingClass = methodReference.getDefiningClass();
            String className;
            if (definingClass.charAt(0) == 'L') {
                className = definingClass.substring(1, definingClass.length() - 1);
            } else {
                className = definingClass;
            }
            int classNameIdx = references.getClassNameItemIndex(className);
            if (classNameIdx < 0) {
                throw new RuntimeException("unknown class name" + definingClass);
            }
            String name = methodReference.getName();
            int nameIdx = references.getStringItemIndex(name);
            if (nameIdx < 0) {
                throw new RuntimeException("unknown method name");
            }
            int shortyIdx = references.getStringItemIndex(MethodUtil.getShorty(methodReference.getParameterTypes(), methodReference.getReturnType()));
            if (shortyIdx < 0) {
                throw new RuntimeException("unknown method shorty");
            }
            String signature = MyMethodUtil.getMethodSignature(methodReference.getParameterTypes(), methodReference.getReturnType());
            int sigIdx = references.getSignatureItemIndex(signature);
            if (sigIdx < 0) {
                throw new RuntimeException("unknown method signature");
            }

            source.write(String.format(
                    "    {.classIdx=%d, .nameIdx=%d, .shortyIdx=%d, .sigIdx=%d},\n",
                    classNameIdx, nameIdx, shortyIdx, sigIdx));
        }
        source.write("};\n");
        source.write("//ends method data\n\n");
        source.write(String.format("vmMethod %s[%d];\n", sym("gMethods"), methodPool.size()));
        source.write("\n");
    }

    private void generateFieldPool() throws IOException {
        final References references = this.references;

        header.write(
                "\n" +
                        "typedef struct {\n" +
                        "    u2 classIdx;\n" +
                        "    u4 nameIdx;\n" +
                        "    u2 typeIdx;\n" +
                        "} FieldId;\n\n");
        header.write("extern const FieldId " + sym("gFieldIds") + "[];\n");
        header.write("extern vmField " + sym("gFields") + "[];\n\n");

        source.write("extern const FieldId " + sym("gFieldIds") + "[] = {\n");

        final List<FieldReference> fieldPool = references.getFieldPool();
        for (FieldReference reference : fieldPool) {
            String definingClass = reference.getDefiningClass();
            String className;
            if (definingClass.charAt(0) == 'L') {
                className = definingClass.substring(1, definingClass.length() - 1);
            } else {
                className = definingClass;
            }
            int classNameIdx = references.getClassNameItemIndex(className);
            if (classNameIdx < 0) {
                throw new RuntimeException("unknown class name");
            }
            int nameIdx = references.getStringItemIndex(reference.getName());
            if (nameIdx < 0) {
                throw new RuntimeException("unknown field name");
            }
            int typeIdx = references.getTypeItemIndex(reference.getType());
            if (typeIdx < 0) {
                throw new RuntimeException("unknown field type");
            }

            source.write(String.format(
                    "    {.classIdx=%d, .nameIdx=%d, .typeIdx=%d},\n",
                    classNameIdx, nameIdx, typeIdx));
        }
        source.write("};\n");
        source.write("//ends field id\n\n");
        source.write(String.format("vmField %s[%d];\n", sym("gFields"), fieldPool.size()));
    }


    private void generateStringPool() throws IOException {
        //类型声明放头文件
        header.write(
                "typedef struct {\n" +
                        "    u4 off;\n" +
                        "} StringId;\n\n");
        header.write("extern const u1 " + sym("gBaseStrPtr") + "[];\n");
        header.write("extern const StringId " + sym("gStringIds") + "[];\n\n");

        //定义放源文件
        source.write("extern const u1 " + sym("gBaseStrPtr") + "[]={\n");

        ArrayList<Long> strOffsets = new ArrayList<>();
        long strOffset = 0;

        final List<String> stringPool = references.getStringPool();
        for (String string : stringPool) {

            //必须使用modified utf8，不然jni的NewStringUtf函数可能出问题.issue #3
            byte[] bytes = ModifiedUtf8.encode(string);

            source.write("    ");
            for (byte aByte : bytes) {
                source.write(String.format("0x%02x,", aByte & 0xFF));
            }
            source.write("0x00,\n");

            strOffsets.add(strOffset);
            strOffset += bytes.length + 1;
        }
        source.write("};\n\n");

        source.write("extern const StringId " + sym("gStringIds") + "[] = {\n");
        for (Long offset : strOffsets) {
            if (offset > 0xFFFFFFFFL) {
                throw new RuntimeException("string offset too long");
            }
            source.write(String.format("    {.off=0x%04x},\n", offset));
        }
        source.write("};\n");
        source.write("//ends string ids\n\n");

        source.flush();
    }

    static String stringEsc(String str) throws UTFDataFormatException {
        byte[] bytes = ModifiedUtf8.encode(str);
        StringBuilder sb = new StringBuilder(4 * bytes.length);
        for (byte b : bytes) {
            sb.append(String.format("\\x%02x", b & 0xFF));
        }
        return sb.toString();
    }

    private void generateTypePool() throws IOException {

        header.write(
                "\n" +
                        "typedef struct {\n" +
                        "    u4 idx;\n" +
                        "} TypeId;\n\n");
        header.write("extern const TypeId " + sym("gTypeIds") + "[];\n\n");

        source.write("extern const TypeId " + sym("gTypeIds") + "[] = {\n");
        final References references = this.references;
        for (String type : references.getTypePool()) {
            source.write(String.format("    {.idx=%d},\n", references.getStringItemIndex(type)));
        }
        source.write("};\n");
        source.write("//ends type ids\n\n");
        source.flush();
    }

    //根据类型池,去掉L开头和;得到class name,其他则不变
    private void generateClassNamePool() throws IOException {
        header.write(
                "\n" +
                        "typedef struct {\n" +
                        "    u4 idx;\n" +
                        "} ClassId;\n\n");
        header.write("extern const ClassId " + sym("gClassIds") + "[];\n\n");


        source.write("extern const ClassId " + sym("gClassIds") + "[] = {\n");

        final References references = this.references;
        for (String className : references.getClassNamePool()) {
            int classNameIdx = references.getStringItemIndex(className);
            if (classNameIdx < 0) {
                throw new RuntimeException("string not contain");
            }
            source.write(String.format("    {.idx=%d},\n", classNameIdx));

        }
        source.write("};\n");
        source.write("//ends class name ids\n\n");
    }

    private void generateSignaturePool() throws IOException {
        header.write(
                "typedef struct {\n" +
                        "    u4 idx;\n" +
                        "} SignatureId;\n\n");
        header.write("extern const SignatureId " + sym("gSignatureIds") + "[];\n\n");

        source.write("extern const SignatureId " + sym("gSignatureIds") + "[] = {\n");

        final References references = this.references;
        for (String sig : references.getSignaturePool()) {
            int sigIdx = references.getStringItemIndex(sig);
            if (sigIdx < 0) {
                throw new RuntimeException("string not contain");
            }
            source.write(String.format("    {.idx=%d},\n", sigIdx));
        }
        source.write("};\n");
        source.write("//ends method signature pool\n\n");
    }
}
