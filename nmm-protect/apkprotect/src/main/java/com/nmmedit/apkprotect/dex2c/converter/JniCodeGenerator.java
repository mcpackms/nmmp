package com.nmmedit.apkprotect.dex2c.converter;

import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedClassDef;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedMethod;
import com.android.tools.smali.dexlib2.dexbacked.DexBuffer;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.util.MethodUtil;
import com.google.common.collect.HashMultimap;
import com.nmmedit.apkprotect.dex2c.DexConfig;
import com.nmmedit.apkprotect.dex2c.converter.instructionrewriter.InstructionRewriter;

import javax.annotation.Nonnull;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;


/**
 * 根据dex把所有方法的字节码和异常表提取出来生成jni函数
 */

public class JniCodeGenerator {
    // 不能再设为false,不然无法正确加载本地库,而且按标准的jni函数名可能会有命名冲突问题
    // 所以只保留注册本地函数这种方式
    // todo 再改改jni函数名生成方式应该可以把bridge这类方法也native化
    private final boolean isRegisterNative = true;

    /**
     * 每个 C 文件最大方法数
     */
    private static final int DEFAULT_MAX_METHODS_PER_FILE = 500;

    /**
     * 最多生成的 C 文件数，超过后剩余方法全部放入最后一个文件
     */
    private static final int MAX_FILES = 1000;

    private final HashMultimap<String, MyMethod> handledNativeMethods = HashMultimap.create();

    private final Map<String, Integer> nativeMethodOffsets = new HashMap<>();
    private final ResolverCodeGenerator resolverCodeGenerator;
    private final InstructionRewriter instructionRewriter;
    private final DexBackedDexFile dexFile;

    //当前处理的 dex 名(如 classes2),用于给跨编译单元符号加前缀
    private String dexName;

    public JniCodeGenerator(@Nonnull DexBackedDexFile dexFile,
                            @Nonnull ClassAnalyzer analyzer,
                            @Nonnull InstructionRewriter instructionRewriter) {
        this.dexFile = dexFile;

//      根据dex里字符串常量,类型常量等生成符号解析代码,给vm提供符号信息
        resolverCodeGenerator = new ResolverCodeGenerator(dexFile, analyzer);

        this.instructionRewriter = instructionRewriter;

        instructionRewriter.loadReferences(resolverCodeGenerator.getReferences(), analyzer);

    }

    /**
     * resolver 符号名(带 dex 前缀)
     */
    private String resolverSym(String base) {
        return dexName + "_" + base;
    }

    public void addMethod(Method method, Writer writer) throws IOException {
        final MethodImplementation implementation = method.getImplementation();
        if (implementation == null) {
            return;
        }

        final boolean isStatic = AccessFlags.STATIC.isSet(method.getAccessFlags());

        final String classType = method.getDefiningClass();

        final String methodName = method.getName();
        final int registerCount = implementation.getRegisterCount();
        final List<? extends CharSequence> parameterTypes = method.getParameterTypes();
        final int parameterRegisterCount = MethodUtil.getParameterRegisterCount(parameterTypes, isStatic);
        final String returnType = method.getReturnType();


        String clazzName = classType.substring(1, classType.length() - 1);

        handledNativeMethods.put(clazzName, new MyMethod(clazzName, methodName, parameterTypes, returnType));

        // 使用 StringBuilder 批量构建函数签名（参数列表部分）
        StringBuilder sb = new StringBuilder(4096);

        sb.append(isRegisterNative ? "" : "JNIEXPORT ");
        sb.append(getJNIType(returnType)).append(' ');
        sb.append(MyMethodUtil.getJniFunctionName(clazzName, methodName, parameterTypes, returnType));
        sb.append("(JNIEnv *env, ");
        sb.append(isStatic ? "jclass jcls" : "jobject thiz");

        // 构建参数列表和寄存器赋值
        StringBuilder params = new StringBuilder();
        StringBuilder regsAssign = new StringBuilder();
        StringBuilder regFlagsAssign = new StringBuilder();

        //如果寄存器数量比较小直接使用栈上内存,不自己分配和释放
        boolean useStack = registerCount <= 8;

        //寄存器初始化
        if (useStack) {
            regsAssign.append("    regptr_t regs[").append(registerCount).append("];\n");
            for (int i = 0; i < registerCount; i++) {
                regsAssign.append("    regs[").append(i).append("] = 0;\n");
            }
            regFlagsAssign.append("    u1 reg_flags[").append(registerCount).append("];\n");
            for (int i = 0; i < registerCount; i++) {
                regFlagsAssign.append("    reg_flags[").append(i).append("] = 0;\n");
            }
        } else {
            regsAssign.append("    regptr_t *regs = (regptr_t *) calloc(").append(registerCount).append(", sizeof(regptr_t) + sizeof(u1));\n");
            regFlagsAssign.append("    u1 *reg_flags = ((u1 *) regs) + (").append(registerCount).append(" * sizeof(regptr_t));\n");
        }
        int paramRegStart = registerCount - parameterRegisterCount;
        if (!isStatic) {
            regsAssign.append("    regs[").append(paramRegStart).append("] = (regptr_t) thiz;\n");
            regFlagsAssign.append("    reg_flags[").append(paramRegStart).append("] = 1;\n");
            paramRegStart++;
        }

        for (int i = 0, size = parameterTypes.size(); i < size; i++) {
            String type = parameterTypes.get(i).toString();
            String jniType = getJNIType(type);
            final int argNum = isStatic ? i : i + 1;
            params.append(jniType).append(" p").append(argNum);
            if (type.startsWith("[") || type.startsWith("L")) {
                regsAssign.append("    regs[").append(paramRegStart).append("] = (regptr_t) p").append(argNum).append(";\n");
                regFlagsAssign.append("    reg_flags[").append(paramRegStart).append("] = 1;\n");
                paramRegStart++;
            } else if (type.equals("F")) {
                regsAssign.append("    SET_REGISTER_FLOAT(").append(paramRegStart++).append(", p").append(argNum).append(");\n");
            } else if (type.equals("D")) {
                regsAssign.append("    SET_REGISTER_DOUBLE(").append(paramRegStart++).append(", p").append(argNum).append(");\n");
                paramRegStart++;
            } else if (type.equals("J")) {
                regsAssign.append("    SET_REGISTER_WIDE(").append(paramRegStart++).append(", p").append(argNum).append(");\n");
                paramRegStart++;
            } else {
                regsAssign.append("    regs[").append(paramRegStart++).append("] = p").append(argNum).append(";\n");
            }
            if (i < size - 1) {
                params.append(", ");
            }
        }
        if (params.length() > 0) {
            sb.append(", ").append(params);
        }
        sb.append(") {\n");

        // 写入完整的函数头
        writer.write(sb.toString());
        writer.write(regsAssign.toString());
        writer.write("\n");
        writer.write(regFlagsAssign.toString());
        writer.write("\n");

        // 生成字节码数组
        writer.write("    static const u2 insns[] = {");
        final byte[] instructionData = instructionRewriter.rewriteInstructions(implementation);
        final int dataLength = instructionData.length;
        final DexBuffer instructionBuf = new DexBuffer(instructionData);
        for (int offset = 0; offset < dataLength; offset += 2) {
            if (offset % 20 == 0) {
                writer.write("\n");
            }
            writer.write(String.format("0x%04x, ", instructionBuf.readUshort(offset)));
        }
        writer.write("\n    };\n");

        // 异常表
        final byte[] tries = instructionRewriter.handleTries(implementation);
        if (tries.length == 0) {
            writer.write("    const u1 *tries = NULL;\n");
        } else {
            writer.write("    static const u1 tries[] = {");
            for (int i = 0; i < tries.length; i++) {
                if (i % 10 == 0) {
                    writer.write("\n");
                }
                writer.write(String.format("0x%02x, ", tries[i] & 0xFF));
            }
            writer.write("\n    };\n");
        }

        //调用解释器
        writer.write(String.format("\n" +
                        "    const vmCode code = {\n" +
                        "            .insns=insns,\n" +
                        "            .insnsSize=%d,\n" +
                        "            .regs=regs,\n" +
                        "            .reg_flags=reg_flags,\n" +
                        "            .triesHandlers=tries\n" +
                        "    };\n" +
                        "\n"
                , dataLength / 2));

        final boolean hasReturnValue = !returnType.equals("V");
        if (hasReturnValue) {
            writer.write("\n" +
                    "    volatile jvalue value = vmInterpret(env,\n" +
                    "                                &code,\n" +
                    "                                &" + resolverSym("dvmResolver") + ");\n"
            );
        } else {
            writer.write("\n" +
                    "    vmInterpret(env,\n" +
                    "              &code,\n" +
                    "              &" + resolverSym("dvmResolver") + ");\n"
            );
        }

        //不使用栈需要释放内存
        if (!useStack) {
            writer.write("    free(regs);\n");
        }

        //根据返回类型处理jvalue
        if (hasReturnValue) {
            char typeCh = returnType.charAt(0);
            writer.write("    return value.");
            writer.write(Character.toLowerCase(typeCh == '[' ? 'L' : typeCh));
            writer.write(";\n");
        }
        writer.write("}\n\n");
    }

    public Set<String> getHandledNativeClasses() {
        return handledNativeMethods.keySet();
    }

    //必须在产生代码后调用才有效果
    public Map<String, Integer> getNativeMethodOffsets() {
        return nativeMethodOffsets;
    }

    public void generate(DexConfig config, Writer resolverHeaderWriter, Writer resolverWriter, Writer codeWriter) throws IOException {
        this.dexName = config.getDexName();

        //生成 resolver 头文件(声明)与源文件(定义)
        resolverCodeGenerator.generate(resolverHeaderWriter, resolverWriter, dexName);

        // 收集所有需要处理的方法
        List<DexBackedMethod> allMethods = new ArrayList<>();
        for (DexBackedClassDef classDef : dexFile.getClasses()) {
            for (DexBackedMethod method : classDef.getMethods()) {
                if (method.getImplementation() != null) {
                    allMethods.add(method);
                }
            }
        }

        int totalMethods = allMethods.size();
        int maxMethodsPerFile = DEFAULT_MAX_METHODS_PER_FILE;

        // 计算需要的文件数，但不超过 MAX_FILES
        int fileCount = (totalMethods + maxMethodsPerFile - 1) / maxMethodsPerFile;
        if (fileCount > MAX_FILES) {
            fileCount = MAX_FILES;
            // 重新计算每个文件的方法数，确保所有方法都能放入
            maxMethodsPerFile = (totalMethods + fileCount - 1) / fileCount;
        }

        generateNativeFunctions(config, codeWriter, allMethods, fileCount, maxMethodsPerFile);
    }

    /**
     * 生成 native functions C 代码
     * <p>
     * 单文件: 直接写入 codeWriter(<dex>_native_functions.c)
     * 多文件: 每个拆分文件是独立的编译单元, 由 ninja 并行编译, 最后一个文件包含注册代码与 setup 函数
     */
    private void generateNativeFunctions(DexConfig config, Writer codeWriter, List<DexBackedMethod> methods,
                                         int fileCount, int maxMethodsPerFile) throws IOException {
        if (fileCount <= 1) {
            //单文件模式,直接写入主文件
            writeFileHeader(config, codeWriter);

            for (DexBackedMethod method : methods) {
                addMethod(method, codeWriter);
            }

            generateNativeMethodCode(config, codeWriter);
            writeSetupFunction(config, codeWriter);
            writeFileFooter(config, codeWriter);
            return;
        }

        File outputDir = config.getOutputDir();
        String dexName = config.getDexName();

        // 每个拆分文件都生成全部方法的前置声明;
        // 最后一个文件的注册代码(gNativeMethods)会引用其他编译单元里的方法, 没有声明无法编译
        final String functionDeclarations = buildFunctionDeclarations(methods);

        // 拆分为多个独立编译单元, 每个文件一个 .o, 由 cmake -j 并行编译
        for (int i = 0; i < fileCount; i++) {
            int startIdx = i * maxMethodsPerFile;
            int endIdx = Math.min(startIdx + maxMethodsPerFile, methods.size());
            List<DexBackedMethod> fileMethods = methods.subList(startIdx, endIdx);

            // 最后一个文件包含注册代码和 setup 函数
            boolean isLastFile = (i == fileCount - 1);

            File cFile = new File(outputDir, dexName + "_native_functions_" + i + ".c");
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(cFile), 64 * 1024)) {
                writeFileHeader(config, writer);

                // 全部方法的跨文件前置声明
                writer.write(functionDeclarations);

                for (DexBackedMethod method : fileMethods) {
                    addMethod(method, writer);
                }

                if (isLastFile) {
                    generateNativeMethodCode(config, writer);
                    writeSetupFunction(config, writer);
                }

                writeFileFooter(config, writer);
            }
        }

        // 主文件仅保留注释, 实际编译单元是各拆分文件
        codeWriter.write("// native functions are split into " + dexName + "_native_functions_0.c ~ _" +
                (fileCount - 1) + ".c, compiled separately\n");
    }

    /**
     * 为所有待生成的 method 构建前置声明文本, 供拆分后的独立编译单元交叉引用
     */
    private String buildFunctionDeclarations(List<DexBackedMethod> methods) {
        StringBuilder sb = new StringBuilder(methods.size() * 64);
        for (DexBackedMethod method : methods) {
            final boolean isStatic = AccessFlags.STATIC.isSet(method.getAccessFlags());
            final String classType = method.getDefiningClass();
            final String clazzName = classType.substring(1, classType.length() - 1);
            final String methodName = method.getName();
            final List<? extends CharSequence> parameterTypes = method.getParameterTypes();
            final String returnType = method.getReturnType();

            sb.append(getJNIType(returnType)).append(' ');
            sb.append(MyMethodUtil.getJniFunctionName(clazzName, methodName, parameterTypes, returnType));
            sb.append("(JNIEnv *env, ");
            sb.append(isStatic ? "jclass jcls" : "jobject thiz");

            int argNum = isStatic ? 0 : 1;
            for (int i = 0, size = parameterTypes.size(); i < size; i++) {
                sb.append(", ").append(getJNIType(parameterTypes.get(i).toString())).append(" p").append(argNum++);
            }
            sb.append(");\n");
        }
        return sb.toString();
    }

    /**
     * 写入 C 文件头(各拆分文件均为独立编译单元, include resolver 头文件获取声明与宏)
     */
    private void writeFileHeader(DexConfig config, Writer writer) throws IOException {
        writer.write("\n" +
                "#include <stdio.h>\n" +
                "#include <string.h>\n" +
                "#include <malloc.h>\n" +
                "#include <jni.h>\n" +
                "#include \"vm.h\"\n" +
                "#include \"" + config.getDexName() + "_resolver.h\"\n" +
                "\n" +
                "#ifdef __cplusplus\n" +
                "extern \"C\" {\n" +
                "#endif\n" +
                "\n" +
                "\n" +
                "#define SET_REGISTER_FLOAT(_idx, _val)      (*((float*) &regs[(_idx)]) = (_val))\n" +
                "\n" +
                "\n" +
                "#define SET_REGISTER_WIDE(_idx, _val)       (regs[(_idx)] =(s8) (_val));\n" +
                "\n" +
                "#define SET_REGISTER_DOUBLE(_idx, _val)     (*((double*) &regs[(_idx)]) = (_val));\n" +
                "\n" +
                "\n");
    }

    /**
     * 写入 C 文件尾
     */
    private void writeFileFooter(DexConfig config, Writer writer) throws IOException {
        writer.write("\n\n#ifdef __cplusplus\n" +
                "}\n" +
                "#endif\n\n");
    }

    /**
     * 写入 setup 函数
     */
    private void writeSetupFunction(DexConfig config, Writer codeWriter) throws IOException {
        codeWriter.write(String.format("void %s(JNIEnv *env) {\n", config.getHeaderFileAndSetupFunc().setupFunctionName));

        codeWriter.write("\n    //符号解析器初始化\n");
        codeWriter.write("    " + resolverSym("resolver_init") + "(env);\n\n");

        if (isRegisterNative) {
            codeWriter.write("    //注册\n");

            final String funName = MyMethodUtil.getJniFunctionName(config.getRegisterNativesClassName(),
                    config.getRegisterNativesMethodName(), Collections.singletonList("I"), "V");
            codeWriter.write(String.format(
                    "    jclass clazz = (*env)->FindClass(env, \"%s\");\n" +
                            "    static const JNINativeMethod nativeMethod = {\n" +
                            "        .name=\"%s\",\n" +
                            "        .signature=\"(I)V\",\n" +
                            "        .fnPtr=%s\n" +
                            "    };\n" +
                            "   (*env)->RegisterNatives(env, clazz, &nativeMethod, 1);\n" +
                            "\n" +
                            "   (*env)->DeleteLocalRef(env, clazz);\n" +
                            "\n",
                    config.getRegisterNativesClassName(),
                    config.getRegisterNativesMethodName(), funName));
        }
        codeWriter.write("}\n");
    }

    //生成本地方法注册代码,同时返回类名和方法数组索引等
    private void generateNativeMethodCode(DexConfig config, Writer writer) throws IOException {
        if (!isRegisterNative) {
            return;
        }
        //记录类名之下所有方法起始位置及数量用于生成注册代码
        HashMap<String, Ranger> methodRanger = new HashMap<>();

        writer.write("\n" +
                "typedef struct{\n" +
                "    u4 nameIdx;\n" +
                "    u4 sigIdx;\n" +
                "    void *fnPtr;\n" +
                "} MyNativeMethod;\n");

        int methodIdx = 0;
        writer.write("static const MyNativeMethod gNativeMethods[] = {\n");
        final References references = resolverCodeGenerator.getReferences();
        for (String clazz : handledNativeMethods.keySet()) {

            int startIdx = methodIdx;
            Set<MyMethod> methods = handledNativeMethods.get(clazz);
            for (MyMethod method : methods) {
                int nameIdx = references.getStringItemIndex(method.name);
                int sigIdx = references.getStringItemIndex(MyMethodUtil.getMethodSignature(method.parameterTypes, method.returnType));
                writer.write(String.format(
                        "    {%d, %d, (void *) %s},\n",
                        nameIdx, sigIdx,
                        MyMethodUtil.getJniFunctionName(method.className, method.name, method.parameterTypes, method.returnType)
                ));
                methodIdx++;
            }
            methodRanger.put(clazz, new Ranger(startIdx, methodIdx - startIdx));
        }

        writer.write("};\n");
        writer.write("//ends native method\n");

        //根据索引生成注册需要的结构体
        writer.write(
                "\n" +
                        "typedef struct {\n" +
                        "    u4 classIdx;\n" +
                        "    u4 offset;\n" +
                        "    u4 count;\n" +
                        "} NativeMethodData;\n");

        writer.write("static const NativeMethodData gNativeRegisterData[] = {\n");
        int dataOff = 0;
        for (Map.Entry<String, Ranger> entry : methodRanger.entrySet()) {
            Ranger ranger = entry.getValue();
            final String className = entry.getKey();
            int classIdx = references.getClassNameItemIndex(className);
            writer.write(String.format("    {.classIdx = %d, .offset = %d, .count = %d},\n", classIdx, ranger.start, ranger.count));
            nativeMethodOffsets.put(className, dataOff++);
        }
        writer.write("};\n\n");

        //当前dex下所有处理过的class对应的本地方法注册
        final String funName = MyMethodUtil.getJniFunctionName(config.getRegisterNativesClassName(),
                config.getRegisterNativesMethodName(), Collections.singletonList("I"), "V");
        writer.write(String.format(
                "static void %s(JNIEnv *env, jclass jcls, jint dataIdx){\n" +
                        "#define MAX_METHOD 8\n" +
                        "    JNINativeMethod methodBuf[MAX_METHOD];\n" +
                        "\n" +
                        "    JNINativeMethod *methods;\n" +
                        "    const NativeMethodData data = gNativeRegisterData[(u4) dataIdx];\n" +
                        "    if (data.count > MAX_METHOD) {\n" +
                        "        methods = (JNINativeMethod *) malloc(sizeof(JNINativeMethod) * data.count);\n" +
                        "    } else {\n" +
                        "        //方法数比较小直接使用栈内存,减少内存分配和释放\n" +
                        "        methods = methodBuf;\n" +
                        "    }\n" +
                        "\n" +
                        "    jclass clazz = (*env)->FindClass(env, STRING_BY_CLASS_ID(data.classIdx));\n" +
                        "    if (clazz == NULL) {\n" +
                        "        return;\n" +
                        "    }\n" +
                        "    for (int midx = 0; midx < data.count; ++midx) {\n" +
                        "        MyNativeMethod myNativeMethod = gNativeMethods[data.offset + midx];\n" +
                        "\n" +
                        "        JNINativeMethod *method = methods + midx;\n" +
                        "        method->name = STRING_BY_ID(myNativeMethod.nameIdx);\n" +
                        "        method->signature = STRING_BY_ID(myNativeMethod.sigIdx);\n" +
                        "        method->fnPtr = myNativeMethod.fnPtr;\n" +
                        "    }\n" +
                        "\n" +
                        "    (*env)->RegisterNatives(env, clazz, methods, data.count);\n" +
                        "\n" +
                        "    (*env)->DeleteLocalRef(env, clazz);\n" +
                        "\n" +
                        "    //不相等表示使用malloc申请的内存需要释放\n" +
                        "    if (methods != methodBuf)free(methods);\n" +
                        "}\n\n"
                , funName)
        );
    }

    public static String getJNIType(String type) {
        switch (type) {
            case "Z":
                return "jboolean";
            case "B":
                return "jbyte";
            case "S":
                return "jshort";
            case "C":
                return "jchar";
            case "I":
                return "jint";
            case "F":
                return "jfloat";
            case "J":
                return "jlong";
            case "D":
                return "jdouble";
//            case "Ljava/lang/String;":
//                return "jstring";
            case "V":
                return "void";
            default:
                return "jobject";
        }
    }

    private static class MyMethod {
        final String className;
        final String name;
        final List<? extends CharSequence> parameterTypes;

        final String returnType;

        MyMethod(String className, String name, List<? extends CharSequence> parameterTypes, String returnType) {
            this.className = className;
            this.name = name;
            this.parameterTypes = parameterTypes;
            this.returnType = returnType;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            MyMethod myMethod = (MyMethod) o;

            if (!className.equals(myMethod.className)) return false;
            if (!name.equals(myMethod.name)) return false;
            if (!parameterTypes.equals(myMethod.parameterTypes)) return false;
            return returnType.equals(myMethod.returnType);
        }

        @Override
        public int hashCode() {
            int result = className.hashCode();
            result = 31 * result + name.hashCode();
            result = 31 * result + parameterTypes.hashCode();
            result = 31 * result + returnType.hashCode();
            return result;
        }
    }

    private static class Ranger {
        final int start;
        final int count;

        Ranger(int start, int count) {
            this.start = start;
            this.count = count;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Ranger ranger = (Ranger) o;

            if (start != ranger.start) return false;
            return count == ranger.count;
        }

        @Override
        public int hashCode() {
            int result = start;
            result = 31 * result + count;
            return result;
        }
    }
}
