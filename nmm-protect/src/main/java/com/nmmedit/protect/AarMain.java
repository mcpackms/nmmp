package com.nmmedit.protect;

import com.nmmedit.apkprotect.ParallelConfig;
import com.nmmedit.apkprotect.aar.AarFolders;
import com.nmmedit.apkprotect.aar.AarProtect;
import com.nmmedit.apkprotect.deobfus.MappingReader;
import com.nmmedit.apkprotect.dex2c.converter.ClassAnalyzer;
import com.nmmedit.apkprotect.dex2c.converter.instructionrewriter.RandomInstructionRewriter;
import com.nmmedit.apkprotect.dex2c.filters.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class AarMain {

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("No Input aar.");
            System.err.println("Usage: <inAar> [<convertRuleFile> mapping.txt] [-j<n>]");
            System.err.println("Options:");
            System.err.println("  -j<n>      并行任务数 (默认: CPU核心数, 0=自动)");
            return;
        }

        // 分离选项和位置参数
        ParallelConfig parallelConfig = ParallelConfig.getDefault();
        List<String> positionalArgs = new ArrayList<>();

        for (String arg : args) {
            if (arg.startsWith("-j") && arg.length() > 2) {
                parallelConfig = ParallelConfig.fromArg(arg);
            } else if (arg.startsWith("--jobs=")) {
                parallelConfig = ParallelConfig.fromArg(arg);
            } else {
                positionalArgs.add(arg);
            }
        }

        if (positionalArgs.isEmpty()) {
            System.err.println("No Input aar.");
            return;
        }

        System.out.println("并行任务数: " + parallelConfig.getJobCount());

        final File aar = new File(positionalArgs.get(0));
        final File outDir = new File(aar.getParentFile(), "build");

        ClassAndMethodFilter filterConfig = new BasicKeepConfig();
        final SimpleRules simpleRules = new SimpleRules();
        if (positionalArgs.size() > 1) {
            simpleRules.parse(new InputStreamReader(new FileInputStream(positionalArgs.get(1)), StandardCharsets.UTF_8));
        } else {
            //all classes
            simpleRules.parse(new StringReader("class *"));
        }

        if (positionalArgs.size() > 2) {
            final MappingReader mappingReader = new MappingReader(new File(positionalArgs.get(2)));
            filterConfig = new ProguardMappingConfig(filterConfig, mappingReader, simpleRules);
        } else {
            filterConfig = new SimpleConvertConfig(new BasicKeepConfig(), simpleRules);
        }

        final ClassAnalyzer classAnalyzer = new ClassAnalyzer();
        //todo 可能需要加载某些厂商私有的sdk


        final AarFolders aarFolders = new AarFolders(aar, outDir);

        final AarProtect aarProtect = new AarProtect.Builder(aarFolders)
                .setInstructionRewriter(new RandomInstructionRewriter())
                .setFilter(filterConfig)
                .setClassAnalyzer(classAnalyzer)
                .setParallelConfig(parallelConfig)
                .build();
        aarProtect.run();
    }
}
