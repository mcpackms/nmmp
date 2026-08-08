package com.nmmedit.apkprotect;

import com.nmmedit.apkprotect.util.FileUtils;

import javax.annotation.Nonnull;
import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

/**
 * VM 缓存管理器，用于管理预编译的 VM 静态库
 * 缓存目录: ~/.nmmp/vm_cache/
 */
public class VmCacheManager {

    private static final String CACHE_DIR = System.getProperty("user.home") + "/.nmmp/vm_cache";
    private static final String VERSION_FILE = CACHE_DIR + "/version";
    private static final String LIB_DIR = CACHE_DIR + "/lib";
    private static final String CACHE_VERSION = "1.0"; // 缓存版本号，更新 VM 代码时需要修改

    /**
     * 获取缓存目录
     */
    public static String getCacheDir() {
        return CACHE_DIR;
    }

    /**
     * 检查缓存是否有效
     */
    public boolean isCacheValid(String cmakePath, String ndkHome) {
        File versionFile = new File(VERSION_FILE);
        if (!versionFile.exists()) {
            return false;
        }

        // 检查版本号
        try {
            String cachedVersion = FileUtils.readFile(versionFile.getAbsolutePath(), java.nio.charset.StandardCharsets.UTF_8).trim();
            if (!CACHE_VERSION.equals(cachedVersion)) {
                return false;
            }
        } catch (IOException e) {
            return false;
        }

        // 检查所有 ABI 的库是否存在
        List<String> abis = Arrays.asList("armeabi-v7a", "arm64-v8a", "x86", "x86_64");
        for (String abi : abis) {
            File libFile = new File(LIB_DIR, abi + "/libnmmvm.a");
            if (!libFile.exists()) {
                return false;
            }
        }

        return true;
    }

    /**
     * 获取预编译的 VM 静态库路径
     */
    public File getCachedLib(String abi) {
        return new File(LIB_DIR, abi + "/libnmmvm.a");
    }

    /**
     * 保存编译好的 VM 库到缓存
     */
    public void saveCachedLib(String abi, File libFile) throws IOException {
        File targetDir = new File(LIB_DIR, abi);
        if (!targetDir.exists()) {
            targetDir.mkdirs();
        }
        File targetFile = new File(targetDir, "libnmmvm.a");
        copyFile(libFile, targetFile);
    }

    /**
     * 写入缓存版本号
     */
    public void writeVersion() throws IOException {
        File versionFile = new File(VERSION_FILE);
        versionFile.getParentFile().mkdirs();
        try (FileWriter writer = new FileWriter(versionFile)) {
            writer.write(CACHE_VERSION);
        }
    }

    /**
     * 清除缓存
     */
    public void clearCache() {
        FileUtils.deleteFile(new File(CACHE_DIR));
    }

    /**
     * 计算 VM 源码的 hash，用于判断是否需要重新编译
     */
    public String computeSourceHash(File vmSourceDir) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            // 简单实现：收集所有 .c 和 .h 文件的内容计算 hash
            if (vmSourceDir.exists() && vmSourceDir.isDirectory()) {
                File[] files = vmSourceDir.listFiles();
                if (files != null) {
                    Arrays.sort(files);
                    for (File file : files) {
                        if (file.isFile() && (file.getName().endsWith(".c") || file.getName().endsWith(".h"))) {
                            md.update(file.getName().getBytes());
                            md.update(Long.toString(file.lastModified()).getBytes());
                        }
                    }
                }
            }
            byte[] hash = md.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            return String.valueOf(System.currentTimeMillis());
        }
    }

    private void copyFile(File source, File target) throws IOException {
        try (InputStream in = new FileInputStream(source);
             OutputStream out = new FileOutputStream(target)) {
            FileUtils.copyStream(in, out);
        }
    }

    /**
     * 检查是否需要编译 VM
     */
    public boolean needsVmBuild() {
        File versionFile = new File(VERSION_FILE);
        if (!versionFile.exists()) {
            return true;
        }
        try {
            String cachedVersion = FileUtils.readFile(versionFile.getAbsolutePath(), java.nio.charset.StandardCharsets.UTF_8).trim();
            return !CACHE_VERSION.equals(cachedVersion);
        } catch (IOException e) {
            return true;
        }
    }
}
