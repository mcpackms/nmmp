package com.nmmedit.apkprotect;

/**
 * 并行配置类，用于控制构建过程中的并行度
 */
public class ParallelConfig {
    private int jobCount;

    private ParallelConfig() {
    }

    /**
     * 获取默认配置，使用 CPU 核心数
     */
    public static ParallelConfig getDefault() {
        ParallelConfig config = new ParallelConfig();
        config.jobCount = Runtime.getRuntime().availableProcessors();
        return config;
    }

    /**
     * 从参数解析并行配置
     * 支持格式: -j4, -j0, --jobs=4, --jobs=0
     * @param arg 参数字符串
     * @return 解析后的配置，如果无法解析返回默认配置
     */
    public static ParallelConfig fromArg(String arg) {
        if (arg == null || arg.isEmpty()) {
            return getDefault();
        }

        ParallelConfig config = new ParallelConfig();

        try {
            if (arg.startsWith("-j")) {
                config.jobCount = Integer.parseInt(arg.substring(2));
            } else if (arg.startsWith("--jobs=")) {
                config.jobCount = Integer.parseInt(arg.substring(7));
            } else {
                config.jobCount = Integer.parseInt(arg);
            }
        } catch (NumberFormatException e) {
            return getDefault();
        }

        // 0 或负数表示使用 CPU 核心数
        if (config.jobCount <= 0) {
            config.jobCount = Runtime.getRuntime().availableProcessors();
        }

        return config;
    }

    public int getJobCount() {
        return jobCount;
    }

    public void setJobCount(int jobCount) {
        this.jobCount = jobCount <= 0 ? Runtime.getRuntime().availableProcessors() : jobCount;
    }
}
