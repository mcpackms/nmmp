package com.nmmedit.apkprotect.data.config;

import com.google.gson.annotations.SerializedName;

public class Config {
    @SerializedName("abi")
    public AbiConfig abi;
    @SerializedName("environment")
    public PathConfig environment;

    @SerializedName("lib_name")
    public String lib_name;
    @SerializedName("vm_lib_name")
    public String vm_lib_name;

    public Config(AbiConfig abi, PathConfig environment) {
        this.abi = abi;
        this.environment = environment;
    }
}