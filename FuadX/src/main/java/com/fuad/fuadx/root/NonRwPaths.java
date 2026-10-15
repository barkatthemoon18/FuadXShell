package com.fuad.fuadx.root;

public enum NonRwPaths {
    SYSTEM("/system"),
    SYSTEM_BIN("/system/bin"),
    SYSTEM_SBIN("/system/sbin"),
    SYSTEM_XBIN("/system/xbin"),
    VENDOR_BIN("/vendor/bin"),
    SBIN("/sbin"),
    ETC("/etc");

    private final String path;

    NonRwPaths(String path) {
        this.path = path;
    }

    public String getPath() {
        return path;
    }
}
