package com.fuad.fuadx.root;

public enum SuPaths {
    DATA_LOCAL("/data/local"),
    DATA_LOCAL_BIN("/data/local/bin"),
    DATA_LOCAL_XBIN("/data/local/xbin"),
    SBIN("/sbin"),
    SU_BIN("/su/sbin"),
    SYSTEM_BIN("/system/bin"),
    SYSTEM_BIN_HIDDEN_EXT("/system/bin/.ext"),
    SYSTEM_BIN_FAILSAFE("/system/bin/failsafe"),
    SYSTEM_SD_XBIN("/system/sd/xbin"),
    SYSTEM_USR_WNR("/system/usr/we-need-root"),
    SYSTEM_XBIN("/system/xbin"),
    CACHE("/cache"),
    DATA("/data"),
    DEV("/dev");

    private final String path;

    SuPaths(String path) {
        this.path = path;
    }

    public String getPath() {
        return path;
    }
}
