package com.fuad.fuadx;

import com.fuad.fuadx.util.AndroidUtil;

public class FuadXModuleInfo {
    private final String timestamp;
    private final String moduleName;

    public FuadXModuleInfo(String moduleName) {
        this.timestamp = AndroidUtil.generateTimestamp();
        this.moduleName = moduleName;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public String getModuleName() {
        return moduleName;
    }
}
