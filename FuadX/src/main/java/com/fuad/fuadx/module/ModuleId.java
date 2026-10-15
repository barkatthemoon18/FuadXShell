package com.fuad.fuadx.module;

import com.fuad.fuadx.Constants;

public enum ModuleId {
    ROOT(Constants.ROOT_MODULE_NAME),
    DEBUG(Constants.DEBUG_MODULE_NAME),
    FRIDA(Constants.FRIDA_MODULE_NAME),
    APK_INTEGRITY(Constants.INTEGRITY_CONTROL_MODULE_NAME),
    SSL_PINNING(Constants.SSL_PINNING_MODULE_NAME);

    private final String moduleName;

    ModuleId(String moduleName) {
        this.moduleName = moduleName;
    }

    public String getModuleName() {
        return moduleName;
    }
}
