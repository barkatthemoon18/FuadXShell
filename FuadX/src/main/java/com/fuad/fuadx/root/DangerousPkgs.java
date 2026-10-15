package com.fuad.fuadx.root;

public enum DangerousPkgs {
    /* TODO: Update list */
    SU("com.noshufou.android.su"),
    SUPERSU("eu.chainfire.supersu"),
    MAGISK("com.topjohnwu.magisk"),
    MAGISK_MANAGER("com.topjohnwu.magisk.manager"),
    MAGISK_HIDE("com.topjohnwu.magisk.hide"),
    MAGISK_MGR("com.topjohnwu.magisk.mgr"),
    MAGISK_MGR_PRO("com.topjohnwu.magisk.mgr.pro"),
    MAGISK_MGR_LITE("com.topjohnwu.magisk.mgr.lite");

    private final String pkgName;

    DangerousPkgs(String packageName) {
        this.pkgName = packageName;
    }

    public String getPkgName() {
        return pkgName;
    }
}
