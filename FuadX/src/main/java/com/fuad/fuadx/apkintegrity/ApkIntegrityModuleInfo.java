package com.fuad.fuadx.apkintegrity;

import com.fuad.fuadx.Constants;
import com.fuad.fuadx.FuadXModuleInfo;

public class ApkIntegrityModuleInfo extends FuadXModuleInfo {
    private static final String TAG = "ApkIntegrityModuleInfo";
    private final String moduleHeuristic;
    private final String moduleDetectionMethod;
    private final String moduleDetectionResult;

    public ApkIntegrityModuleInfo(String moduleHeuristic, String moduleDetectionMethod,
                                   String moduleDetectionResult) {
        super(Constants.INTEGRITY_CONTROL_MODULE_NAME);
        this.moduleHeuristic = moduleHeuristic;
        this.moduleDetectionMethod = moduleDetectionMethod;
        this.moduleDetectionResult = moduleDetectionResult;
    }

    public String getModuleHeuristic() {
        return moduleHeuristic;
    }

    public String getModuleDetectionMethod() {
        return moduleDetectionMethod;
    }

    public String getModuleDetectionResult() {
        return moduleDetectionResult;
    }
}
