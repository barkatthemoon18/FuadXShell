package com.fuad.fuadx.debug;

import com.fuad.fuadx.Constants;
import com.fuad.fuadx.FuadXModuleInfo;

public class DebugModuleInfo extends FuadXModuleInfo {
    private static final String TAG = "DebugModuleInfo";
    private final String moduleHeuristic;
    private final String moduleDetectionMethod;
    private final String moduleDetectionResult;

    public DebugModuleInfo(String moduleHeuristic, String moduleDetectionMethod,
                           String moduleDetectionResult) {
        super(Constants.DEBUG_MODULE_NAME);
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
