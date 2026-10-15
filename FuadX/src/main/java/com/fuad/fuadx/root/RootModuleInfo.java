package com.fuad.fuadx.root;

import com.fuad.fuadx.Constants;
import com.fuad.fuadx.FuadXModuleInfo;

public class RootModuleInfo extends FuadXModuleInfo {
    private static final String TAG = "RootModuleInfo";
    private final String moduleHeuristic;
    private final String moduleDetectionMethod;
    private final String moduleDetectionResult;

    public RootModuleInfo(String moduleHeuristic, String moduleDetectionMethod,
                          String moduleDetectionResult) {
        super(Constants.ROOT_MODULE_NAME);
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
