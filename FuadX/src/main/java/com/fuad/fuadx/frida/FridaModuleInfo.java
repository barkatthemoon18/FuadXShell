package com.fuad.fuadx.frida;

import com.fuad.fuadx.Constants;
import com.fuad.fuadx.FuadXModuleInfo;

public class FridaModuleInfo extends FuadXModuleInfo {
    private static final String TAG = "FridaModuleInfo";
    private final String moduleHeuristic;
    private final String moduleDetectionMethod;
    private final String moduleDetectionResult;

    public FridaModuleInfo(String moduleHeuristic, String moduleDetectionMethod,
                           String moduleDetectionResult) {
        super(Constants.FRIDA_MODULE_NAME);
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
