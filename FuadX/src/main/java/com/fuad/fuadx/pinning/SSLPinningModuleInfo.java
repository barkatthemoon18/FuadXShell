package com.fuad.fuadx.pinning;

import com.fuad.fuadx.Constants;
import com.fuad.fuadx.FuadXModuleInfo;

public class SSLPinningModuleInfo extends FuadXModuleInfo {
    private static final String TAG = "SSLPinningModuleInfo";
    private final String moduleHeuristic;
    private final String moduleDetectionMethod;
    private final String moduleDetectionResult;

    public SSLPinningModuleInfo(String moduleHeuristic, String moduleDetectionMethod,
                                 String moduleDetectionResult) {
        super(Constants.SSL_PINNING_MODULE_NAME);
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
