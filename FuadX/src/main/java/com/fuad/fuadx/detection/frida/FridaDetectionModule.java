package com.fuad.fuadx.detection.frida;

import com.fuad.fuadx.detection.DetectionContext;
import com.fuad.fuadx.detection.DetectionModule;
import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.module.ModuleId;

public class FridaDetectionModule implements DetectionModule {
    @Override
    public ModuleId id() {
        return ModuleId.FRIDA;
    }

    @Override
    public DetectionResult check(DetectionContext context) {
        throw new UnsupportedOperationException("Stub");
    }
}
