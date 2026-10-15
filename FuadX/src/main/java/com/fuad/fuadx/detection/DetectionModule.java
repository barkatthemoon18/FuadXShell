package com.fuad.fuadx.detection;

import com.fuad.fuadx.module.ModuleId;

public interface DetectionModule {
    ModuleId id();
    DetectionResult check(DetectionContext context);
}
