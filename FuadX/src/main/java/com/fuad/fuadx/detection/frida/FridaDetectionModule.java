package com.fuad.fuadx.detection.frida;

import com.fuad.fuadx.detection.DetectionContext;
import com.fuad.fuadx.detection.DetectionEvidence;
import com.fuad.fuadx.detection.DetectionModule;
import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.detection.DetectionSource;
import com.fuad.fuadx.frida.Frida;
import com.fuad.fuadx.frida.FridaModuleInfo;
import com.fuad.fuadx.module.ModuleId;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class FridaDetectionModule implements DetectionModule {
    @Override
    public ModuleId id() {
        return ModuleId.FRIDA;
    }

    @Override
    public DetectionResult check(DetectionContext context) {
        Objects.requireNonNull(context, "context");

        try {
            return fromLegacy(Frida.isRunningFridaOnApk(context.getApplicationContext()));
        }
        catch (RuntimeException e) {
            return DetectionResult.error(id(), "FRIDA_EXECUTION_ERROR", e.getClass().getSimpleName());
        }
    }

    private static DetectionResult fromLegacy(FridaModuleInfo[] results) {
        List<DetectionEvidence> evidence = new ArrayList<>();

        if (results == null) {
            return DetectionResult.inconclusive(ModuleId.FRIDA, "Legacy Frida returned on ambiguous null result");
        }
        for (FridaModuleInfo info : results) {
            if (info == null) {
                continue;
            }
            evidence.add(new DetectionEvidence(info.getModuleHeuristic(), info.getModuleDetectionMethod(),
                    info.getModuleDetectionResult(), DetectionSource.ANDROID_SIDE));
        }
        if (evidence.isEmpty()) {
            return DetectionResult.inconclusive(ModuleId.FRIDA, "Legacy Frida provided no conclusive result");
        }
        return DetectionResult.detected(ModuleId.FRIDA, evidence);
    }
}
