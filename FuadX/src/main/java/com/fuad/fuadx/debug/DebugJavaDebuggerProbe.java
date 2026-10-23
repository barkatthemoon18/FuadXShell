package com.fuad.fuadx.debug;

import com.fuad.fuadx.detection.DetectionEvidence;
import com.fuad.fuadx.detection.DetectionSource;
import com.fuad.fuadx.heuristic.HeuristicResult;

import java.util.Collections;

public final class DebugJavaDebuggerProbe {

    public HeuristicResult scan() {
        if (android.os.Debug.isDebuggerConnected()) {
            return HeuristicResult.detected(Collections.singletonList(
                    new DetectionEvidence("JavaDebuggerConnected", "isDebuggerConnected",
                            "Java debugger is attached", DetectionSource.ANDROID_SIDE)));
        }
        if (android.os.Debug.waitingForDebugger()) {
            return HeuristicResult.inconclusive("Application is waiting for a Java debugger");
        }
        return HeuristicResult.clean();
    }
}
