package com.fuad.fuadx.apkintegrity;

import android.content.Context;
import android.content.pm.ApplicationInfo;

import com.fuad.fuadx.detection.DetectionEvidence;
import com.fuad.fuadx.detection.DetectionSource;
import com.fuad.fuadx.heuristic.HeuristicResult;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public final class ApkApplicationFlagsProbe {
    private final Context context;
    private final boolean enforcedReleaseFlags;

    public ApkApplicationFlagsProbe(Context context, boolean enforcedReleaseFlags) {
        this.context = Objects.requireNonNull(context, "context");
        this.enforcedReleaseFlags = enforcedReleaseFlags;
    }

    public HeuristicResult scan() {
        List<DetectionEvidence> evidences;
        ApplicationInfo applicationInfo;

        if (!enforcedReleaseFlags) {
            return HeuristicResult.clean();
        }
        try {
            applicationInfo = context.getApplicationInfo();
            evidences = new ArrayList<>();
            if ((applicationInfo.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
                evidences.add(new DetectionEvidence("ApkDebuggable", "ApplicationInfo.flags",
                        "Application is debuggable", DetectionSource.ANDROID_SIDE));
            }
            if ((applicationInfo.flags & ApplicationInfo.FLAG_TEST_ONLY) != 0) {
                evidences.add(new DetectionEvidence("ApkTestOnly", "ApplicationInfo.flags",
                        "Application is test-only", DetectionSource.ANDROID_SIDE));
            }
            return evidences.isEmpty() ? HeuristicResult.clean() : HeuristicResult.detected(evidences);
        }
        catch (RuntimeException e) {
            return HeuristicResult.error("APK_APPLICATION_FLAGS_FAILED", "Unable to inspect application flags");
        }
    }
}
