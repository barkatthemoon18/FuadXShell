package com.fuad.fuadx.detection.reporting;

import android.util.Log;

import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.detection.policy.DetectionDecision;

import java.util.Objects;

public final class LogcatDetectionReporter implements DetectionReporter {
    private static final String TAG = "FuadXDetection";

    @Override
    public void report(DetectionResult result, DetectionDecision decision) {
        String message;

        Objects.requireNonNull(result, "result");
        Objects.requireNonNull(decision, "decision");
        message = "module=" + result.getModuleId() + ", status=" + result.getStatus()
                + ", evidence=" + result.getEvidence().size()
                + ", diagnostics=" + result.getDiagnostics().size();
        switch (decision) {
            case REPORT_DETECTION:
                Log.e(TAG, "Detection reported: " + message);
                break;
            case REPORT_DIAGNOSTIC:
                Log.w(TAG, "Diagnostic reported: " + message + ", errorCode=" + result.getErrorCode());
                break;
            case CONTINUE:
                break;
            default:
                throw new IllegalStateException("Unknown decision: " + decision);
        }
    }
}
