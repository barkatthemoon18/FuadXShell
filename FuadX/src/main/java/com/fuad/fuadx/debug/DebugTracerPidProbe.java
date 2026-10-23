package com.fuad.fuadx.debug;

import com.fuad.fuadx.Constants;
import com.fuad.fuadx.detection.DetectionEvidence;
import com.fuad.fuadx.detection.DetectionSource;
import com.fuad.fuadx.heuristic.HeuristicResult;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Collections;
import java.util.Objects;

public final class DebugTracerPidProbe {
    private final File statusFile;

    public DebugTracerPidProbe() {
        this(new File(Constants.PATH_PROC_SELF_STATUS));
    }

    public DebugTracerPidProbe(File statusFile) {
        this.statusFile = Objects.requireNonNull(statusFile, "statusFile");
    }

    public HeuristicResult scan() {
        String line;
        String raw;
        int pid;

        if (!statusFile.isFile()) {
            return HeuristicResult.inconclusive("Process status file unavailable");
        }
        try (BufferedReader reader = new BufferedReader(new FileReader(statusFile))) {
            while ((line = reader.readLine()) != null) {
                if (!line.startsWith("TracerPid:")) {
                    continue;
                }
                raw = line.substring("TracerPid:".length()).trim();
                try {
                    pid = Integer.parseInt(raw);
                }
                catch (NumberFormatException e) {
                    return HeuristicResult.error("DEBUG_TRACERPID_INVALID", "Invalid TracerPid value");
                }
                if (pid < 0) {
                    return HeuristicResult.error("DEBUG_TRACERPID_INVALID", "Negative TracerPid value");
                }
                if (pid > 0) {
                    return HeuristicResult.detected(Collections.singletonList(
                            new DetectionEvidence("TracerPidStatus", "readProcSelfStatus",
                                    "TracerPid=" + pid, DetectionSource.ANDROID_SIDE)));
                }
                return HeuristicResult.clean();
            }
            return HeuristicResult.inconclusive("TracerPid field not found");
        }
        catch (IOException | SecurityException e) {
            return HeuristicResult.error("DEBUG_TRACERPID_READ_FAILED", "Unable to inspect process status: " + e.getClass().getSimpleName());
        }
    }
}
