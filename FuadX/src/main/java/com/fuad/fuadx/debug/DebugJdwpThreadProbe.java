package com.fuad.fuadx.debug;

import com.fuad.fuadx.Constants;
import com.fuad.fuadx.detection.DetectionEvidence;
import com.fuad.fuadx.detection.DetectionSource;
import com.fuad.fuadx.heuristic.HeuristicResult;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

public final class DebugJdwpThreadProbe {
    private final File taskDirectory;

    public DebugJdwpThreadProbe() {
        this(new File(Constants.PATH_PROC_SELF_TASK));
    }

    public DebugJdwpThreadProbe(File taskDirectory) {
        this.taskDirectory = Objects.requireNonNull(taskDirectory);
    }

    public HeuristicResult scan() {
        List<DetectionEvidence> evidences = new ArrayList<>();
        File[] threads;
        File commFile;
        String line;
        String name;
        boolean foundName;
        int inspected = 0;
        int failed = 0;

        if (!taskDirectory.isDirectory()) {
            return HeuristicResult.inconclusive("Thread directory unavailable");
        }
        threads = taskDirectory.listFiles();
        if (threads == null) {
            return HeuristicResult.error("DEBUG_THREAD_ENUM_FAILED", "Unable to enumerate threads");
        }
        for (File thread : threads) {
            if (!thread.isDirectory()) {
                continue;
            }
            commFile = new File(thread, "comm");
            try (BufferedReader reader = new BufferedReader(new FileReader(commFile))) {
                name = reader.readLine();
                if (name == null) {
                    failed++;
                    continue;
                }
                inspected++;
                if (name.toLowerCase(Locale.ROOT).contains("jdwp")) {
                    evidences.add(new DetectionEvidence("JdwpComm", "readThreadComm",
                            "Thread name: " + name, DetectionSource.ANDROID_SIDE));
                }
            }
            catch (FileNotFoundException e) {
                if (thread.isDirectory()) {
                    failed++;
                }
            }
            catch (IOException | SecurityException e) {
                failed++;
            }
        }
        if (!evidences.isEmpty()) {
            return HeuristicResult.detected(evidences);
        }
        if (failed > 0) {
            return HeuristicResult.inconclusive("Some thread names could not be inspected");
        }
        if (inspected == 0) {
            return HeuristicResult.inconclusive("No thread names could be inspected");
        }
        return HeuristicResult.clean();
    }
}
