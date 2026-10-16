package com.fuad.fuadx.frida;

import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;

import com.fuad.fuadx.Constants;
import com.fuad.fuadx.detection.DetectionEvidence;
import com.fuad.fuadx.detection.DetectionSource;
import com.fuad.fuadx.heuristic.HeuristicResult;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

public final class FridaNamedPipeProbe {

    @FunctionalInterface
    interface LinkResolver {
        String readLink(String path) throws ErrnoException;
    }

    private final File fdDirectory;
    private final LinkResolver linkResolver;

    public FridaNamedPipeProbe() {
        this(new File(Constants.PATH_PROC_SELF_FD), Os::readlink);
    }

    FridaNamedPipeProbe(File fdDirectory, LinkResolver linkResolver) {
        this.fdDirectory = Objects.requireNonNull(fdDirectory);
        this.linkResolver = Objects.requireNonNull(linkResolver);
    }

    public HeuristicResult scan() {
        List<DetectionEvidence> evidences = new ArrayList<>();
        File[] descriptors;
        String fdName;
        String targetPath;
        int inspected;
        int failed;

        try {
            if (!fdDirectory.isDirectory()) {
                return HeuristicResult.inconclusive("Process fd directory is unavailable");
            }
            descriptors = fdDirectory.listFiles();
        }
        catch (SecurityException e) {
            return HeuristicResult.error("FRIDA_FD_ACCESS_DENIED", "Unable to access process file descriptors");
        }
        if (descriptors == null) {
            return HeuristicResult.error("FRIDA_FD_ENUM_FAILED", "Unable to enumerate process file descriptors");
        }
        if (descriptors.length == 0) {
            return HeuristicResult.inconclusive("No file descritpos were enumerated");
        }
        inspected = 0;
        failed = 0;
        for (File fd : descriptors) {
            fdName = fd.getName();
            if (!isNumericDescriptor(fdName)) {
                continue;
            }
            try {
                targetPath = linkResolver.readLink(fd.getAbsolutePath());
                if (targetPath == null || targetPath.isEmpty()) {
                    failed++;
                    continue;
                }
                inspected++;
                if (targetPath.toLowerCase(Locale.ROOT).contains(Constants.LINJECTOR.toLowerCase(Locale.ROOT))) {
                    evidences.add(new DetectionEvidence("FridaNamedPipes", "readProcSelfFdLinks",
                            "fd " + fdName + "references linjector", DetectionSource.ANDROID_SIDE));
                }
            }
            catch (ErrnoException e) {
                if (e.errno != OsConstants.ENOENT) {
                    failed++;
                }
            }
            catch (SecurityException e) {
                failed++;
            }
        }
        if (!evidences.isEmpty()) {
            return HeuristicResult.detected(evidences);
        }
        if (failed > 0) {
            return HeuristicResult.inconclusive("Some file descriptors could not be inspected");
        }
        if (inspected == 0) {
            return HeuristicResult.inconclusive("No file descriptor target could not be inspected");
        }
        return HeuristicResult.clean();
    }

    private static boolean isNumericDescriptor(String name) {
        char value;

        if (name.isEmpty()) {
            return false;
        }
        for (int i = 0; i < name.length(); i++) {
            value = name.charAt(i);
            if (value < '0' || value > '9') {
                return false;
            }
        }
        return true;
    }
}
