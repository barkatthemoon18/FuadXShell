package com.fuad.fuadx.debug;

import static android.os.Process.myPid;

import android.content.Context;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.Log;

import com.fuad.fuadx.Constants;
import com.fuad.fuadx.errormsgbox.ErrorCodes;
import com.fuad.fuadx.exception.FuadXRuntimeException;
import com.fuad.fuadx.logger.FuadXLogger;
import com.fuad.fuadx.report.FuadXTombstone;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Debug {
    private static final String TAG = "Debug";
    private static final ExecutorService executorService = Executors.newFixedThreadPool(2);
    private static final ExecutorService executorServiceExhaustive =
            Executors.newFixedThreadPool(3);
    private static final long intervalMillis = 5000;
    private static HandlerThread handlerThreadDefault;
    private static HandlerThread handlerThreadExhaustive;
    private static Handler handlerDefault;
    private static Handler handlerExhaustive;
    private static Runnable debugThreadRunnable;
    private static Runnable exhaustiveDebugThreadRunnable;

    public static synchronized DebugModuleInfo[] isRunningDebugOnApk(Context ctx) {
        try {
            CompletableFuture<DebugModuleInfo> futureJavaDebugger = CompletableFuture
                    .supplyAsync(() -> {
                try {
                    Log.e(TAG, "Checking for Java debugger...");
                    return checkForJavaDebugger(ctx);
                }
                catch (Exception e) {
                    Log.e(TAG, "Error checking for Java debugger: " + e.getMessage(), e);
                    return null;
                }
            }, executorService);
            CompletableFuture<DebugModuleInfo> futureNativeDebugger = CompletableFuture
                    .supplyAsync(() -> {
               try {
                   Log.e(TAG, "Checking for Native debugger...");
                   return checkForNativeDebugger(ctx);
               }
               catch (Exception e) {
                   Log.e(TAG, "Error checking for Native debugger: " + e.getMessage(), e);
                   return null;
               }
            }, executorService);
            CompletableFuture<DebugModuleInfo> futureTracedStatus = CompletableFuture
                    .supplyAsync(() -> {
                try {
                    Log.e(TAG, "Checking for traced status...");
                    return checkTracedStatus(ctx);
                }
                catch (Exception e) {
                    Log.e(TAG, "Error checking for traced status: " + e.getMessage(), e);
                    return null;
                }
            }, executorServiceExhaustive);
            CompletableFuture<DebugModuleInfo> futureTraceStopOnWchan = CompletableFuture
                    .supplyAsync(() -> {
                try {
                    Log.e(TAG, "Checking for trace stop on wchan...");
                    return checkTraceStopOnWchan(ctx);
                }
                catch (Exception e) {
                    Log.e(TAG, "Error checking for trace stop on wchan: " + e.getMessage(), e);
                    return null;
                }
            }, executorServiceExhaustive);
            CompletableFuture<DebugModuleInfo> futureIdaTracing = CompletableFuture
                    .supplyAsync(() -> {
                try {
                    Log.e(TAG, "Checking for IDA tracing...");
                    return checkForIdaTracing(ctx);
                }
                catch (Exception e) {
                    Log.e(TAG, "Error checking for IDA tracing: " + e.getMessage(), e);
                    return null;
                }
            }, executorServiceExhaustive);
            return CompletableFuture.allOf(futureJavaDebugger, futureNativeDebugger).thenApply(v -> {
                DebugModuleInfo javaDebuggerInfo = futureJavaDebugger.join();
                DebugModuleInfo nativeDebuggerInfo = futureNativeDebugger.join();
                DebugModuleInfo tracedStatusInfo = futureTracedStatus.join();
                DebugModuleInfo traceStopOnWchanInfo = futureTraceStopOnWchan.join();
                DebugModuleInfo idaTracingInfo = futureIdaTracing.join();
                if (javaDebuggerInfo != null || nativeDebuggerInfo != null ||
                        tracedStatusInfo != null || traceStopOnWchanInfo != null ||
                        idaTracingInfo != null) {
                    return new DebugModuleInfo[] {
                            javaDebuggerInfo,
                            nativeDebuggerInfo,
                            tracedStatusInfo,
                            traceStopOnWchanInfo,
                            idaTracingInfo
                    };
                }
                return null;
            }).get();
        }
        catch (Exception e) {
            FuadXLogger.log().error(TAG, "Error checking for debug modules: " +
                    e.getMessage());
            FuadXTombstone tombstone = new FuadXTombstone(Constants.DEBUG_MODULE_NAME,
                    "Error checking for debug modules", e.getMessage(), ErrorCodes
                    .DEFAULT_ERROR_GENERIC_MESSAGE.getValue(), new Throwable().getStackTrace());
            tombstone.save(ctx);
            Log.e(TAG, "Error checking for debug modules: " + e.getMessage(), e);
            return null;
        }
    }

    public static synchronized void stopChecking() {
        Log.e(TAG, "Stopping the Debug module");
        if (handlerDefault != null && handlerExhaustive != null && debugThreadRunnable != null
                && exhaustiveDebugThreadRunnable != null) {
            handlerDefault.removeCallbacks(debugThreadRunnable);
            handlerExhaustive.removeCallbacks(exhaustiveDebugThreadRunnable);
        }
        if (handlerThreadDefault != null) {
            handlerThreadDefault.quitSafely();
            handlerThreadDefault = null;
            handlerDefault = null;
        }
        if (handlerThreadExhaustive != null) {
            handlerThreadExhaustive.quitSafely();
            handlerThreadExhaustive = null;
            handlerExhaustive = null;
        }
        executorService.shutdown();
        executorServiceExhaustive.shutdown();
    }

    private static DebugModuleInfo checkForJavaDebugger(Context ctx) {
        String pattern = "(?:" + Pattern.quote(Constants.JDWP) + ")";
        Pattern p = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
        Log.e(TAG, "Checking for Java debugger...");
        File taskDir = new File(Constants.PATH_PROC_SELF_TASK);
        if (taskDir.exists() && taskDir.isDirectory()) {
            File[] taskEntries = taskDir.listFiles();
            if (taskEntries != null) {
                for (File taskEntry : taskEntries) {
                    String tid = taskEntry.getName();
                    if (tid.equalsIgnoreCase(".") || tid.equalsIgnoreCase("..")) {
                        continue;
                    }
                    String commPath = String.format(Constants.PATH_PROC_SELF_TASK_COMM, tid);
                    Log.e(TAG, "Checking comm path: " + commPath);
                    File commFile = new File(commPath);
                    if (commFile.exists() && commFile.isFile()) {
                        try (BufferedReader bufferedReader =
                                     new BufferedReader(new FileReader(commFile))) {
                            StringBuilder commBuilder = new StringBuilder();
                            String line;
                            while ((line = bufferedReader.readLine()) != null) {
                                commBuilder.append(line).append("\n");
                            }
                            String content = commBuilder.toString();
                            if (content.contains(Constants.JDWP)) {
                                Log.e(TAG, "Java debugger detected in comm file: " + commPath);
                                Matcher matcher = p.matcher(content);
                                String match = matcher.find() ? matcher.group() : "";
                                throw new FuadXRuntimeException(ctx, Constants.DEBUG_MODULE_NAME,
                                        "Java debugger was detected", "Java debugger (" + match + ")",
                                        ErrorCodes.FATAL_DEBUG_JAVA_DEBUGGER.getValue());
                            }
                            else {
                                Log.e(TAG, "No Java debugger detected in comm file: "
                                        + commPath);
                            }
                        }
                        catch (FuadXRuntimeException e) {
                            FuadXLogger.log().fatal(TAG, "Registering Java debugger " +
                                    "detected: " + e.getMessage());
                            Log.e(TAG, "Registering Java debugger", e);
                            return new DebugModuleInfo("JdwpComm",
                                    "checkForJavaDebugger", e.getDetails());
                        }
                        catch (Exception e) {
                            FuadXLogger.log().error(TAG, "Error on method: " + e.getMessage());
                            Log.e(TAG, "Error on method: " + e.getMessage(), e);
                            return null;
                        }
                    }
                }
            }
        }
        else {
            FuadXLogger.log().error(TAG, "Task directory does not exist or is not a directory: " +
                    taskDir.getPath());
            Log.e(TAG, "Task directory does not exist or is not a directory: " +
                    taskDir.getPath());
        }
        return null;
    }

    private static DebugModuleInfo checkForNativeDebugger(Context ctx) {
        Log.e(TAG, "Checking for Native debugger...");
        File statusFile = new File(Constants.PATH_PROC_SELF_STATUS);
        if (statusFile.exists() && statusFile.isFile()) {
            try (BufferedReader bufferedReader = new BufferedReader(new FileReader(statusFile))) {
                String line;
                while ((line = bufferedReader.readLine()) != null) {
                    if (line.startsWith(Constants.TRACER_PID)) {
                        String[] parts = line.split(":");
                        if (parts.length > 1) {
                            int tracerPid = Integer.parseInt(parts[1].trim());
                            if (tracerPid != 0) {
                                Log.e(TAG, "Native debugger detected: TracerPid = " + tracerPid);
                                throw new FuadXRuntimeException(ctx, Constants.DEBUG_MODULE_NAME,
                                        "Native debugger was detected", "Native debugger " +
                                        "(TracerPid = " + tracerPid + ")", ErrorCodes
                                        .FATAL_DEBUG_NATIVE_DEBUGGER.getValue());
                            }
                            else {
                                Log.e(TAG, "No native debugger detected");
                            }
                        }
                    }
                }
            }
            catch (FuadXRuntimeException e) {
                FuadXLogger.log().fatal(TAG,"Registering TracerPid different from zero: " +
                        e.getMessage());
                Log.e(TAG, "Registering TracerPid different from zero: " + e.getMessage(), e);
                return new DebugModuleInfo("TracerPidStatus",
                        "checkForNativeDebugger", e.getDetails());
            }
            catch (Exception e) {
                FuadXLogger.log().error(TAG, "Error on method: " + e.getMessage());
                Log.e(TAG, "Error on method: " + e.getMessage(), e);
            }
        }
        Log.e(TAG, "Checking for Native debugger in threads...");
        File taskDir = new File(Constants.PATH_PROC_SELF_TASK_STATUS);
        File[] threads = taskDir.listFiles();
        if (threads != null) {
            for (File thread : threads) {
                String tid = thread.getName();
                if (tid.equalsIgnoreCase(".") || tid.equalsIgnoreCase("..")) {
                    continue;
                }
                String statusPath = String.format(Constants.PATH_PROC_SELF_TASK_STATUS, tid);
                File threadStatus = new File(statusPath);
                if (!threadStatus.exists())
                    continue;
                try (BufferedReader bufferedReader =
                             new BufferedReader(new FileReader(threadStatus))) {
                    String line;
                    while ((line = bufferedReader.readLine()) != null) {
                        if (line.startsWith(Constants.TRACER_PID)) {
                            String[] parts = line.split(":");
                            if (parts.length > 1) {
                                int tracerPid = Integer.parseInt(parts[1].trim());
                                if (tracerPid != 0) {
                                    Log.e(TAG, "Native debugger detected in thread: " + tid +
                                            ", TracerPid = " + tracerPid);
                                    throw new FuadXRuntimeException(ctx, Constants.DEBUG_MODULE_NAME,
                                            "Native debugger was detected in thread",
                                            "Native debugger " + "(TracerPid = " + tracerPid + ")",
                                            ErrorCodes.FATAL_DEBUG_NATIVE_DEBUGGER.getValue());
                                }
                                else {
                                    Log.e(TAG, "No native debugger detected in thread: " + tid);
                                }
                            }
                        }
                        else {
                            Log.e(TAG, "No native debugger detected in thread status file: " +
                                    threadStatus.getPath() + ", Line: " + line);
                        }
                    }
                }
                catch (FuadXRuntimeException e) {
                    FuadXLogger.log().fatal(TAG,"Registering TracerPid different from " +
                            "zero on thread: " + e.getMessage());
                    Log.e(TAG, "Registering TracerPid different from zero: " + e.getMessage(),
                            e);
                    return new DebugModuleInfo("TracerPidStatus",
                            "checkForNativeDebugger", e.getDetails());
                }
                catch (Exception e) {
                    FuadXLogger.log().error(TAG, "Error on method: " + e.getMessage());
                    Log.e(TAG, "Error reading thread status file: " + e.getMessage(), e);
                }
            }
        }
        return null;
    }

    private static DebugModuleInfo checkTracedStatus(Context ctx) {
        final Pattern PATTERN = Pattern
                .compile("(\\d+)\\s+\\(([^)]+)\\)\\s+(\\S)\\s+(\\d+)\\s+(\\d+)\\s");
        Log.e(TAG, "Checking traced status...");
        String procPath = String.format(Constants.PATH_PROC_PID_TASK_PID_STAT, myPid(), myPid());
        File procFile = new File(procPath);
        if (procFile.exists() && procFile.isFile()) {
            try (BufferedReader bufferedReader = new BufferedReader(new FileReader(procFile))) {
                String line = bufferedReader.readLine();
                if (line != null) {
                    Matcher matcher = PATTERN.matcher(line);
                    if (matcher.find()) {
                        String pid = matcher.group(1);
                        String processName = matcher.group(2);
                        String state = matcher.group(3);
                        String ppid = matcher.group(4);
                        String pgid = matcher.group(5);
                        Log.e(TAG, "PID: " + pid + ", Process Name: " + processName +
                                ", State: " + state + ", PPID: " + ppid + ", PGID: " + pgid);
                        if ("t".equals(state)) {
                            Log.e(TAG, "Process is traced (tracing stop): " + processName);
                            throw new FuadXRuntimeException(ctx, Constants.DEBUG_MODULE_NAME,
                                    "Native tracing was detected",
                                    "Native tracing status is on: " + (state) + " " + procPath,
                                    ErrorCodes.FATAL_DEBUG_NATIVE_DEBUGGER.getValue());
                        }
                        else {
                            Log.e(TAG, "Process is not traced: " + processName);
                        }
                    }
                }
            }
            catch (FuadXRuntimeException e) {
                FuadXLogger.log().fatal(TAG, "Registering traced status: " + e.getMessage());
                Log.e(TAG, "Registering traced status: " + e.getMessage(), e);
                return new DebugModuleInfo("TracedStatus",
                        "checkTracedStatus", e.getDetails());
            }
            catch (Exception e) {
                FuadXLogger.log().error(TAG, "Error on method: " + e.getMessage());
                Log.e(TAG, "Error on method: " + e.getMessage(), e);
            }
        }
        else {
            FuadXLogger.log().error(TAG, "Proc file does not exist or is not a file: " + procPath);
            Log.e(TAG, "Proc file does not exist or is not a file: " + procPath);
        }
        return null;
    }

    private static DebugModuleInfo checkTraceStopOnWchan(Context ctx) {
        Log.e(TAG, "Checking trace stop on wchan...");
        String procPath = String.format(Constants.PATH_PROC_PID_TASK_PID_WCHAN, myPid(), myPid());
        File procFile = new File(procPath);
        if (procFile.exists() && procFile.isFile()) {
            try (BufferedReader bufferedReader = new BufferedReader(new FileReader(procFile))) {
                String line = bufferedReader.readLine();
                if (line != null) {
                    if (line.contains(Constants.PTRACE_STOP)) {
                        Log.e(TAG, "Process is traced (tracing stop): " + line);
                        throw new FuadXRuntimeException(ctx, Constants.DEBUG_MODULE_NAME,
                                "Process is traced",
                                "Process has breakpoints (tracing stop): " + line, ErrorCodes
                                .FATAL_DEBUG_NATIVE_DEBUGGER.getValue());
                    }
                    else {
                        Log.e(TAG, "Process is not traced: " + line);
                    }
                }
            }
            catch (FuadXRuntimeException e) {
                FuadXLogger.log().fatal(TAG, "Registering trace stop on wchan: " +
                        e.getMessage());
                Log.e(TAG, "Registering trace stop on wchan: " + e.getMessage(), e);
                return new DebugModuleInfo("PtraceStop",
                        "checkTraceStopOnWchan", e.getDetails());
            }
            catch (Exception e) {
                FuadXLogger.log().error(TAG, "Error on method: " + e.getMessage());
                Log.e(TAG, "Error reading proc file: " + e.getMessage(), e);
            }
        }
        return null;
    }

    private static DebugModuleInfo checkForIdaTracing(Context ctx) {
        Log.e(TAG, "Checking for IDA tracing...");
        Process process;
        BufferedReader bufferedReader;
        try {
            process = Runtime.getRuntime().exec(Constants.LSOF);
            bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                Log.e(TAG, "lsof line: " + line);
                if (line.contains(Constants.LIBJDWP)) {
                    bufferedReader.close();
                    Log.e(TAG, "IDA tracing detected: " + line);
                    throw new FuadXRuntimeException(ctx, Constants.DEBUG_MODULE_NAME,
                            "IDA tracing was detected",
                            "IDA-Java tracing detected: " + line, ErrorCodes
                            .FATAL_DEBUG_JAVA_DEBUGGER.getValue());
                }
                else {
                    Log.e(TAG, "No IDA tracing detected: " + line);
                }
            }
            int exitCode = process.waitFor();
            Log.e(TAG, "lsof command exited with code: " + exitCode);
        }
        catch (FuadXRuntimeException e) {
            FuadXLogger.log().fatal(TAG, "Registering IDA tracing: " + e.getMessage());
            Log.e(TAG, "Registering IDA tracing: " + e.getMessage(), e);
            return new DebugModuleInfo("IdaTracingOverJdwp",
                    "checkForIdaTracing", e.getDetails());
        }
        catch (Exception e) {
            FuadXLogger.log().error(TAG, "Error on method: " + e.getMessage());
            Log.e(TAG, "Error executing lsof command: " + e.getMessage(), e);
        }
        return null;
    }
}
