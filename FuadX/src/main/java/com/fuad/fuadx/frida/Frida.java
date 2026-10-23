package com.fuad.fuadx.frida;

import static android.os.Process.myPid;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Build;
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
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Frida {
    private static final String TAG = "Frida";
    private static final ExecutorService executorService = Executors.newFixedThreadPool(3);
    private static final long intervalMillis = 5000;
    private static HandlerThread handlerThread;
    private static Handler handler;
    private static Runnable fridaThreadRunnable;

    public static synchronized FridaModuleInfo[] isRunningFridaOnApk(Context ctx) {
        try {
            CompletableFuture<FridaModuleInfo> futureFridaThreads = CompletableFuture.supplyAsync(() -> {
                try {
                    Log.e(TAG, "Checking for Frida threads...");
                    return checkForFridaThreads(ctx);
                }
                catch (Exception e) {
                    Log.e(TAG, "Error checking for Frida threads: " + e.getMessage(), e);
                    return null;
                }
            }, executorService);
            CompletableFuture<FridaModuleInfo> futureFridaPipes = CompletableFuture.supplyAsync(() -> {
                try {
                    Log.e(TAG, "Checking for Frida named pipes...");
                    return checkForFridaNamedPipes(ctx);
                }
                catch (Exception e) {
                    Log.e(TAG, "Error checking for Frida named pipes: " + e.getMessage(), e);
                    return null;
                }
            }, executorService);
            CompletableFuture<FridaModuleInfo> futureFridaLoadedLibs = CompletableFuture.supplyAsync(() -> {
                try {
                    Log.e(TAG, "Checking for Frida loaded libraries...");
                    return checkForFridaLoadedLibraries(ctx);
                }
                catch (Exception e) {
                    Log.e(TAG, "Error checking for Frida loaded libraries: " + e.getMessage(), e);
                    return null;
                }
            }, executorService);
            return CompletableFuture.allOf(futureFridaThreads, futureFridaPipes,
                            futureFridaLoadedLibs)
                    .thenApply(v -> {
                        FridaModuleInfo fridaModuleInfoThreads = futureFridaThreads.join();
                        FridaModuleInfo fridaModuleInfoPipes = futureFridaPipes.join();
                        FridaModuleInfo fridaModuleInfoLoadedLibs = futureFridaLoadedLibs.join();
                        if (fridaModuleInfoThreads != null || fridaModuleInfoPipes != null ||
                                fridaModuleInfoLoadedLibs != null) {
                            return new FridaModuleInfo[]{
                                    fridaModuleInfoThreads,
                                    fridaModuleInfoPipes,
                                    fridaModuleInfoLoadedLibs
                            };
                        }
                        return null;
            }).get();
        }
        catch (Exception e) {
            FuadXLogger.log().error(TAG, "Error in Frida detection: " + e.getMessage());
            FuadXTombstone tombstone = new FuadXTombstone(
                    Constants.FRIDA_MODULE_NAME,
                    "Frida detection error",
                    e.getMessage(),
                    ErrorCodes.DEFAULT_ERROR_GENERIC_MESSAGE.getValue(),
                    new Throwable().getStackTrace());
            tombstone.save(ctx);
            Log.e(TAG, "Error in Frida detection: " + e.getMessage(), e);
            return null;
        }
    }

    public static synchronized void stopChecking() {
        Log.e(TAG, "Stopping the Frida module");
        if (handler != null) {
            handler.removeCallbacks(fridaThreadRunnable);
        }
        if (handlerThread != null) {
            handlerThread.quitSafely();
            handlerThread = null;
            handler = null;
        }
        executorService.shutdown();
    }

    private static FridaModuleInfo checkForFridaThreads(Context ctx) {
        String pattern = "(?:" + Pattern.quote(Constants.GUM_JS_LOOP) + "|" +
                Pattern.quote(Constants.GMAIN) + ")";
        Pattern p = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
        Log.e(TAG, "Checking for Frida threads...");
        File procDir = new File(Constants.PATH_PROC_SELF_TASK);
        if (procDir.exists() && procDir.isDirectory()) {
            File[] fileEntries = procDir.listFiles();
            if (fileEntries != null) {
                for (File fileEntry : fileEntries) {
                    String entryName = fileEntry.getName();
                    if (entryName.equalsIgnoreCase(".") ||
                            entryName.equalsIgnoreCase("..")) {
                        continue;
                    }
                    String fPath = String.format(Constants.PATH_PROC_SELF_TASK_STATUS, entryName);
                    Log.e(TAG, "Testing Frida Thread Path: " + fPath);
                    File f = new File(fPath);
                    if (f.exists() && f.isFile()) {
                        try (BufferedReader bufferedReader = new BufferedReader(new FileReader(f))) {
                            StringBuilder buffer = new StringBuilder();
                            String line;
                            while ((line = bufferedReader.readLine()) != null) {
                                buffer.append(line).append("\n");
                            }
                            String fileContent = buffer.toString();
                            if (fileContent.contains(Constants.GUM_JS_LOOP) ||
                                    fileContent.contains(Constants.GMAIN)) {
                                Log.e(TAG, "Frida thread detected: " + entryName);
                                Matcher matcher = p.matcher(fileContent);
                                String match = matcher.find() ? matcher.group() : "";
                                throw new FuadXRuntimeException(ctx, Constants.FRIDA_MODULE_NAME,
                                        "Frida thread was detected", "Frida thread (" + match
                                         + ")", ErrorCodes
                                        .FATAL_FRIDA_THREAD_DETECTED.getValue());
                            }
                        }
                        catch (FuadXRuntimeException e) {
                            FuadXLogger.log().fatal(TAG, "Registering Frida thread" +
                                    e.getMessage());
                            Log.e(TAG, "Registering Frida thread", e);
                            return new FridaModuleInfo("FridaNamedThreads",
                                    "checkForFridaThreads", e.getDetails());
                        }
                        catch (Exception e) {
                            FuadXLogger.log().error(TAG, "Error reading file: " +
                                    e.getMessage());
                            Log.e(TAG, "Error reading file: " + e.getMessage(), e);
                        }
                    }
                }
            }
        }
        else {
            FuadXLogger.log().error(TAG, "Proc directory does not exist or is not " +
                    "a directory: " + procDir.getAbsolutePath());
            Log.e(TAG, "Proc directory does not exist or is not a directory: " +
                    procDir.getAbsolutePath());
        }
        return null;
    }

    private static FridaModuleInfo checkForFridaNamedPipes(Context ctx) throws IOException {
        Log.e(TAG, "Checking for Frida named pipes...");
        try {
            File procDir = new File(Constants.PATH_PROC_SELF_FD);
            if (procDir.exists() && procDir.isDirectory()) {
                File[] fileEntries = procDir.listFiles();
                if (fileEntries != null) {
                    for (File fileEntry : fileEntries) {
                        String entryName = fileEntry.getName();
                        if (entryName.equalsIgnoreCase(".") ||
                                entryName.equalsIgnoreCase("..")) {
                            continue;
                        }
                        String fPath = String.format(Constants.PATH_PROC_SELF_FD_FORMAT, entryName);
                        Log.e(TAG, "Testing Named Pipe Path: " + fPath);
                        File f = new File(fPath);
                        String targetPath = null;
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                            if (Files.isSymbolicLink(f.toPath())) {
                                targetPath = Files.readSymbolicLink(f.toPath()).toString();
                            }
                        }
                        else {
                            if (f.getAbsolutePath().equals(f.getCanonicalPath())) {
                                targetPath = f.getCanonicalPath();
                            }
                        }
                        if (targetPath != null) {
                            if (targetPath.contains(Constants.LINJECTOR)) {
                                Log.e(TAG, "Frida named pipe detected: " + targetPath);
                                throw new FuadXRuntimeException(ctx, Constants.FRIDA_MODULE_NAME,
                                        "Frida named pipe was deteted", "Frida named pipe " +
                                        "(linjector)", ErrorCodes.FATAL_FRIDA_NAMED_PIPE_DETECTED
                                        .getValue());
                            }
                        }
                    }
                }
            }
        }
        catch (FuadXRuntimeException e) {
            FuadXLogger.log().fatal(TAG, "Registering Frida named pipe: " + e.getMessage());
            Log.e(TAG, "Registering Frida named pipe", e);
            return new FridaModuleInfo("FridaNamedPipes",
                    "checkForFridaNamedPipes", e.getDetails());
        }
        catch (Exception e) {
            FuadXLogger.log().error(TAG, "Error reading file: " + e.getMessage());
            Log.e(TAG, "Error reading file: " + e.getMessage(), e);
        }
        return null;
    }

    private static FridaModuleInfo checkForFridaLoadedLibraries(Context ctx) {
        String pattern = "(?:" + Pattern.quote(Constants.LINJECTOR) + "|" +
                Pattern.quote(Constants.FRIDA_SERVER) + "|" +
                Pattern.quote(Constants.FRIDA_AGENT) + "|" +
                Pattern.quote(Constants.FRIDA_GADGET) + ")";
        Pattern p = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
        Log.e(TAG, "Checking for Frida loaded libraries...");
        try {
            @SuppressLint("DefaultLocale") String lsofCmd = String.format(Constants.LSOF_PID, myPid());
            Process process;
            BufferedReader bufferedReader;
            process = Runtime.getRuntime().exec(lsofCmd);
            bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                Log.e(TAG, "lsof output: " + line);
                if (line.contains(Constants.LINJECTOR) ||
                        line.contains(Constants.FRIDA_SERVER) ||
                        line.contains(Constants.FRIDA_AGENT) ||
                        line.contains(Constants.FRIDA_GADGET)) {
                    Log.e(TAG, "Frida loaded library detected: " + line);
                    Matcher matcher = p.matcher(line);
                    String match = matcher.find() ? matcher.group() : "";
                    throw new FuadXRuntimeException(ctx, Constants.FRIDA_MODULE_NAME,
                            "Frida loaded library was detected", "Frida loaded library " +
                            "(" + match + ")", ErrorCodes
                            .FATAL_FRIDA_LOADED_LIBRARY_DETECTED.getValue());
                }
            }
            int exitCode = process.waitFor();
            Log.e(TAG, "lsof command exit code: " + exitCode);
            bufferedReader.close();
            process.destroy();
        }
        catch (FuadXRuntimeException e) {
            FuadXLogger.log().fatal(TAG, "Registering Frida loaded library: " + e.getMessage());
            Log.e(TAG, "Registering Frida loaded library", e);
            return new FridaModuleInfo("FridaLoadedLibraries",
                    "checkForFridaLoadedLibraries", e.getDetails());
        }
        catch (Exception e) {
            FuadXLogger.log().error(TAG, "Error while running lsof cmd: " + e.getMessage());
            Log.e(TAG, "Error while running lsof cmd: " + e.getMessage(), e);
        }
        return null;
    }
}
