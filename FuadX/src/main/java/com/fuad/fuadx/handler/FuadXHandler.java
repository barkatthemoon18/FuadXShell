package com.fuad.fuadx.handler;

import android.content.Context;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.Log;

import com.fuad.fuadx.Constants;
import com.fuad.fuadx.apkintegrity.ApkIntegrity;
import com.fuad.fuadx.apkintegrity.ApkIntegrityModuleInfo;
import com.fuad.fuadx.debug.Debug;
import com.fuad.fuadx.debug.DebugModuleInfo;
import com.fuad.fuadx.logger.FuadXLogger;
import com.fuad.fuadx.pinning.SSLPinning;
import com.fuad.fuadx.pinning.SSLPinningModuleInfo;

import java.util.HashMap;
import java.util.Map;

public class FuadXHandler {
    private static final String TAG = "FuadXHandler";
    private static HandlerThread handlerThread;
    private static Handler handler;
    private static final int delayMillisecs = 5000;
    private static final int delayMillisecsPinning = 10000;

    private static synchronized native void runRootChecks();

    public static synchronized void init(Context ctx) {
        FuadXLogger.log().info(TAG, "Initializing FuadXHandler to run checks");
        if (handlerThread == null || !handlerThread.isAlive()) {
            handlerThread = new HandlerThread("FuadXHandlerThread");
            handlerThread.start();
            handler = new Handler(handlerThread.getLooper());
            handler.post(() -> performChecking(ctx));
        }
    }

    public static synchronized void performChecking(Context ctx) {
        if (handler == null) {
            FuadXLogger.log().error(TAG, "HandlerThread not initialized");
            Log.e(TAG, "HandlerThread not initialized");
            return;
        }
        FuadXLogger.log().info(TAG, "Running checks on background thread");
        Log.e(TAG, "Running checks on background thread");
        runApkIntegrity(ctx);
        runAppPinned(ctx);
        runDebugModule(ctx);
        /* TODO: Root pending */
    }

    public static synchronized void stopCheckingPerModule(String moduleName) {
        switch (moduleName) {
            case Constants.FRIDA_MODULE_NAME:
                stopFridaModule();
                break;
            case Constants.DEBUG_MODULE_NAME:
                stopDebugModule();
                break;
            case Constants.SSL_PINNING_MODULE_NAME:
                stopSSLPinningModule();
                break;
            case Constants.INTEGRITY_CONTROL_MODULE_NAME:
                stopIntegrityControlModule();
                break;
            case Constants.ROOT_MODULE_NAME:
                stopRootModule();
                break;
            default:
                FuadXLogger.log().info(TAG, "Unknown module: " + moduleName);
                Log.e(TAG, "No action performed");
                break;
        }
    }

    private static synchronized void runApkIntegrity(Context ctx) {
        Log.e(TAG, "Initializing Apk Integrity module");
        FuadXLogger.log().info(TAG, "Initializing Apk Integrity module");
        ApkIntegrityModuleInfo[] resultInfo = ApkIntegrity.isApkStaticallySecured(ctx);
        if (resultInfo == null) {
            FuadXLogger.log().info(TAG, "Apk Integrity check is secure");
            Log.e(TAG, "Apk Integrity check is secure");
            stopCheckingPerModule(Constants.INTEGRITY_CONTROL_MODULE_NAME);
        }
        else {
            Map<String, Object> metadata = new HashMap<>();
            for (ApkIntegrityModuleInfo info : resultInfo) {
                if (info != null) {
                    metadata.put("heuristic", info.getModuleHeuristic());
                    metadata.put("method", info.getModuleDetectionMethod());
                    metadata.put("result", info.getModuleDetectionResult());
                }
            }
            FuadXLogger.log().fatal(TAG, "APK Integrity check failed", metadata);
            Log.e(TAG, "APK Integrity check failed");
            stopCheckingPerModule(Constants.INTEGRITY_CONTROL_MODULE_NAME);
        }
    }

    private static synchronized void runAppPinned(Context ctx) {
        Log.e(TAG, "Initializing SSL Pinning module");
        FuadXLogger.log().info(TAG, "Initializing SSL Pinning module");
        SSLPinningModuleInfo[] resultInfo = SSLPinning.isAppPinned(ctx);
        if (resultInfo == null) {
            FuadXLogger.log().info(TAG, "SSL Pinning check is secure");
            Log.e(TAG, "SSL Pinning check is secure");
            handler.postDelayed(() -> performChecking(ctx), delayMillisecsPinning);
        }
        else {
            Map<String, Object> metadata = new HashMap<>();
            for (SSLPinningModuleInfo info : resultInfo) {
                if (info != null) {
                    metadata.put("heuristic", info.getModuleHeuristic());
                    metadata.put("method", info.getModuleDetectionMethod());
                    metadata.put("result", info.getModuleDetectionResult());
                }
            }
            FuadXLogger.log().fatal(TAG, "SSL Pinning check failed", metadata);
            Log.e(TAG, "SSL Pinning check failed");
            stopCheckingPerModule(Constants.SSL_PINNING_MODULE_NAME);
        }
    }

    private static void runDebugModule(Context ctx) {
        Log.e(TAG, "Initializing Debug module");
        FuadXLogger.log().info(TAG, "Initializing Debug module");
        DebugModuleInfo[] resultInfo = Debug.isRunningDebugOnApk(ctx);
        if (resultInfo == null) {
            FuadXLogger.log().info(TAG, "Debug module is not running on the APK");
            Log.e(TAG, "Debug module is not running on the APK");
            handler.postDelayed(() -> performChecking(ctx), delayMillisecs);
        }
        else {
            Map<String, Object> metadata = new HashMap<>();
            for (DebugModuleInfo info : resultInfo) {
                if (info != null) {
                    metadata.put("heuristic", info.getModuleHeuristic());
                    metadata.put("method", info.getModuleDetectionMethod());
                    metadata.put("result", info.getModuleDetectionResult());
                }
            }
            FuadXLogger.log().fatal(TAG, "Debug module is running on the APK", metadata);
            Log.e(TAG, "Debug module is running on the APK");
            stopCheckingPerModule(Constants.DEBUG_MODULE_NAME);
        }
    }

    private static synchronized void stopFridaModule() {
        Log.w(TAG, "Frida is managed by FuadXRuntime. " + "Use FuadXRuntime.stop(ModuleId.FRIDA)");
    }

    private static synchronized void stopDebugModule() {
        // Debug.stopChecking();
        Log.e(TAG, "Stopping the Debug module");
    }

    private static synchronized void stopSSLPinningModule() {
        // SSLPinning.stopChecking();
        Log.e(TAG, "Stopping the SSL Pinning module");
    }

    private static synchronized void stopIntegrityControlModule() {
        // ApkIntegrity.stopChecking();
        Log.e(TAG, "Stopping the Integrity Control module");
    }

    private static synchronized void stopRootModule() {

    }
}
