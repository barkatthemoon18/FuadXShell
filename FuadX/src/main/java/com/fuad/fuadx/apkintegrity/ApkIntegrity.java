package com.fuad.fuadx.apkintegrity;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.res.AssetManager;
import android.content.res.XmlResourceParser;
import android.os.Build;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.Log;

import com.fuad.fuadx.Constants;
import com.fuad.fuadx.crypto.hash.CryptoHash;
import com.fuad.fuadx.errormsgbox.ErrorCodes;
import com.fuad.fuadx.exception.FuadXRuntimeException;
import com.fuad.fuadx.logger.FuadXLogger;
import com.fuad.fuadx.report.FuadXTombstone;
import com.fuad.fuadx.util.Base64Utils;

import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class ApkIntegrity {
    private static final String TAG = "ApkIntegrity";
    private static final ExecutorService executorService = Executors.newFixedThreadPool(3);
    private static HandlerThread handlerThread;
    private static Handler handler;
    private static Runnable apkIntegrityRunnable;

    public static ApkIntegrityModuleInfo verifyCertificateV1(Context ctx) {
        ZipEntry rsaCertEntry = null;

        try (ZipFile zipFile = new ZipFile(ctx.getPackageCodePath())) {
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.getName().contains("META-INF") && entry.getName().endsWith(".RSA")) {
                    rsaCertEntry = entry;
                    break;
                }
            }
            if (rsaCertEntry == null) {
                Log.e(TAG, "No RSA certificate found in APK");
                return null;
            }
            InputStream inputStream = zipFile.getInputStream(rsaCertEntry);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certificateFactory
                    .generateCertificate(inputStream);
            byte[] digest = Base64Utils.decodeFromUrlSafeString(CryptoHash
                    .SHA2_256.digest(certificate.getEncoded()));
            if (!Hex.toHexString(digest).equalsIgnoreCase(Constants.APK_SIGNATURE)) {
                Log.e(TAG, "APK Signature V1 doesn't match expected signature");
                throw new FuadXRuntimeException(ctx, Constants.INTEGRITY_CONTROL_MODULE_NAME,
                        "APK Signature V1 doesn't match expected signature",
                        "Signature: " + Hex.toHexString(digest) + "/ Expected:" +
                                Constants.APK_SIGNATURE,
                        ErrorCodes.DEFAULT_ERROR_INTEGRTIY_CONTROL.getValue());
            }
            if (certificate.getSubjectDN().getName().contains(Constants.ANDROID_DEBUG)) {
                Log.e(TAG, "APK Signature V1 was signed with Debug Keystore");
                throw new FuadXRuntimeException(ctx, Constants.INTEGRITY_CONTROL_MODULE_NAME,
                        "APK Signature V1 was signed with Debug Keystore",
                        "Certificate Subject DN: " + certificate.getSubjectDN().getName(),
                        ErrorCodes.DEFAULT_ERROR_INTEGRTIY_CONTROL.getValue());
            }
            return null;
        }
        catch (FuadXRuntimeException e) {
            FuadXLogger.log().fatal(TAG, e.getMessage(), Map.of("details", e.getDetails()));
            Log.e(TAG, "Registering APK Signature V1 error: " + e.getMessage(), e);
            return new ApkIntegrityModuleInfo("ApkIntegritySignatureV1",
                    "verifyCertificateV1", e.getDetails());
        }
        catch (Exception e) {
            Log.e(TAG, "Error verifying signature V1: " + e.getMessage(), e);
            return null;
        }
    }

    public static ApkIntegrityModuleInfo verifyCertificateV2Onwards(Context ctx) {
        Signature[] signatures;

        try {
            PackageManager packageManager = ctx.getPackageManager();
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                PackageInfo packageInfo = packageManager.getPackageInfo(ctx.getPackageName(),
                        PackageManager.GET_SIGNING_CERTIFICATES);
                if (packageInfo.signingInfo == null) {
                    Log.e(TAG, "No signing info found");
                    return null;
                }
                signatures = packageInfo.signingInfo.getApkContentsSigners();
            }
            else {
                PackageInfo packageInfo = packageManager.getPackageInfo(ctx.getPackageName(),
                        PackageManager.GET_SIGNATURES);
                if (packageInfo.signatures == null) {
                    Log.e(TAG, "No signatures found");
                    return null;
                }
                signatures = packageInfo.signatures;
            }
            for (Signature signature : signatures) {
                byte[] raw = signature.toByteArray();
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                InputStream inputStream = new ByteArrayInputStream(raw);
                X509Certificate certificate = (X509Certificate) certificateFactory
                        .generateCertificate(inputStream);
                MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
                byte[] digest = messageDigest.digest(certificate.getEncoded());
                if (!Hex.toHexString(digest).equalsIgnoreCase(Constants.APK_SIGNATURE)) {
                    Log.e(TAG, "APK Signature V2 onwards doesn't match expected signature");
                    throw new FuadXRuntimeException(ctx, Constants.INTEGRITY_CONTROL_MODULE_NAME,
                            "APK Signature V2 onwards doesn't match expected signature",
                            "Signature: " + Hex.toHexString(digest) + "/ Expected:" +
                                    Constants.APK_SIGNATURE,
                            ErrorCodes.DEFAULT_ERROR_INTEGRTIY_CONTROL.getValue());
                }
                if (certificate.getSubjectDN().getName().contains(Constants.ANDROID_DEBUG)) {
                    Log.e(TAG, "APK Signature V2 onwards was signed with Debug Keystore");
                    throw new FuadXRuntimeException(ctx, Constants.INTEGRITY_CONTROL_MODULE_NAME,
                            "APK Signature V2 onwards was signed with Debug Keystore",
                            "Certificate Subject DN: " + certificate.getSubjectDN().getName(),
                            ErrorCodes.DEFAULT_ERROR_INTEGRTIY_CONTROL.getValue());
                }
                return null;
            }
            Log.e(TAG, "No matching signature found");
            return null;
        }
        catch (FuadXRuntimeException e) {
            FuadXLogger.log().fatal(TAG, e.getMessage(), Map.of("details", e.getDetails()));
            Log.e(TAG, "Registering APK Signature V2 onwards error: " + e.getMessage(), e);
            return new ApkIntegrityModuleInfo("ApkIntegritySignatureV2Onwards",
                    "verifyCertificateV2Onwards", e.getDetails());
        }
        catch (Exception e) {
            Log.e(TAG, "Error verifying signature V2 and onwards: " + e.getMessage(), e);
            return null;
        }
    }

    public static ApkIntegrityModuleInfo checkAndroidManifest(Context ctx) {
        try {
            AssetManager assetManager = ctx.getAssets();
            XmlResourceParser parser = assetManager.openXmlResourceParser("AndroidManifest.xml");
            while (parser.next() != 1) {
                switch (parser.getEventType()) {
                    case XmlResourceParser.START_DOCUMENT:
                        Log.e(TAG, "Start Document");
                        break;
                    case XmlResourceParser.START_TAG:
                        Log.e(TAG, "Start Tag");
                        if (parser.getName().equalsIgnoreCase(Constants.APPLICATION_CONSTANT)) {
                            for (int i = 0; i < parser.getAttributeCount(); i++) {
                                if (parser.getAttributeName(i).equalsIgnoreCase(Constants.
                                        DEBUGGABLE_CONSTANT)) {
                                    Log.e(TAG, "Application is debuggable");
                                    throw new FuadXRuntimeException(ctx,
                                            Constants.INTEGRITY_CONTROL_MODULE_NAME,
                                            "Apk Integrity check found a debuggable apk",
                                            "Manifest tag: (" + parser.getAttributeName(i) + ")",
                                            ErrorCodes.DEFAULT_ERROR_INTEGRTIY_CONTROL.getValue());
                                }
                            }
                        }
                        break;
                    case XmlResourceParser.END_TAG:
                        Log.e(TAG, "End Tag");
                        break;
                    case XmlResourceParser.TEXT:
                        Log.e(TAG, "Text");
                        break;
                    default:
                        Log.e(TAG, "Unknown event type: " + parser.getEventType());
                        break;
                }
            }
            return null;
        }
        catch (FuadXRuntimeException e) {
            FuadXLogger.log().fatal(TAG, "Found debuggable apk in AndroidManifest: " +
                    e.getMessage());
            Log.e(TAG, "Registering debuggable apk", e);
            return new ApkIntegrityModuleInfo("ApkIntegrityManifest",
                    "checkAndroidManifest", e.getDetails());
        }
        catch (Exception e) {
            FuadXLogger.log().error(TAG, "General error found in checkAndroidManifest: " +
                    e.getMessage());
            Log.e(TAG, "Error in checkAndroidManifest: " + e.getMessage(), e);
            return null;
        }
    }

    public static synchronized ApkIntegrityModuleInfo[] isApkStaticallySecured(Context ctx) {
        try {
            CompletableFuture<ApkIntegrityModuleInfo> futureApkIntegrityManifest = CompletableFuture
                    .supplyAsync(() -> {
                        try {
                            Log.e(TAG, "Checking for APK integrity manifest...");
                            return checkAndroidManifest(ctx);
                        }
                        catch (Exception e) {
                            Log.e(TAG, "Error checking for APK integrity threads: " + e.getMessage(), e);
                            return null;
                        }
                    }, executorService);
            CompletableFuture<ApkIntegrityModuleInfo> futureApkIntegritySignatureLegacy =
                    CompletableFuture.supplyAsync(() -> {
                        try {
                            Log.e(TAG, "Checking for APK integrity legacy signature...");
                            return verifyCertificateV1(ctx);
                        }
                        catch (Exception e) {
                            Log.e(TAG, "Error checking for APK integrity legacy signature: "
                                    + e.getMessage(), e);
                            return null;
                        }
                    }, executorService);
            CompletableFuture<ApkIntegrityModuleInfo> futureApkIntegritySignatureV2Onwards =
                    CompletableFuture.supplyAsync(() -> {
                        try {
                            Log.e(TAG, "Checking for APK integrity V2+ signatures...");
                            return verifyCertificateV2Onwards(ctx);
                        }
                        catch (Exception e) {
                            Log.e(TAG, "Error checking for APK integrity V2+ signatures: "
                                    + e.getMessage(), e);
                            return null;
                        }
                    }, executorService);
            return CompletableFuture.allOf(futureApkIntegrityManifest)
                    .thenApply(v -> {
                        ApkIntegrityModuleInfo apkIntegrityModuleInfoManifest =
                                futureApkIntegrityManifest.join();
                        ApkIntegrityModuleInfo apkIntegrityModuleInfoSignatureLegacy =
                                futureApkIntegritySignatureLegacy.join();
                        ApkIntegrityModuleInfo apkIntegrityModuleInfoSignatureV2Onwards =
                                futureApkIntegritySignatureV2Onwards.join();
                        if (apkIntegrityModuleInfoManifest != null ||
                                apkIntegrityModuleInfoSignatureLegacy != null ||
                                apkIntegrityModuleInfoSignatureV2Onwards != null) {
                            return new ApkIntegrityModuleInfo[] {
                                    apkIntegrityModuleInfoManifest,
                                    apkIntegrityModuleInfoSignatureLegacy,
                                    apkIntegrityModuleInfoSignatureV2Onwards
                            };
                        }
                        return null;
            }).get();
        }
        catch (Exception e) {
            FuadXLogger.log().error(TAG, "Error in Apk Integrity detection: " + e.getMessage());
            FuadXTombstone tombstone = new FuadXTombstone(
                    Constants.INTEGRITY_CONTROL_MODULE_NAME,
                    "Apk Integrity detection error",
                    e.getMessage(),
                    ErrorCodes.DEFAULT_ERROR_INTEGRTIY_CONTROL.getValue(),
                    new Throwable().getStackTrace()
            );
            tombstone.save(ctx);
            Log.e(TAG, "Error in APK integrity check: " + e.getMessage(), e);
            return null;
        }
    }

    public static synchronized void stopChecking() {
        Log.e(TAG, "Stopping APK integrity checks");
        if (handler != null) {
            handler.removeCallbacks(apkIntegrityRunnable);
        }
        if (handlerThread != null) {
            handlerThread.quitSafely();
            handlerThread = null;
            handler = null;
        }
    }
}
