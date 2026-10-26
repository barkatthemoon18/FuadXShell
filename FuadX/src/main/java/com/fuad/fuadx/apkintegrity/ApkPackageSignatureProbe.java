package com.fuad.fuadx.apkintegrity;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;

import com.fuad.fuadx.detection.DetectionEvidence;
import com.fuad.fuadx.detection.DetectionSource;
import com.fuad.fuadx.heuristic.HeuristicResult;

import org.bouncycastle.util.encoders.Hex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

public final class ApkPackageSignatureProbe {
    private final Context context;
    private final String expectedPackageName;
    private final Set<String> expectedPins;

    public ApkPackageSignatureProbe(Context context, String expectedPackageName, Set<String> expectedPins) {
        Set<String> normalized = new HashSet<>();
        String value;

        this.context = Objects.requireNonNull(context, "context");
        this.expectedPackageName = Objects.requireNonNull(expectedPackageName, "expectedPackageName");
        Objects.requireNonNull(expectedPins, "expectedPins");

        if (expectedPins.isEmpty()) {
            throw new IllegalArgumentException("Expected signer pins cannot be empty");
        }
        for (String pin : expectedPins) {
            value = Objects.requireNonNull(pin, "expectedPin").replace(":", "")
                    .toUpperCase(Locale.ROOT);
            if (!value.matches("[0-9A-F]{64}")) {
                throw new IllegalArgumentException("Invalid SHA-256 certificate fingerprint");
            }
            normalized.add(value);
        }
        this.expectedPins = Collections.unmodifiableSet(normalized);
    }

    public HeuristicResult scan() {
        Signature[] signers;
        MessageDigest digest;
        Set<String> actualPins = new HashSet<>();

        if (!expectedPackageName.equals(context.getPackageName())) {
            return detected("Unexpected application package name");
        }
        try {
            signers = currentSigners();
            if (signers == null || signers.length == 0) {
                return HeuristicResult.error("APK_SIGENRS_MISSING",
                        "PackageManager returned no signing certificates");
            }
            digest = MessageDigest.getInstance("SHA-256");
            for (Signature signer : signers) {
                if (signer == null) {
                    return HeuristicResult.error("APK_SIGNER_INVALID", "Null signing certificate");
                }
                actualPins.add(Hex.toHexString(digest.digest(signer.toByteArray()))
                        .toUpperCase(Locale.ROOT));
            }
            if (!actualPins.equals(expectedPins) || signers.length != expectedPins.size()) {
                return detected("Installed APK signer identity mismatch");
            }
            return HeuristicResult.clean();
        }
        catch (PackageManager.NameNotFoundException e) {
            return HeuristicResult.error("APK_PACKAGE_NOT_FOUND", "Package information unavailable");
        }
        catch (NoSuchAlgorithmException e) {
            return HeuristicResult.error("APK_DIGEST_UNAVAILABLE", "SHA-256 unavailable");
        }
        catch (RuntimeException e) {
            return HeuristicResult.error("APK_PACKAGE_SIGNATURE_READ_FAILED",
                    "Unable to inspect package signing information");
        }
    }

    @SuppressWarnings("deprecation")
    private Signature[] currentSigners() throws PackageManager.NameNotFoundException {
        Signature[] history;
        PackageManager packageManager;
        PackageInfo packageInfo;
        SigningInfo signingInfo;

        packageManager = context.getPackageManager();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            packageInfo = packageManager.getPackageInfo(expectedPackageName, PackageManager.GET_SIGNING_CERTIFICATES);
            signingInfo = packageInfo.signingInfo;
            if (signingInfo == null) {
                return null;
            }
            if (signingInfo.hasMultipleSigners()) {
                return signingInfo.getApkContentsSigners();
            }
            history = signingInfo.getSigningCertificateHistory();
            if (history != null && history.length > 0) {
                return new Signature[] { history[history.length - 1] };
            }
            return signingInfo.getApkContentsSigners();
        }
        packageInfo = packageManager.getPackageInfo(expectedPackageName, PackageManager.GET_SIGNATURES);
        return packageInfo.signatures;
    }

    private static HeuristicResult detected(String details) {
        return HeuristicResult.detected(Collections.singletonList(
                new DetectionEvidence("ApkPackageSignature", "PackageManager", details,
                        DetectionSource.ANDROID_SIDE)));
    }
}
