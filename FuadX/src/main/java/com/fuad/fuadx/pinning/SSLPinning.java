package com.fuad.fuadx.pinning;

import android.content.Context;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.Log;

import com.fuad.fuadx.Constants;
import com.fuad.fuadx.errormsgbox.ErrorCodes;
import com.fuad.fuadx.exception.FuadXRuntimeException;
import com.fuad.fuadx.exception.MissingCertificateException;
import com.fuad.fuadx.logger.FuadXLogger;
import com.fuad.fuadx.report.FuadXTombstone;
import com.fuad.fuadx.util.AndroidUtil;

import org.bouncycastle.util.encoders.Hex;

import java.net.URL;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class SSLPinning {
    private static final String TAG = "SSLPinning";
    private static final String[] fingerprintSHA256EachLevel = {
            "87665B9AB9221E21795F03E5FBEDCA723EB71CA22F1AD219C49AF42276B95602",
            "5DFDB3CF31B26F23D87C09F3A0CEF642F64069A9FB7CFE29270BB5DC0F1E16BB",
            "96BCEC06264976F37460779ACF28C5A7CFE8A3C0AAE11A8FFCEE05C0BDDF08C6"
    };
    private static final List<Map.Entry<String, String>> subjectIssuerEachLevel = Arrays.asList(
            new AbstractMap.SimpleEntry<>("api.stackexchange.com", "E5"),
            new AbstractMap.SimpleEntry<>("E5", "ISRG Root X1"),
            new AbstractMap.SimpleEntry<>("ISRG Root X1", "ISRG Root X1")
    );
    private static final long intervalMillis = 10000;
    private static HandlerThread handlerThread;
    private static Handler handler;
    private static Runnable sslPinningRunnable;
    private static final ExecutorService executorService = Executors.newFixedThreadPool(2);

    private static void checkTrustedCerts(List<Map.Entry<Integer, Boolean>>
                                                                  trustedCertsStatus,
                                          Certificate cert) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            if (cert instanceof X509Certificate) {
                /* Check for SHA-256 fingerprint / Common Name */
                String fingerprint = Hex.toHexString(md.digest(cert.getEncoded()));
                for (int i = 0; i < fingerprintSHA256EachLevel.length; i++) {
                    if (fingerprint.equalsIgnoreCase(fingerprintSHA256EachLevel[i])) {
                        if (((X509Certificate) cert).getSubjectX500Principal()
                                .getName().contains(subjectIssuerEachLevel.get(i).getKey()) &&
                                ((X509Certificate) cert).getIssuerX500Principal().getName()
                                        .contains(subjectIssuerEachLevel.get(i).getValue())) {
                            trustedCertsStatus.get(i).setValue(true);
                            Log.e(TAG, "Trusted cert found: " +
                                    ((X509Certificate) cert).getSubjectX500Principal().getName());
                            break;
                        }
                    }
                }
            }
        }
        catch (Exception e) {
            Log.e(TAG, "Error checking trusted certs: " + e.getMessage(), e);
        }
    }

    private static List<Certificate> fillCertificateChain(Certificate[] certs) throws Exception {
        boolean isRootCertSent = false;
        boolean isLeafCertSent = false;
        boolean isMiddleCertSent = false;

        if (((X509Certificate) certs[0]).getSubjectX500Principal().getName()
                .contains(subjectIssuerEachLevel.get(0).getKey()) &&
                ((X509Certificate) certs[0]).getIssuerX500Principal().getName()
                        .contains(subjectIssuerEachLevel.get(0).getValue())) {
            isLeafCertSent = true;
        }
        if (((X509Certificate) certs[1]).getSubjectX500Principal().getName()
                .contains((((X509Certificate) certs[1]).getIssuerX500Principal().getName()))) {
            isRootCertSent = true;
        }
        else {
            isMiddleCertSent = true;
        }
        if (!isLeafCertSent) {
            throw new Exception("Leaf certificate not sent. It's mandatory");
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null);
        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager) {
                X509Certificate[] acceptedIssuers = ((X509TrustManager) tm).getAcceptedIssuers();
                for (X509Certificate cert : acceptedIssuers) {
                    if (!isRootCertSent && cert.getSubjectX500Principal().getName()
                            .contains(subjectIssuerEachLevel.get(2).getKey())) {
                        Log.e(TAG, "Root certificate subject was found in CA Android " +
                                "Store. Sorting certificate chain");
                        return new ArrayList<>(Arrays.asList(certs[0], certs[1], cert));
                    }
                    else if (!isMiddleCertSent && cert.getSubjectX500Principal().getName()
                            .contains(subjectIssuerEachLevel.get(1).getKey())) {
                        Log.e(TAG, "Middle certificate subject was found in CA Android " +
                                "Store. Sorting certificate chain");
                        return new ArrayList<>(Arrays.asList(certs[0], cert, certs[1]));
                    }
                }
            }
        }
        throw new MissingCertificateException("Missing certificate wasn't found in CA Android " +
                "Store. Certificate chain is not valid. Please check your certificate chain");
    }

    /* TODO: Add date validation */
    private static SSLPinningModuleInfo calculateHashesAndIssuerEachLevel(Context ctx,
                                                                          Certificate[] certs) {
        List<Map.Entry<Integer, Boolean>> trustedCertsStatus = Arrays.asList(
                new AbstractMap.SimpleEntry<>(0, Boolean.FALSE),
                new AbstractMap.SimpleEntry<>(1, Boolean.FALSE),
                new AbstractMap.SimpleEntry<>(2, Boolean.FALSE)
        );
        List<Certificate> chainCertificateWithMissingCert;

        try {
            if (certs.length < 2) {
                Log.e(TAG, "Unable to verify certificate chain. Only got one certificate");
                FuadXLogger.log().error(TAG, "Unable to verify certificate chain. " +
                        "Only got one certificate");
                throw new FuadXRuntimeException(ctx, Constants.SSL_PINNING_MODULE_NAME,
                        "Unable to verify certificate chain", "Only got one certificate was provided",
                        ErrorCodes.FATAL_SSL_PINNING_ONE_CERTIFICATE.getValue());
            }
            else if (certs.length == 2) {
                chainCertificateWithMissingCert = fillCertificateChain(certs);
                Log.e(TAG, "Selected CA Android Store self-building certificate chain");
                FuadXLogger.log().info(TAG, "Selected CA Android Store self-building " +
                        "certificate chain");
                for (Certificate cert : chainCertificateWithMissingCert) {
                    checkTrustedCerts(trustedCertsStatus, cert);
                }
                if (trustedCertsStatus.stream().allMatch(entry -> Boolean.TRUE.equals(entry
                        .getValue()))) {
                    Log.e(TAG, "App is properly pinned");
                    return null;
                }
                else {
                    Log.e(TAG, "App is not properly pinned");
                    String formatResults = AndroidUtil
                            .formatFuadXRuntimeSSLPinningDetails(trustedCertsStatus.stream()
                            .filter(entry -> Boolean.FALSE.equals(entry.getValue()))
                            .collect(Collectors.toList()));
                    throw new FuadXRuntimeException(ctx, Constants.SSL_PINNING_MODULE_NAME,
                            "App is not properly pinned", formatResults, ErrorCodes
                            .DEFAULT_ERROR_PINNING_MESSAGE.getValue());
                }
            }
            else if (certs.length == 3) {
                Log.e(TAG, "Got the full chain (three certs). Checking out");
                FuadXLogger.log().info(TAG, "Got the full chain (three certs). " +
                        "Checking out");
                for (Certificate cert : certs) {
                    checkTrustedCerts(trustedCertsStatus, cert);
                }
                if (trustedCertsStatus.stream().allMatch(entry -> Boolean.TRUE.equals(entry
                        .getValue()))) {
                    Log.e(TAG, "App is properly pinned");
                    return null;
                }
                else {
                    Log.e(TAG, "App is not properly pinned");
                    String formatResults = AndroidUtil
                            .formatFuadXRuntimeSSLPinningDetails(trustedCertsStatus.stream()
                                    .filter(entry -> Boolean.FALSE.equals(entry.getValue()))
                                    .collect(Collectors.toList()));
                    throw new FuadXRuntimeException(ctx, Constants.SSL_PINNING_MODULE_NAME,
                            "App is not properly pinned", formatResults, ErrorCodes
                            .DEFAULT_ERROR_PINNING_MESSAGE.getValue());
                }
            }
        }
        catch (FuadXRuntimeException e) {
            Log.e(TAG, "Error checking SSL pinning: " + e.getMessage(), e);
            FuadXLogger.log().fatal(TAG, "Error checking SSL pinning: " + e.getMessage());
            return new SSLPinningModuleInfo("CalculateHashAndFingerprints",
                    "calculateHashesAndIssuerEachLevel", e.getDetails());
        }
        catch (MissingCertificateException e) {
            Log.e(TAG, "Missing certificate exception: " + e.getMessage(), e);
            FuadXLogger.log().error(TAG, "Missing certificate exception: " + e.getMessage());
            FuadXTombstone tombstone = new FuadXTombstone(Constants.SSL_PINNING_MODULE_NAME,
                    "SSL Pinning detection failed", e.getMessage(), ErrorCodes
                    .FATAL_SSL_PINNING_WRONG_CHAIN_VALIDATION.getValue(), new Throwable()
                    .getStackTrace());
            tombstone.save(ctx);
            return null;
        }
        catch (Exception e) {
            FuadXLogger.log().error(TAG, "Error checking SSL pinning: " + e.getMessage());
            Log.e(TAG, "Error checking SSL pinning: " + e.getMessage(), e);
            return null;
        }
        Log.e(TAG, "Should not reach this");
        return null;
    }

    private static SSLPinningModuleInfo checkForSocketConnection(Context ctx) {
        try {
            if (AndroidUtil.isNetworkAvailable(ctx) != -1) {
                Log.e(TAG, "Checking SSL Pinning through SSL Socket connection");
                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, null, null);
                SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
                SSLSocket sslSocket = (SSLSocket) sslSocketFactory
                        .createSocket(new URL(Constants.PINNING_URL).getHost(), 443);
                sslSocket.startHandshake();
                return calculateHashesAndIssuerEachLevel(ctx, sslSocket.getSession()
                        .getPeerCertificates());
            }
            Log.e(TAG, "No internet connection was found. Unable to check SSL pinning");
            FuadXLogger.log().error(TAG, "No internet connection was found. " +
                    "Unable to check SSL pinning");
        }
        catch (Exception e) {
            Log.e(TAG, "Error checking SSL pinning over SSL Socket: " + e.getMessage(), e);
            FuadXLogger.log().error(TAG, "Error checking SSL pinning over SSL Socket: " +
                    e.getMessage());
        }
        return null;
    }

    private static SSLPinningModuleInfo checkforHttpsConnection(Context ctx) {
        try {
            if (AndroidUtil.isNetworkAvailable(ctx) != -1) {
                Log.e(TAG, "Checking SSL Pinning through HTTPS connection");
                HttpsURLConnection httpsURLConnection = (HttpsURLConnection)
                        new URL(Constants.PINNING_URL).openConnection();
                httpsURLConnection.setConnectTimeout(5000);
                httpsURLConnection.connect();
                return calculateHashesAndIssuerEachLevel(ctx, httpsURLConnection
                        .getServerCertificates());
            }
            Log.e(TAG, "No internet connection was found. Unable to check SSL pinning");
            FuadXLogger.log().error(TAG, "No internet connection was found. " +
                    "Unable to check SSL pinning");
        }
        catch (Exception e) {
            Log.e(TAG, "Error checking SSL pinning over HTTPS Conn: " + e.getMessage(), e);
            FuadXLogger.log().error(TAG, "Error checking SSL pinning over SSL Socket: " +
                    e.getMessage());
        }
        return null;
    }

    public static synchronized SSLPinningModuleInfo[] isAppPinned(Context ctx) {
        try {
            CompletableFuture<SSLPinningModuleInfo> futureSocketThread = CompletableFuture
                .supplyAsync(() -> {
                    try {
                        Log.e(TAG, "Checking for SSL Pinning over sockets...");
                        return checkForSocketConnection(ctx);
                    }
                    catch (Exception e) {
                        Log.e(TAG, "Error checking for SSL pinning: " + e.getMessage(), e);
                        return null;
                    }
                }, executorService);
            CompletableFuture<SSLPinningModuleInfo> futureHttpsConnectionThread = CompletableFuture
                .supplyAsync(() -> {
                    try {
                        Log.e(TAG, "Checking for SSL Pinning over HTTPS...");
                        return checkforHttpsConnection(ctx);
                    }
                    catch (Exception e) {
                        Log.e(TAG, "Error checking for SSL pinning: " + e.getMessage(), e);
                        return null;
                    }
                }, executorService);
            return CompletableFuture.allOf(futureSocketThread, futureHttpsConnectionThread)
                .thenApply(v -> {
                    SSLPinningModuleInfo sslPinningModuleInfoSocket = futureSocketThread.join();
                    SSLPinningModuleInfo sslPinningModuleInfoHttps =
                            futureHttpsConnectionThread.join();
                    if (sslPinningModuleInfoSocket != null ||
                            sslPinningModuleInfoHttps != null) {
                        return new SSLPinningModuleInfo[] {
                                sslPinningModuleInfoSocket,
                                sslPinningModuleInfoHttps
                        };
                    }
                    return null;
            }).get();
        }
        catch (Exception e) {
            FuadXLogger.log().error(TAG, "Error in SSL Pinning detection: " +
                    e.getMessage());
            FuadXTombstone tombstone = new FuadXTombstone(Constants.SSL_PINNING_MODULE_NAME,
                    "SSL Pinning detection failed", e.getMessage(), ErrorCodes
                    .DEFAULT_ERROR_GENERIC_MESSAGE.getValue(), new Throwable().getStackTrace());
            tombstone.save(ctx);
            Log.e(TAG, "Error in SSL Pinning detection: " + e.getMessage(), e);
            return null;
        }
    }

    public static synchronized void stopChecking() {
        Log.e(TAG, "Stopping SSL Pinning module");
        if (handler != null) {
            handler.removeCallbacks(sslPinningRunnable);
        }
        if (handlerThread != null) {
            handlerThread.quitSafely();
            handlerThread = null;
            handler = null;
        }
    }
}