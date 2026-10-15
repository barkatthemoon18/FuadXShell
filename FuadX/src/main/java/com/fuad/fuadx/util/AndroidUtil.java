package com.fuad.fuadx.util;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.util.Log;

import com.fuad.fuadx.Constants;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class AndroidUtil {
    private static final String TAG = "AndroidUtil";

    public static synchronized String getCmdlinePackageName() {
        String cmdline;

        try {
            File cmdlineFile = new File(Constants.PATH_PROC_CMDLINE);
            if (cmdlineFile.exists() && cmdlineFile.isFile()) {
                try (BufferedReader reader = new BufferedReader(new FileReader(cmdlineFile))) {
                    StringBuilder cmdlineBuilder = new StringBuilder();
                    int character;
                    while ((character = reader.read()) != -1) {
                        if (character >= 32 && character <= 126) {
                            cmdlineBuilder.append((char) character);
                        }
                    }
                    cmdline = cmdlineBuilder.toString();
                    Log.e(TAG, "Cmdline: " + cmdline);
                    if (!cmdline.contains(" ")) {
                        Log.e(TAG, "Package name: " + cmdline);
                        return cmdline;
                    }
                    else {
                        String apkPath = cmdline.split(" ")[0];
                        Log.e(TAG, "APK path: " + apkPath);
                        return cmdline;
                    }
                }
            }
        }
        catch (Exception e) {
            Log.e(TAG, "Error reading cmdline file: " + e.getMessage(), e);
        }
        return null;
    }

    public static synchronized int isNetworkAvailable(Context ctx) {
        try {
            ConnectivityManager connectivityManager =
                    (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (connectivityManager != null) {
                NetworkCapabilities caps = connectivityManager
                        .getNetworkCapabilities(connectivityManager.getActiveNetwork());
                if (caps != null &&
                        caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                        caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
                    if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                        Log.e(TAG, "Network type: WiFi");
                        return 1;
                    }
                    else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                        Log.e(TAG, "Network type: Cellular");
                        return 0;
                    }
                    else {
                        Log.e(TAG, "Network type: Other");
                        return -1;
                    }
                }
            }
        }
        catch (Exception e) {
            Log.e(TAG, "Error checking network availability: " + e.getMessage(), e);
        }
        return -1;
    }

    public static synchronized String generateTimestamp() {
        long timestampMillis = System.currentTimeMillis();

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.getDefault())
                    .format(new Date(timestampMillis));
        }
        return Instant.now().toString();
    }

    public static synchronized String formatFuadXRuntimeSSLPinningDetails(List<Map.Entry<Integer,
            Boolean>> sslPinningScan) {
        StringBuilder sb = new StringBuilder();
        sb.append("SSL Pinning Scan Results:\n");
        for (Map.Entry<Integer, Boolean> entry : sslPinningScan) {
            sb.append("Element: ").append(entry.getKey()).append("\n");
            sb.append("Result: ").append(entry.getValue()).append("\n");
        }
        return sb.toString();
    }
}
