package com.fuad.fuadx.util;

import android.util.Base64;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public abstract class Base64Utils {
    private static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;

    private Base64Utils() {
        /* Empty intentionally */
    }

    public static synchronized byte[] encode(byte[] src) {
        if (src.length == 0) {
            return src;
        }
        return Base64.encode(src, Base64.DEFAULT);
    }

    public static synchronized byte[] decode(byte[] src) {
        if (src.length == 0) {
            return src;
        }
        return Base64.decode(src, Base64.DEFAULT);
    }

    public static synchronized byte[] encodeUrlSafe(byte[] src) {
        if (src.length == 0) {
            return src;
        }
        return Base64.encode(src, Base64.URL_SAFE);
    }

    public static synchronized byte[] decodeUrlSafe(byte[] src) {
        if (src.length == 0) {
            return src;
        }
        return Base64.decode(src, Base64.URL_SAFE);
    }

    public static synchronized String encodeToString(byte[] src) {
        if (src.length == 0) {
            return "";
        }
        return new String(encode(src), DEFAULT_CHARSET);
    }

    public static synchronized byte[] decodeFromString(String src) {
        if (src.isEmpty()) {
            return new byte[0];
        }
        return decode(src.getBytes(DEFAULT_CHARSET));
    }

    public static synchronized String encodeToUrlSafeString(byte[] src) {
        return new String(encodeUrlSafe(src), DEFAULT_CHARSET);
    }

    public static synchronized byte[] decodeFromUrlSafeString(String src) {
        return decodeUrlSafe(src.getBytes(DEFAULT_CHARSET));
    }
}
