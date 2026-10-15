package com.fuad.fuadx.crypto.hash.impl;

import com.fuad.fuadx.crypto.enums.CryptoHashAlgorithmType;
import com.fuad.fuadx.crypto.hash.CryptoHashAlgorithm;
import com.fuad.fuadx.exception.HashException;
import com.fuad.fuadx.util.Base64Utils;

import java.security.MessageDigest;

public class SHA3512CryptoHash implements CryptoHashAlgorithm {
    @Override
    public CryptoHashAlgorithmType type() {
        return CryptoHashAlgorithmType.SHA3_256;
    }

    @Override
    public String digest(byte[] data) {
        try {
            MessageDigest digestCipher = getCipher();
            return Base64Utils.encodeToUrlSafeString(digestCipher.digest(data));
        }
        catch (Exception e) {
            throw new HashException("Error while hashing", e);
        }
    }

    @Override
    public boolean check(byte[] dataHashed, byte[] data) {
        try {
            MessageDigest digestCipher = getCipher();
            return MessageDigest.isEqual(digestCipher.digest(data), dataHashed);
        }
        catch (Exception e) {
            throw new HashException("Error while verifying hashing", e);
        }
    }

    private MessageDigest getCipher() {
        try {
            return MessageDigest.getInstance("SHA3-256");
        }
        catch (Exception e) {
            throw new HashException("Error while retrieving Cipher", e);
        }
    }
}
