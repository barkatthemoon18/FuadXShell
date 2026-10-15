package com.fuad.fuadx.crypto.hash;

import com.fuad.fuadx.crypto.enums.CryptoHashAlgorithmType;

public interface CryptoHashAlgorithm {
    CryptoHashAlgorithmType type();

    String digest(byte[] digest);

    boolean check(byte[] dataHashed, byte[] data);
}
