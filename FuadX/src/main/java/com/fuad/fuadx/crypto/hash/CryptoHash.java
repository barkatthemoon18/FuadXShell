package com.fuad.fuadx.crypto.hash;

import com.fuad.fuadx.crypto.enums.CryptoHashAlgorithmType;
import com.fuad.fuadx.crypto.hash.impl.SHA2256CryptoHash;
import com.fuad.fuadx.crypto.hash.impl.SHA2512CryptoHash;
import com.fuad.fuadx.crypto.hash.impl.SHA3256CryptoHash;
import com.fuad.fuadx.crypto.hash.impl.SHA3512CryptoHash;

import java.util.function.Supplier;

public enum CryptoHash implements CryptoHashAlgorithm {
    SHA2_256(SHA2256CryptoHash::new),
    SHA2_512(SHA2512CryptoHash::new),
    SHA3_256(SHA3256CryptoHash::new),
    SHA3_512(SHA3512CryptoHash::new);

    private final CryptoHashAlgorithm algorithm;

    CryptoHash(Supplier<CryptoHashAlgorithm> supplier) {
        this.algorithm = supplier.get();
    }

    @Override
    public CryptoHashAlgorithmType type() { return this.algorithm.type(); }

    @Override
    public String digest(byte[] digest) {
        return this.algorithm.digest(digest);
    }

    @Override
    public boolean check(byte[] dataHashed, byte[] data) {
        return this.algorithm.check(dataHashed, data);
    }
}
