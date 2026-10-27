package com.fuad.fuadx.apkintegrity.verifier;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public final class ParsedSigner {
    public static final class AlgorithmValue {
        private final int algorithmId;
        private final byte[] value;

        AlgorithmValue(int algorithmId, byte[] value) {
            this.algorithmId = algorithmId;
            this.value = Objects.requireNonNull(value, "value").clone();
        }

        public int getAlgorithmId() {
            return algorithmId;
        }

        public byte[] getValue() {
            return value.clone();
        }
    }

    private final int schemeId;
    private final int signerIndex;
    private final int minSdk;
    private final int maxSdk;
    private final byte[] signedData;
    private final byte[] publicKeySpki;
    private final List<AlgorithmValue> signatures;
    private final List<AlgorithmValue> digests;
    private final List<byte[]> certificatesDer;
    private final Map<Integer, byte[]> additionalAttributes;

    ParsedSigner(int schemeId, int signerIndex, int minSdk, int maxSdk, byte[] signedData,
                 byte[] publicKeySpki, List<AlgorithmValue> signatures, List<AlgorithmValue> digests,
                 List<byte[]> certificatesDer, Map<Integer, byte[]> additionalAttributes) {
        List<byte[]> certificates = new ArrayList<>(certificatesDer.size());
        Map<Integer, byte[]> attributes = new HashMap<>();

        this.schemeId = schemeId;
        this.signerIndex = signerIndex;
        this.minSdk = minSdk;
        this.maxSdk = maxSdk;
        this.signedData = Objects.requireNonNull(signedData, "signedData").clone();
        this.publicKeySpki = Objects.requireNonNull(publicKeySpki, "publicKeySpki").clone();
        this.signatures = Collections.unmodifiableList(new ArrayList<>(signatures));
        this.digests = Collections.unmodifiableList(new ArrayList<>(digests));
        certificatesDer.forEach(certificate -> certificates
                .add(Objects.requireNonNull(certificate, "certificate").clone()));
        this.certificatesDer = Collections.unmodifiableList(certificates);
        additionalAttributes.forEach((id, bytes) -> attributes.put(id, bytes.clone()));
        this.additionalAttributes = Collections.unmodifiableMap(attributes);
    }

    public int getSchemeId() {
        return schemeId;
    }

    public int getSignerIndex() {
        return signerIndex;
    }

    public int getMinSdk() {
        return minSdk;
    }

    public int getMaxSdk() {
        return maxSdk;
    }

    public byte[] getSignedData() {
        return signedData.clone();
    }

    public byte[] getPublicKeySpki() {
        return publicKeySpki.clone();
    }

    public List<AlgorithmValue> getSignatures() {
        return signatures;
    }

    public List<AlgorithmValue> getDigests() {
        return digests;
    }

    public List<byte[]> getCertificatesDer() {
        List<byte[]> copy = new ArrayList<>(certificatesDer.size());

        certificatesDer.forEach(certificate -> copy.add(certificate.clone()));
        return Collections.unmodifiableList(copy);
    }

    public Map<Integer, byte[]> getAdditionalAttributes() {
        Map<Integer, byte[]> copy = new HashMap<>();

        additionalAttributes.forEach((id, bytes) -> copy.put(id, bytes.clone()));
        return Collections.unmodifiableMap(copy);
    }
 }
