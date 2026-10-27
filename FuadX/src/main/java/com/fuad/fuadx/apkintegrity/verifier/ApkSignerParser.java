package com.fuad.fuadx.apkintegrity.verifier;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public final class ApkSignerParser {
    private static final int MAX_SIGNERS = 64;
    private static final int MAX_ALGORITHMS = 64;
    private static final int MAX_CERTIFICATES = 32;
    private static final int MAX_ATTRIBUTES = 256;

    private ApkSignerParser() {
        /* Empty intentionally */
    }

    public static List<ParsedSigner> parse(byte[] schemeBlock, int schemeId) throws IOException {
        List<ParsedSigner> result;
        ByteBuffer rootBuffer;
        ByteBuffer signersBuffer;

        Objects.requireNonNull(schemeBlock, "schemeBlock");
        if (schemeId != ApkSigningBlockReader.V2_ID && schemeId != ApkSigningBlockReader.V3_ID &&
                schemeId != ApkSigningBlockReader.V31_ID) {
            throw new IllegalArgumentException("Unsupported scheme ID");
        }
        rootBuffer = ByteBuffer.wrap(schemeBlock).order(ByteOrder.LITTLE_ENDIAN);
        signersBuffer = lengthPrefixedSlice(rootBuffer, "signers");
        requireConsumed(rootBuffer, "scheme block");
        result = new ArrayList<>();
        while (signersBuffer.hasRemaining()) {
            if (result.size() >= MAX_SIGNERS) {
                throw new IOException("Too many signers");
            }
            result.add(parseSigner(lengthPrefixedSlice(signersBuffer, "signer"), schemeId, result.size()));
        }
        if (result.isEmpty()) {
            throw new IOException("No signers found");
        }
        return Collections.unmodifiableList(result);
    }

    private static ParsedSigner parseSigner(ByteBuffer signerBuffer, int schemeId, int index) throws IOException {
        List<ParsedSigner.AlgorithmValue> signatures;
        List<ParsedSigner.AlgorithmValue> digests;
        List<byte[]> certificates;
        Map<Integer, byte[]> attributes;
        ByteBuffer dataBuffer;
        byte[] signedData;
        byte[] publicKey;
        boolean v3;
        int minSdk;
        int maxSdk;
        int signedMinSdk;
        int signedMaxSdk;

        v3 = schemeId == ApkSigningBlockReader.V2_ID;
        signedData = lengthPrefixedBytes(signerBuffer, "signedData");
        minSdk = -1;
        maxSdk = -1;
        if (v3) {
            minSdk = sdk(signerBuffer, "outer minSdk");
            maxSdk = sdk(signerBuffer, "outer maxSdk");
            validateSdkRange(minSdk, maxSdk);
        }
        signatures = parseAlgorithms(lengthPrefixedSlice(signerBuffer, "signatures"), "signatures");
        publicKey = lengthPrefixedBytes(signerBuffer, "publicKey");
        if (publicKey.length == 0) {
            throw new IOException("Empty public key");
        }
        requireConsumed(signerBuffer, "signer");
        dataBuffer = ByteBuffer.wrap(signedData).order(ByteOrder.LITTLE_ENDIAN);
        digests = parseAlgorithms(lengthPrefixedSlice(dataBuffer, "digests"), "digests");
        certificates = parseCertificates(lengthPrefixedSlice(dataBuffer, "certificates"));
        if (v3) {
            signedMinSdk = sdk(dataBuffer, "signed minSdk");
            signedMaxSdk = sdk(dataBuffer, "signed maxSdk");
            if (minSdk != signedMinSdk || maxSdk != signedMaxSdk) {
                throw new IOException("SDK range mismatch");
            }
        }
        attributes = parseAttributes(lengthPrefixedSlice(dataBuffer, "additional attributes"));
        requireConsumed(dataBuffer, "signedData");
        if (digests.size() != signatures.size()) {
            throw new IOException("Digest and signature algorithm lists differ");
        }
        for (int i = 0; i < digests.size(); i++) {
            if (digests.get(i).getAlgorithmId() != signatures.get(i).getAlgorithmId()) {
                throw new IOException("Digest/Signature algorithm order mismatch");
            }
        }
        return new ParsedSigner(schemeId, index, minSdk, maxSdk, signedData, publicKey, signatures,
                digests, certificates, attributes);
    }

    private static List<ParsedSigner.AlgorithmValue> parseAlgorithms(ByteBuffer sequence, String name) throws IOException {
        List<ParsedSigner.AlgorithmValue> result = new ArrayList<>();
        Set<Integer> watched = new HashSet<>();
        ByteBuffer entryBuffer;
        byte[] value;
        int algorithmId;

        while (sequence.hasRemaining()) {
            if (result.size() >= MAX_ALGORITHMS) {
                throw new IOException("Too many " + name);
            }
            entryBuffer = lengthPrefixedSlice(sequence, name + " entry");
            algorithmId = uint32(entryBuffer, "algorithm ID");
            value = lengthPrefixedBytes(entryBuffer, name + " value");
            requireConsumed(entryBuffer, name + " entry");
            if (value.length == 0 || !watched.add(algorithmId)) {
                throw new IOException("Empty or duplicate " + name + " entry");
            }
            result.add(new ParsedSigner.AlgorithmValue(algorithmId, value));
        }
        if (result.isEmpty()) {
            throw new IOException("Empty " + name);
        }
        return result;
    }

    private static List<byte[]> parseCertificates(ByteBuffer sequence) throws IOException {
        List<byte[]> result = new ArrayList<>();
        byte[] certificate;

        while (sequence.hasRemaining()) {
            if (result.size() >= MAX_CERTIFICATES) {
                throw new IOException("Too many certificates");
            }
            certificate = lengthPrefixedBytes(sequence, "certificate");
            if (certificate.length == 0) {
                throw new IOException("Empty certificate");
            }
            result.add(certificate);
        }
        if (result.isEmpty()) {
            throw new IOException("No certificates");
        }
        return result;
    }

    private static Map<Integer, byte[]> parseAttributes(ByteBuffer sequence) throws IOException {
        Map<Integer, byte[]> result = new LinkedHashMap<>();
        ByteBuffer entryBuffer;
        byte[] value;
        int id;

        while (sequence.hasRemaining()) {
            if (result.size() >= MAX_ATTRIBUTES) {
                throw new IOException("Too many attributes");
            }
            entryBuffer = lengthPrefixedSlice(sequence, "attribute");
            id = uint32(entryBuffer, "attribute ID");
            value = new byte[entryBuffer.remaining()];
            entryBuffer.get(value);
            if (result.putIfAbsent(id, value) != null) {
                throw new IOException("Duplicate attribute ID");
            }
        }
        return result;
    }

    private static ByteBuffer lengthPrefixedSlice(ByteBuffer parent, String field) throws IOException {
        ByteBuffer sliceBuffer;
        long length;
        int size;

        length = Integer.toUnsignedLong(uint32(parent, field + " length"));
        if (length >= parent.remaining()) {
            throw new IOException("Invalid length for " + field);
        }
        size = (int) length;
        sliceBuffer = parent.slice().order(ByteOrder.LITTLE_ENDIAN);
        sliceBuffer.limit(size);
        parent.position(parent.position() + size);
        return sliceBuffer;
    }

    private static byte[] lengthPrefixedBytes(ByteBuffer parent, String field) throws IOException {
        ByteBuffer dataBuffer;
        byte[] bytes;

        dataBuffer = lengthPrefixedSlice(parent, field);
        bytes = new byte[dataBuffer.remaining()];
        dataBuffer.get(bytes);
        return bytes;
    }

    private static int uint32(ByteBuffer dataBuffer, String field) throws IOException {
        if (dataBuffer.remaining() < Integer.BYTES) {
            throw new IOException("Truncated " + field);
        }
        return dataBuffer.getInt();
    }

    private static int sdk(ByteBuffer dataBuffer, String field) throws IOException {
        long value;

        value = Integer.toUnsignedLong(uint32(dataBuffer, field));
        if (value == 0 || value > Integer.MAX_VALUE) {
            throw new IOException("Invalid " + field);
        }
        return (int) value;
    }

    private static void validateSdkRange(int min, int max) throws IOException {
        if (min > max) {
            throw new IOException("Invalid SDK range");
        }
    }

    private static void requireConsumed(ByteBuffer buffer, String field) throws IOException {
        if (buffer.hasRemaining()) {
            throw new IOException("Trailing bytes in " + field);
        }
    }
}
