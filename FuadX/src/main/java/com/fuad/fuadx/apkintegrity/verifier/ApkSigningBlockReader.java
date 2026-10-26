package com.fuad.fuadx.apkintegrity.verifier;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public final class ApkSigningBlockReader {
    public static final int V2_ID = 0x7109871a;
    public static final int V3_ID = 0xf05368c0;
    public static final int V31_ID = 0x1b93ad61;
    private static final byte[] MAGIC = "APK Sig Block 42".getBytes(StandardCharsets.UTF_8);
    private static final int EOCD_MIN_SIZE = 22;
    private static final int MAX_ZIP_COMMENT = 65535;
    private static final long MAX_SIGNING_BLOCK_BYTES = 32L * 1024 * 1024;

    private ApkSigningBlockReader() {
        /* Empty intentionally */
    }

    public static final class Layout {
        public final long signingBlockOffset;
        public final long centralDirectoryOffset;
        public final long eocdOffset;
        private final Map<Integer, byte[]> schemeBlocks;

        private Layout(long signingBlockOffset, long centralDirectoryOffset, long eocdOffset,
                       Map<Integer, byte[]> schemeBlocks) {
            this.signingBlockOffset = signingBlockOffset;
            this.centralDirectoryOffset = centralDirectoryOffset;
            this.eocdOffset = eocdOffset;
            this.schemeBlocks = new HashMap<>(schemeBlocks);
        }

        public byte[] getSchemeBlock(int id) {
            byte[] value = schemeBlocks.get(id);
            return value == null ? null : value.clone();
        }

        public boolean hasScheme(int id) {
            return schemeBlocks.containsKey(id);
        }
    }

    public static Layout read(File apkFile) throws IOException {
        Map<Integer, byte[]> schemes;
        ByteBuffer zipBuffer;
        ByteBuffer locatorBuffer;
        ByteBuffer footerBuffer;
        ByteBuffer headerBuffer;
        ByteBuffer pairsBuffer;
        byte[] tail;
        byte[] footer;
        byte[] magic;
        byte[] value;
        long fileSize;
        long cdSize;
        long cdOffset;
        long eocdOffset;
        long blockSize;
        long blockStart;
        long pairsLength;
        int tailSize;
        int disk;
        int diskEntries;
        int totalEntries;
        int eocdPosition;
        int cdDisk;
        int entriesLength;
        int id;
        int valueLength;
        boolean signatureMatches;
        boolean commentMatches;

        Objects.requireNonNull(apkFile, "apkFile");
        try (RandomAccessFile apk = new RandomAccessFile(apkFile, "r")) {
            fileSize = apk.length();
            if (fileSize < EOCD_MIN_SIZE) {
                throw new IOException("APK size is too short");
            }
            tailSize = (int)Math.min(fileSize, EOCD_MIN_SIZE + MAX_ZIP_COMMENT);
            tail = readAt(apk, fileSize - tailSize, tailSize);
            zipBuffer = ByteBuffer.wrap(tail).order(ByteOrder.LITTLE_ENDIAN);
            eocdPosition = -1;
            for (int i = tailSize - EOCD_MIN_SIZE; i >= 0; i--) {
                signatureMatches = u32(zipBuffer, i) == 0x06054b50L;
                commentMatches = i + EOCD_MIN_SIZE + u16(zipBuffer, i + 20) == tailSize;
                if (signatureMatches && commentMatches) {
                    eocdPosition = i;
                    break;
                }
            }
            if (eocdPosition < 0) {
                throw new IOException("ZIP EOCD not found");
            }
            disk = u16(zipBuffer, eocdPosition + 4);
            cdDisk = u16(zipBuffer, eocdPosition + 6);
            diskEntries = u16(zipBuffer, eocdPosition + 8);
            totalEntries = u16(zipBuffer, eocdPosition + 10);
            if (disk != 0 || cdDisk != 0 || diskEntries != totalEntries) {
                throw new IOException("Multi-disk ZIP unsupported");
            }
            cdSize = u32(zipBuffer, eocdPosition + 12);
            cdOffset = u32(zipBuffer, eocdPosition + 16);
            if (cdSize == 0xffffffffL || totalEntries == 0xffff) {
                throw new IOException("ZIP64 unsupported");
            }
            eocdOffset = fileSize - tailSize + eocdPosition;
            if (eocdOffset >= 20) {
                locatorBuffer = ByteBuffer.wrap(readAt(apk, eocdOffset - 20, 4)).order(ByteOrder.LITTLE_ENDIAN);
                if (locatorBuffer.getInt() == 0x07064b50) {
                    throw new IOException("ZIP64 unsupported");
                }
            }
            if (cdOffset + cdSize != eocdOffset || cdOffset < 24) {
                throw new IOException("Invalid ZIP central directory layout");
            }
            footer = readAt(apk, cdOffset - 24, 24);
            footerBuffer = ByteBuffer.wrap(footer).order(ByteOrder.LITTLE_ENDIAN);
            blockSize = footerBuffer.getLong();
            magic = Arrays.copyOfRange(footer, 8, 24);
            if (!Arrays.equals(magic, MAGIC)) {
                throw new IOException("APK Signing block magic missing");
            }
            if (blockSize < 24 || blockSize > MAX_SIGNING_BLOCK_BYTES || blockSize > cdOffset - 8) {
                throw new IOException("Invalid APK Signing Block size");
            }
            blockStart = cdOffset - blockSize - 8;
            headerBuffer = ByteBuffer.wrap(readAt(apk, blockStart, 8)).order(ByteOrder.LITTLE_ENDIAN);
            if (headerBuffer.getLong() != blockSize) {
                throw new IOException("Signing Block sizes disagree");
            }
            entriesLength = (int) (blockSize - 24);
            pairsBuffer = ByteBuffer.wrap(readAt(apk, blockStart + 8, entriesLength)).order(ByteOrder.LITTLE_ENDIAN);
            schemes = new HashMap<>();
            while (pairsBuffer.hasRemaining()) {
                if (pairsBuffer.remaining() < 8) {
                    throw new IOException("Truncated signing block entry");
                }
                pairsLength = pairsBuffer.getLong();
                if (pairsLength < 4 || pairsLength > pairsBuffer.remaining()) {
                    throw new IOException("Malformed signing block entry length");
                }
                id = pairsBuffer.getInt();
                valueLength = (int) pairsLength - 4;
                if (id == V2_ID || id == V3_ID || id == V31_ID) {
                    if (schemes.containsKey(id)) {
                        throw new IOException("Duplicate signature scheme block");
                    }
                    value = new byte[valueLength];
                    pairsBuffer.get(value);
                    schemes.put(id, value);
                }
                else {
                    pairsBuffer.position(pairsBuffer.position() + valueLength);
                }
            }
            return new Layout(blockStart, cdOffset, eocdOffset, schemes);
        }
    }

    private static int u16(ByteBuffer buffer, int offset) {
        return Short.toUnsignedInt(buffer.getShort(offset));
    }

    private static long u32(ByteBuffer buffer, int offset) {
        return Integer.toUnsignedLong(buffer.getInt(offset));
    }

    private static byte[] readAt(RandomAccessFile file, long offset, int length) throws IOException {
        byte[] bytes = new byte[length];

        file.seek(offset);
        file.readFully(bytes);
        return bytes;
    }
}
