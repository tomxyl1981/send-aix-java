package com.aixwallet.crypto.skycoin;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;

public class SkycoinEncoder {

    public static byte[] serializeTransaction(SkycoinTransaction.Transaction tx) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        try {
            writeUint32LE(0, baos);

            writeUint8(0, baos);

            byte[] innerHashBytes = hexToBytes(tx.innerHash);
            baos.write(innerHashBytes);

            byte[] sigsBytes = serializeSliceOfSigs(tx.sigs);
            baos.write(sigsBytes);

            byte[] inputsBytes = serializeSliceOfSHA256(tx.inputs);
            baos.write(inputsBytes);

            byte[] outputsBytes = serializeOutputs(tx.outputs);
            baos.write(outputsBytes);

            byte[] result = baos.toByteArray();

            writeUint32LE(result.length, result, 0);

            return result;
        } catch (IOException e) {
            throw new RuntimeException("Serialization failed", e);
        }
    }

    public static byte[] serializeUxBody(SkycoinTransaction.UxBody ux) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        try {
            byte[] srcTxBytes = hexToBytes(ux.srcTransaction);
            baos.write(srcTxBytes);

            byte[] addrBytes = decodeBase58Address(ux.address);
            baos.write(addrBytes);

            writeUint64LE(ux.coins, baos);
            writeUint64LE(ux.hours, baos);

            return baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("UxBody serialization failed", e);
        }
    }

    public static byte[] serializeSliceOfSigs(List<String> sigs) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        try {
            writeUint32LE(sigs.size(), baos);
            for (String sigHex : sigs) {
                byte[] sigBytes = hexToBytes(sigHex);
                baos.write(sigBytes);
            }
            return baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Sigs serialization failed", e);
        }
    }

    public static byte[] serializeSliceOfSHA256(List<String> inputs) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        try {
            writeUint32LE(inputs.size(), baos);
            for (String inputHex : inputs) {
                byte[] inputBytes = hexToBytes(inputHex);
                baos.write(inputBytes);
            }
            return baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Inputs serialization failed", e);
        }
    }

    public static byte[] serializeOutputs(List<SkycoinTransaction.TransactionOutput> outputs) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        try {
            writeUint32LE(outputs.size(), baos);
            for (SkycoinTransaction.TransactionOutput output : outputs) {
                byte[] outputBytes = serializeOutput(output);
                baos.write(outputBytes);
            }
            return baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Outputs serialization failed", e);
        }
    }

    public static byte[] serializeOutput(SkycoinTransaction.TransactionOutput output) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        try {
            // Base58解码: [Key(20) | Version(1) | Checksum(4)]
            // Go序列化: [Version(1) | Key(20)]
            byte[] decoded = Base58.decode(output.address);
            if (decoded.length != 25) {
                throw new RuntimeException("Invalid address length: " + decoded.length);
            }
            
            // 重排: Version(1) + Key(20) = 21 bytes
            byte[] addrBytes = new byte[21];
            addrBytes[0] = decoded[20];  // Version
            System.arraycopy(decoded, 0, addrBytes, 1, 20);  // Key
            
            baos.write(addrBytes);

            writeUint64LE(output.coins, baos);
            writeUint64LE(output.hours, baos);

            return baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Output serialization failed", e);
        }
    }

    private static void writeUint8(int value, ByteArrayOutputStream baos) throws IOException {
        baos.write((byte) (value & 0xFF));
    }

    private static void writeUint32LE(int value, ByteArrayOutputStream baos) throws IOException {
        baos.write((byte) (value & 0xFF));
        baos.write((byte) ((value >> 8) & 0xFF));
        baos.write((byte) ((value >> 16) & 0xFF));
        baos.write((byte) ((value >> 24) & 0xFF));
    }

    private static void writeUint32LE(int value, byte[] buffer, int offset) {
        buffer[offset] = (byte) (value & 0xFF);
        buffer[offset + 1] = (byte) ((value >> 8) & 0xFF);
        buffer[offset + 2] = (byte) ((value >> 16) & 0xFF);
        buffer[offset + 3] = (byte) ((value >> 24) & 0xFF);
    }

    private static void writeUint64LE(long value, ByteArrayOutputStream baos) throws IOException {
        baos.write((byte) (value & 0xFF));
        baos.write((byte) ((value >> 8) & 0xFF));
        baos.write((byte) ((value >> 16) & 0xFF));
        baos.write((byte) ((value >> 24) & 0xFF));
        baos.write((byte) ((value >> 32) & 0xFF));
        baos.write((byte) ((value >> 40) & 0xFF));
        baos.write((byte) ((value >> 48) & 0xFF));
        baos.write((byte) ((value >> 56) & 0xFF));
    }

    private static byte[] hexToBytes(String hex) {
        if (hex == null || hex.length() % 2 != 0) {
            return new byte[0];
        }
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < result.length; i++) {
            int val = Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
            result[i] = (byte) val;
        }
        return result;
    }
    
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    private static void debugLog(String msg) {
        System.out.println("[SkycoinEncoder] " + msg);
    }

    private static byte[] decodeBase58Address(String address) {
        return Base58.decode(address);
    }
}
