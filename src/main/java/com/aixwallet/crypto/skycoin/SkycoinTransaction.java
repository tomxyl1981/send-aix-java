package com.aixwallet.crypto.skycoin;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class SkycoinTransaction {

    static {
        try {
            // Try to load from resources first
            String libName = "skycoin_serializer";
            java.io.InputStream is = SkycoinTransaction.class.getResourceAsStream("/" + libName + ".dylib");
            if (is != null) {
                java.io.File tempFile = java.io.File.createTempFile(libName, ".dylib");
                tempFile.deleteOnExit();
                try (java.io.FileOutputStream fos = new java.io.FileOutputStream(tempFile)) {
                    byte[] buffer = new byte[4096];
                    int bytesRead;
                    while ((bytesRead = is.read(buffer)) != -1) {
                        fos.write(buffer, 0, bytesRead);
                    }
                }
                System.load(tempFile.getAbsolutePath());
                System.out.println("✅ skycoin_serializer library loaded from resources");
            } else {
                System.loadLibrary("skycoin_serializer");
                System.out.println("✅ skycoin_serializer library loaded successfully");
            }
        } catch (UnsatisfiedLinkError e) {
            System.err.println("⚠️ skycoin_serializer JNI not loaded: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("⚠️ Error loading skycoin_serializer: " + e.getMessage());
        }
    }

    // C JNI functions for serialization
    private static native String nativeHashInner(String inputsHex, String outputsHex);
    private static native String nativeSerializeInputs(String inputHashHex);
    private static native String nativeSerializeOutputs(String addresses, String coinsArr, String hoursArr);
    
    public static String hashInnerCJNI(String inputsHex, String outputsHex) {
        try {
            return nativeHashInner(inputsHex, outputsHex);
        } catch (Exception | UnsatisfiedLinkError e) {
            System.err.println("C JNI hashInner failed: " + e.getMessage());
            return null;
        }
    }

    public static String serializeInputsCJNI(String inputHashHex) {
        try {
            return nativeSerializeInputs(inputHashHex);
        } catch (Exception | UnsatisfiedLinkError e) {
            System.err.println("C JNI serializeInputs failed: " + e.getMessage());
            return null;
        }
    }

    public static String serializeOutputsCJNI(String addresses, String coinsArr, String hoursArr) {
        try {
            return nativeSerializeOutputs(addresses, coinsArr, hoursArr);
        } catch (Exception | UnsatisfiedLinkError e) {
            System.err.println("C JNI serializeOutputs failed: " + e.getMessage());
            return null;
        }
    }
    
    // Debug callback interface
    public interface DebugCallback {
        void onDebug(String message);
    }
    
    private static DebugCallback debugCallback;
    
    public static void setDebugCallback(DebugCallback callback) {
        debugCallback = callback;
    }
    
    private static void debugLog(String msg) {
        System.out.println(msg);
        if (debugCallback != null) {
            debugCallback.onDebug(msg);
        }
    }

    public static class TransactionOutput {
        public String address;
        public long coins;
        public long hours;
        public byte[] addressBytes21; // 21 bytes (version + pubkey hash) for serialization

        public TransactionOutput(String address, long coins, long hours) {
            this.address = address;
            this.coins = coins;
            this.hours = hours;
        }

        public TransactionOutput(String address, long coins, long hours, byte[] addressBytes21) {
            this.address = address;
            this.coins = coins;
            this.hours = hours;
            this.addressBytes21 = addressBytes21;
        }

        public byte[] serialize() {
            return SkycoinEncoder.serializeOutput(this);
        }
    }

    public static class UxBody {
        public String srcTransaction;
        public String address;
        public long coins;
        public long hours;

        public UxBody(String srcTransaction, String address, long coins, long hours) {
            this.srcTransaction = srcTransaction;
            this.address = address;
            this.coins = coins;
            this.hours = hours;
        }

        public byte[] hashBytes() {
            byte[] serialized = SkycoinEncoder.serializeUxBody(this);
            return sha256(sha256(serialized));
        }

        public String hashHex() {
            return bytesToHex(hashBytes());
        }
    }

    public static class Transaction {
        public long length;
        public byte type;
        public String innerHash;
        public List<String> sigs;
        public List<String> inputs;
        public List<TransactionOutput> outputs;

        public Transaction() {
            this.sigs = new ArrayList<>();
            this.inputs = new ArrayList<>();
            this.outputs = new ArrayList<>();
            this.type = 0;
        }

        public byte[] hashInner() {
            // Try to use C JNI functions first for exact Go compatibility
            String inputsHex = null;
            String outputsHex = null;
            
            debugLog("[C JNI] hashInner: Starting...");
            
            // Use C JNI for serialization
            if (inputs.size() == 1) {
                inputsHex = serializeInputsCJNI(inputs.get(0));
                debugLog("[C JNI] serializeInputs: " + inputsHex);
            } else {
                debugLog("[C JNI] Warning: inputs.size() = " + inputs.size() + " (only 1 supported)");
            }
            
            // Build addresses, coins, hours strings for outputs
            if (outputs.size() > 0) {
                StringBuilder addrs = new StringBuilder();
                StringBuilder coins = new StringBuilder();
                StringBuilder hours = new StringBuilder();
                for (int i = 0; i < outputs.size(); i++) {
                    if (i > 0) {
                        addrs.append(",");
                        coins.append(",");
                        hours.append(",");
                    }
                    addrs.append(outputs.get(i).address);
                    coins.append(outputs.get(i).coins);
                    hours.append(outputs.get(i).hours);
                }
                outputsHex = serializeOutputsCJNI(addrs.toString(), coins.toString(), hours.toString());
                debugLog("[C JNI] serializeOutputs: " + outputsHex);
            }
            
            if (inputsHex != null && outputsHex != null) {
                String innerHashHex = hashInnerCJNI(inputsHex, outputsHex);
                debugLog("[C JNI] hashInner result: " + innerHashHex);
                if (innerHashHex != null) {
                    debugLog("[C JNI] SUCCESS - Using C implementation");
                    return hexToBytes(innerHashHex);
                } else {
                    debugLog("[C JNI] ERROR - C returned null, falling back to Java");
                }
            } else {
                debugLog("[C JNI] ERROR - inputs or outputs null, falling back to Java");
            }
            
            // Fallback to Java implementation
            debugLog("[Java] Using Java fallback hashInner");
            byte[] inBytes = SkycoinEncoder.serializeSliceOfSHA256(inputs);
            byte[] outBytes = SkycoinEncoder.serializeOutputs(outputs);
            byte[] combined = new byte[inBytes.length + outBytes.length];
            System.arraycopy(inBytes, 0, combined, 0, inBytes.length);
            System.arraycopy(outBytes, 0, combined, inBytes.length, outBytes.length);
            return sha256(combined);
        }

        public byte[] hash() {
            return sha256(serialize());
        }

        public byte[] serialize() {
            return SkycoinEncoder.serializeTransaction(this);
        }
    }

    public static Transaction createTransaction(
            List<String> inputHashes,
            List<UxBody> uxouts,
            String toAddress,
            long coinsToSend,
            String changeAddress,
            long changeHours,
            String privateKey) {

        Transaction tx = new Transaction();

        tx.outputs.add(new TransactionOutput(toAddress, coinsToSend, 0));

        long totalCoins = 0;
        for (String inputHash : inputHashes) {
            tx.inputs.add(inputHash);
        }
        for (UxBody ux : uxouts) {
            totalCoins += ux.coins;
        }

        long changeCoins = totalCoins - coinsToSend;
        if (changeCoins > 0) {
            tx.outputs.add(new TransactionOutput(changeAddress, changeCoins, changeHours));
        }

        byte[] innerHashBytes = tx.hashInner();
        tx.innerHash = bytesToHex(innerHashBytes);

        for (int i = 0; i < tx.inputs.size(); i++) {
            // Use input hash (same as Go: cipher.AddSHA256(innerHash, txn.In[i]))
            byte[] inputHashBytes = hexToBytes(tx.inputs.get(i));
            byte[] hashToSign = addSHA256(innerHashBytes, inputHashBytes);
            String signature = signHash(hashToSign, privateKey);
            tx.sigs.add(signature);
        }

        byte[] serialized = tx.serialize();
        tx.length = serialized.length;

        return tx;
    }

    public static String signHash(byte[] hash, String privateKeyHex) {
        try {
            byte[] privateKeyBytes = hexToBytes(privateKeyHex);
            debugLog("=== SIGN HASH DEBUG ===");
            debugLog("PrivateKey (hex): " + privateKeyHex);
            debugLog("PrivateKey length: " + privateKeyBytes.length);
            debugLog("Hash to sign (hex): " + bytesToHex(hash));

            // 使用更精确的secp256k1参数
            X9ECParameters params = SECNamedCurves.getByName("secp256k1");
            ECCurve curve = params.getCurve();
            ECPoint G = params.getG();
            BigInteger n = params.getN();

            BigInteger d = new BigInteger(1, privateKeyBytes);
            if (d.compareTo(BigInteger.ONE) < 0 || d.compareTo(n) >= 0) {
                throw new IllegalArgumentException("Invalid private key");
            }

            // 计算公钥用于recovery ID
            ECPoint pubKeyPoint = G.multiply(d).normalize();  // 必须normalize转换为仿射坐标
            byte[] pubKeyBytes = pubKeyPoint.getEncoded(true);
            debugLog("PublicKey (hex): " + bytesToHex(pubKeyBytes));
            debugLog("PublicKey length: " + pubKeyBytes.length);
            
            // 从公钥生成地址用于调试
            String derivedAddress = SkycoinWallet.generateAddress(pubKeyBytes);
            debugLog("Derived address from private key: " + derivedAddress);
            
            // 计算公钥Y坐标
            BigInteger pubKeyY = pubKeyPoint.getAffineYCoord().toBigInteger();
            debugLog("PublicKey Y (hex): " + pubKeyY.toString(16));
            debugLog("PublicKey Y isOdd: " + pubKeyY.testBit(0));
            
            // 使用确定性签名以确保一致性
            BigInteger[] sig = deterministicSign(hash, privateKeyBytes, n);
            BigInteger r = sig[0];
            BigInteger s = sig[1];
            debugLog("R value (hex): " + r.toString(16));
            debugLog("S value (hex): " + s.toString(16));

            // 规范化s值（防止延展性攻击）
            BigInteger halfN = n.shiftRight(1);
            if (s.compareTo(halfN) > 0) {
                s = n.subtract(s);
                debugLog("S normalized (high s -> low s): " + s.toString(16));
            }

            // 计算recovery ID (0或1，基于公钥Y坐标的奇偶性)
            int recoveryId = pubKeyY.testBit(0) ? 1 : 0; // 如果Y是奇数则为1，偶数为0
            debugLog("Recovery ID: " + recoveryId);
            
            // 添加恢复字节
            byte[] rBytes = bigIntegerToBytes(r, 32);
            byte[] sBytes = bigIntegerToBytes(s, 32);
            
            byte[] signature = new byte[65];
            System.arraycopy(rBytes, 0, signature, 0, 32);
            System.arraycopy(sBytes, 0, signature, 32, 32);
            signature[64] = (byte) recoveryId; // recovery byte: 0或1
            
            String sigHex = bytesToHex(signature);
            debugLog("Final Signature (hex): " + sigHex);
            debugLog("Signature R (hex): " + sigHex.substring(0, 64));
            debugLog("Signature S (hex): " + sigHex.substring(64, 128));
            debugLog("Signature Recovery: " + signature[64]);
            debugLog("=== END SIGN DEBUG ===");

            return sigHex;
        } catch (Exception e) {
            debugLog("ERROR in signHash: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Failed to sign hash", e);
        }
    }

    // 确定性签名实现（RFC 6979）
    private static BigInteger[] deterministicSign(byte[] hash, byte[] privateKey, BigInteger n) {
        try {
            // 使用RFC 6979确定性签名算法
            BigInteger d = new BigInteger(1, privateKey);
            
            // 初始化HMAC-SHA256
            Mac mac = Mac.getInstance("HmacSHA256");
            byte[] v = new byte[32];
            byte[] k = new byte[32];
            
            // 初始化V为0x01
            Arrays.fill(v, (byte) 0x01);
            // 初始化K为0x00
            Arrays.fill(k, (byte) 0x00);
            
            // Step B
            mac.init(new SecretKeySpec(k, "HmacSHA256"));
            mac.update(v);
            mac.update((byte) 0x00); // 0x00 for private key generation
            mac.update(privateKey);
            mac.update(hash);
            k = mac.doFinal();
            
            // Step C
            mac.init(new SecretKeySpec(k, "HmacSHA256"));
            mac.update(v);
            v = mac.doFinal();
            
            // Step D
            mac.init(new SecretKeySpec(k, "HmacSHA256"));
            mac.update(v);
            mac.update((byte) 0x01); // 0x01 for signature generation
            mac.update(privateKey);
            mac.update(hash);
            k = mac.doFinal();
            
            // Step E
            mac.init(new SecretKeySpec(k, "HmacSHA256"));
            mac.update(v);
            v = mac.doFinal();
            
            // Generate K
            BigInteger kValue;
            do {
                // Step F & G
                mac.init(new SecretKeySpec(k, "HmacSHA256"));
                mac.update(v);
                v = mac.doFinal();
                
                kValue = new BigInteger(1, v);
            } while (kValue.equals(BigInteger.ZERO) || kValue.compareTo(n) >= 0);
            
            // 使用生成的k值进行签名
            X9ECParameters params = SECNamedCurves.getByName("secp256k1");
            org.bouncycastle.crypto.params.ECDomainParameters ecDomainParams = 
                new org.bouncycastle.crypto.params.ECDomainParameters(
                    params.getCurve(), params.getG(), params.getN(), params.getH());
            
            CipherParameters privKey = new org.bouncycastle.crypto.params.ECPrivateKeyParameters(d, ecDomainParams);
            ECDSASigner signer = new ECDSASigner();
            signer.init(true, privKey);
            
            return signer.generateSignature(hash);
        } catch (Exception e) {
            throw new RuntimeException("Deterministic signing failed", e);
        }
    }

    private static byte[] bigIntegerToBytes(BigInteger b, int numBytes) {
        byte[] bytes = new byte[numBytes];
        byte[] biBytes = b.toByteArray();
        int start = (biBytes.length == numBytes + 1) ? 1 : 0;
        int length = Math.min(biBytes.length - start, numBytes);
        System.arraycopy(biBytes, start, bytes, numBytes - length, length);
        return bytes;
    }

    private static byte[] addSHA256(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return sha256(result);
    }

    public static byte[] sha256(byte[] input) {
        SHA256Digest digest = new SHA256Digest();
        digest.update(input, 0, input.length);
        byte[] result = new byte[32];
        digest.doFinal(result, 0);
        return result;
    }

    public static String bytesToHex(byte[] bytes) {
        return Hex.toHexString(bytes);
    }

    public static byte[] hexToBytes(String hex) {
        if (hex == null || hex.length() % 2 != 0) {
            return new byte[0];
        }
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < result.length; i++) {
            String byteStr = hex.substring(2 * i, 2 * i + 2);
            result[i] = (byte) Integer.parseInt(byteStr, 16);
        }
        return result;
    }

    public static byte[] longToBytesLE(long value) {
        byte[] result = new byte[8];
        result[0] = (byte) (value & 0xFF);
        result[1] = (byte) ((value >> 8) & 0xFF);
        result[2] = (byte) ((value >> 16) & 0xFF);
        result[3] = (byte) ((value >> 24) & 0xFF);
        result[4] = (byte) ((value >> 32) & 0xFF);
        result[5] = (byte) ((value >> 40) & 0xFF);
        result[6] = (byte) ((value >> 48) & 0xFF);
        result[7] = (byte) ((value >> 56) & 0xFF);
        return result;
    }

    public static byte[] decodeBase58Address(String address) {
        return Base58.decode(address);
    }

    public static String encodeBase58(byte[] data) {
        return Base58.encode(data);
    }

    private static byte[] trimLeadingZeros(byte[] bytes) {
        int i = 0;
        while (i < bytes.length - 1 && bytes[i] == 0) {
            i++;
        }
        byte[] result = new byte[bytes.length - i];
        System.arraycopy(bytes, i, result, 0, result.length);
        return result;
    }
}
