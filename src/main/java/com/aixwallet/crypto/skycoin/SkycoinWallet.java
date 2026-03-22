package com.aixwallet.crypto.skycoin;

import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class SkycoinWallet {
    private String address;
    private String publicKey;
    private String privateKey;
    private String seed;

    private static final org.bouncycastle.asn1.x9.X9ECParameters PARAMS = 
        org.bouncycastle.asn1.sec.SECNamedCurves.getByName("secp256k1");
    private static final org.bouncycastle.math.ec.ECCurve CURVE = PARAMS.getCurve();
    private static final ECPoint G = PARAMS.getG();
    private static final BigInteger ORDER = PARAMS.getN();

    public static SkycoinWallet fromMnemonic(String mnemonic) {
        byte[] seedBytes = mnemonic.getBytes(StandardCharsets.UTF_8);
        return new SkycoinWallet(seedBytes, mnemonic);
    }

    public static SkycoinWallet fromMnemonic(String mnemonic, String passphrase) {
        return fromMnemonic(mnemonic);
    }

    /**
     * Creates a wallet from a seed string and label
     *
     * @param seed The seed string
     * @param label A label for the wallet
     * @return A new SkycoinWallet instance
     */
    public static SkycoinWallet fromSeed(String seed, String label) {
        byte[] seedBytes = seed.getBytes(StandardCharsets.UTF_8);
        return new SkycoinWallet(seedBytes, label);
    }

    /**
     * Generates a random 12-word mnemonic phrase
     * @return A 12-word mnemonic phrase
     */
    public static String generateMnemonic() {
        return MnemonicUtils.generateMnemonic();
    }

    private SkycoinWallet(byte[] seedBytes, String mnemonic) {
        this.seed = mnemonic;
        
        byte[][] keys = generateDeterministicKeyPair(seedBytes);
        byte[] publicKeyBytes = keys[0];
        byte[] privateKeyBytes = keys[1];
        
        this.publicKey = Hex.toHexString(publicKeyBytes);
        this.privateKey = Hex.toHexString(privateKeyBytes);
        this.address = generateAddress(publicKeyBytes);
    }

    private static byte[][] generateDeterministicKeyPair(byte[] seedIn) {
        byte[] seed1 = secp256k1Hash(seedIn);
        byte[] seed2 = sha256(concat(seedIn, seed1));
        
        return generateKeyPair(seed2);
    }

    private static byte[] secp256k1Hash(byte[] hash) {
        byte[] hash1 = sha256(hash);
        
        byte[][] keys1 = generateKeyPair(hash1);
        byte[] seckey1 = keys1[1];
        
        byte[] hash2 = sha256(hash1);
        byte[][] keys2 = generateKeyPair(hash2);
        byte[] pubkey2 = keys2[0];
        
        byte[] ecdh = ecdh(pubkey2, seckey1);
        
        return sha256(concat(hash1, ecdh));
    }

    private static byte[] ecdh(byte[] pubkey, byte[] seckey) {
        ECPoint pub = CURVE.decodePoint(pubkey).normalize();
        BigInteger d = new BigInteger(1, seckey);
        ECPoint result = pub.multiply(d).normalize();
        return result.getEncoded(true);
    }

    private static byte[][] generateKeyPair(byte[] seed) {
        byte[] seckey = new byte[32];
        
        int attempts = 0;
        while (attempts < 100) {
            byte[] hash = sha256(seed);
            System.arraycopy(hash, 0, seckey, 0, 32);
            
            BigInteger d = new BigInteger(1, seckey);
            if (d.compareTo(BigInteger.ONE) >= 0 && d.compareTo(ORDER) < 0) {
                break;
            }
            
            seed = sha256(concat(new byte[32], hash));
            attempts++;
        }
        
        ECPoint Q = G.multiply(new BigInteger(1, seckey)).normalize();
        byte[] pubkey = Q.getEncoded(true);
        
        return new byte[][] { pubkey, seckey };
    }

    public static String generateAddress(byte[] publicKeyBytes) {
        // Go 标准做法: RIPEMD160(SHA256(SHA256(pubkey)))
        byte[] sha256_1 = sha256(publicKeyBytes);
        byte[] sha256_2 = sha256(sha256_1);
        
        RIPEMD160Digest ripeMd160 = new RIPEMD160Digest();
        ripeMd160.update(sha256_2, 0, sha256_2.length);
        byte[] ripeMd160Hash = new byte[20];
        ripeMd160.doFinal(ripeMd160Hash, 0);
        
        // Go format: Key(20) + Version(0x00) + Checksum(4)
        // Checksum = first 4 bytes of SHA256(Key + Version)
        byte version = 0x00;
        
        // Build data for checksum: Key + Version
        byte[] keyAndVersion = new byte[21];
        System.arraycopy(ripeMd160Hash, 0, keyAndVersion, 0, 20);
        keyAndVersion[20] = version;
        
        // Calculate checksum
        byte[] checksum = sha256(keyAndVersion);
        
        // Build final address: Key + Version + Checksum[0:4]
        byte[] addressBytes = new byte[25];
        System.arraycopy(ripeMd160Hash, 0, addressBytes, 0, 20);
        addressBytes[20] = version;
        System.arraycopy(checksum, 0, addressBytes, 21, 4);
        
        return Base58.encode(addressBytes);
    }

    /**
     * Generate address from private key
     * @param privateKeyHex The private key in hexadecimal format
     * @return The corresponding Skycoin address
     */
    public static String generateAddressFromPrivateKey(String privateKeyHex) {
        byte[] privateKeyBytes = hexToBytes(privateKeyHex);
        if (privateKeyBytes == null || privateKeyBytes.length != 32) {
            return null;
        }

        // Generate public key from private key: Q = d * G
        BigInteger d = new BigInteger(1, privateKeyBytes);
        ECPoint Q = G.multiply(d).normalize();
        byte[] publicKeyBytes = Q.getEncoded(true);

        // Generate address from public key
        return generateAddress(publicKeyBytes);
    }
    
    // Get 21 bytes (version + pubkey hash) from public key
    public static byte[] getAddressBytes21(byte[] publicKeyBytes) {
        byte[] sha256_1 = sha256(publicKeyBytes);
        byte[] sha256_2 = sha256(sha256_1);
        
        RIPEMD160Digest ripeMd160 = new RIPEMD160Digest();
        ripeMd160.update(sha256_2, 0, sha256_2.length);
        byte[] ripeMd160Hash = new byte[20];
        ripeMd160.doFinal(ripeMd160Hash, 0);
        
        // Build 21 bytes: pubkey hash (20) + version (0x00)
        byte[] addressBytes21 = new byte[21];
        System.arraycopy(ripeMd160Hash, 0, addressBytes21, 0, 20);
        addressBytes21[20] = 0x00;
        
        return addressBytes21;
    }
    
    // Get 21 bytes from address string (by decoding and taking first 21 bytes)
    public static byte[] getAddressBytes21FromAddress(String address) {
        byte[] fullBytes = Base58.decode(address);
        if (fullBytes.length >= 21) {
            byte[] addr21 = new byte[21];
            System.arraycopy(fullBytes, 0, addr21, 0, 21);
            return addr21;
        }
        return null;
    }

    private static byte[] sha256(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(input);
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 failed", e);
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
    
    public static byte[] hexToBytes(String hex) {
        if (hex == null || hex.length() % 2 != 0) return null;
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return result;
    }

    public String getAddress() {
        return address;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public String getSeed() {
        return seed;
    }
}
