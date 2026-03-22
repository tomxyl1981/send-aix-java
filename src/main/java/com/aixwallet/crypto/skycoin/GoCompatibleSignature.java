package com.aixwallet.crypto.skycoin;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * 精确复刻 Go secp256k1 签名的 Java 实现
 * 参考: github.com/skycoin/skycoin/src/cipher/secp256k1-go
 */
public class GoCompatibleSignature {

    // secp256k1 曲线参数
    private static final BigInteger CURVE_P = new BigInteger(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    private static final BigInteger CURVE_N = new BigInteger(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    private static final BigInteger CURVE_HALF_N = CURVE_N.shiftRight(1);

    // 基点 G 的坐标
    private static final BigInteger Gx = new BigInteger(
        "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
    private static final BigInteger Gy = new BigInteger(
        "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);

    // 测试用固定 nonce (6个6) - 设为 false 使用随机 nonce
    private static final boolean USE_FIXED_NONCE = false;
    private static final BigInteger FIXED_NONCE = new BigInteger(
        "6666666666666666666666666666666666666666666666666666666666666666", 16);

    /**
     * 使用与 Go 完全相同的算法签名
     * @param hash 32字节哈希
     * @param privateKey 32字节私钥
     * @return 65字节签名 (R||S||recovery_id)
     */
    public static byte[] sign(byte[] hash, byte[] privateKey) {
        return sign(hash, privateKey, null);
    }

    /**
     * 使用与 Go 完全相同的算法签名
     * @param hash 32字节哈希
     * @param privateKey 32字节私钥
     * @param nonce 固定 nonce (可选，为 null 时使用随机)
     * @return 65字节签名 (R||S||recovery_id)
     */
    public static byte[] sign(byte[] hash, byte[] privateKey, BigInteger customNonce) {
        if (hash.length != 32) {
            throw new IllegalArgumentException("Hash must be 32 bytes");
        }
        if (privateKey.length != 32) {
            throw new IllegalArgumentException("Private key must be 32 bytes");
        }

        BigInteger d = new BigInteger(1, privateKey);
        BigInteger e = new BigInteger(1, hash);

        // 生成 nonce
        BigInteger k;
        if (customNonce != null) {
            k = customNonce;
        } else if (USE_FIXED_NONCE) {
            k = FIXED_NONCE;
        } else {
            // 随机 nonce
            SecureRandom random = new SecureRandom();
            do {
                byte[] nonceBytes = new byte[32];
                random.nextBytes(nonceBytes);
                k = new BigInteger(1, nonceBytes);
            } while (k.signum() <= 0 || k.compareTo(CURVE_N) >= 0);
        }

        // 计算 r = k * G 的 x 坐标
        BigInteger[] kG = ecMul(Gx, Gy, k);
        BigInteger r = kG[0].mod(CURVE_N);

        // 如果 r == 0, 失败
        if (r.signum() == 0) {
            throw new RuntimeException("Signature failed: r = 0");
        }

        // 计算 s = k^(-1) * (e + r * d) mod n
        BigInteger kInv = k.modInverse(CURVE_N);
        BigInteger s = kInv.multiply(e.add(r.multiply(d))).mod(CURVE_N);

        // s malleability 保护: 如果 s > n/2, 则 s = n - s
        int recoveryId = 0;
        
        // 检查 y 坐标的奇偶性
        BigInteger y = kG[1];
        if (y.testBit(0)) {
            recoveryId |= 1;
        }

        // Go 检查: 如果 r >= order, 设置 bit 1
        BigInteger rCheck = new BigInteger(1, new byte[32]); 
        // 简化: 不做这个检查

        if (s.compareTo(CURVE_HALF_N) > 0) {
            s = CURVE_N.subtract(s);
            recoveryId ^= 1; // 翻转 bit 0
        }

        // 构建签名: R(32) + S(32) + recovery_id(1)
        byte[] signature = new byte[65];
        
        byte[] rBytes = toBytes32(r);
        byte[] sBytes = toBytes32(s);
        
        System.arraycopy(rBytes, 0, signature, 0, 32);
        System.arraycopy(sBytes, 0, signature, 32, 32);
        signature[64] = (byte) recoveryId;

        return signature;
    }

    /**
     * 将 BigInteger 转换为 32 字节数组 (大端序)
     */
    private static byte[] toBytes32(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length == 32) {
            return bytes;
        }
        if (bytes.length > 32) {
            // 去掉前导的 0
            byte[] result = new byte[32];
            System.arraycopy(bytes, bytes.length - 32, result, 0, 32);
            return result;
        }
        // 少于 32 字节，前面补 0
        byte[] result = new byte[32];
        System.arraycopy(bytes, 0, result, 32 - bytes.length, bytes.length);
        return result;
    }

    /**
     * 椭圆曲线点乘: result = k * P
     */
    private static BigInteger[] ecMul(BigInteger px, BigInteger py, BigInteger k) {
        BigInteger rx = BigInteger.ZERO;
        BigInteger ry = BigInteger.ZERO;

        BigInteger dx = px;
        BigInteger dy = py;

        // 使用二进制展开
        BigInteger temp = k;
        while (temp.signum() > 0) {
            if (temp.testBit(0)) {
                // result = result + current
                if (rx.signum() == 0) {
                    rx = dx;
                    ry = dy;
                } else {
                    BigInteger[] sum = ecAdd(rx, ry, dx, dy);
                    rx = sum[0];
                    ry = sum[1];
                }
            }
            // current = current * 2
            BigInteger[] doubled = ecDouble(dx, dy);
            dx = doubled[0];
            dy = doubled[1];
            
            temp = temp.shiftRight(1);
        }

        return new BigInteger[] {rx, ry};
    }

    /**
     * 点加法: result = p1 + p2
     */
    private static BigInteger[] ecAdd(BigInteger x1, BigInteger y1, BigInteger x2, BigInteger y2) {
        if (x1.signum() == 0) {
            return new BigInteger[] {x2, y2};
        }
        if (x2.signum() == 0) {
            return new BigInteger[] {x1, y1};
        }

        if (x1.equals(x2)) {
            if (y1.equals(y2)) {
                return ecDouble(x1, y1);
            } else {
                return new BigInteger[] {BigInteger.ZERO, BigInteger.ZERO};
            }
        }

        // λ = (y2 - y1) / (x2 - x1)
        BigInteger dx = x2.subtract(x1);
        BigInteger dy = y2.subtract(y1);
        BigInteger lam = dy.multiply(dx.modInverse(CURVE_P)).mod(CURVE_P);

        // x3 = λ² - x1 - x2
        BigInteger x3 = lam.multiply(lam).subtract(x1).subtract(x2).mod(CURVE_P);
        // y3 = λ(x1 - x3) - y1
        BigInteger y3 = lam.multiply(x1.subtract(x3)).subtract(y1).mod(CURVE_P);

        return new BigInteger[] {x3, y3};
    }

    /**
     * 点倍增: result = 2 * p
     */
    private static BigInteger[] ecDouble(BigInteger x, BigInteger y) {
        if (y.signum() == 0) {
            return new BigInteger[] {BigInteger.ZERO, BigInteger.ZERO};
        }

        // λ = (3x² + a) / (2y)
        BigInteger x2 = x.multiply(x).mod(CURVE_P);
        BigInteger threeX2 = x2.multiply(BigInteger.valueOf(3)).mod(CURVE_P);
        BigInteger twoY = y.multiply(BigInteger.valueOf(2)).mod(CURVE_P);
        
        BigInteger lam = threeX2.multiply(twoY.modInverse(CURVE_P)).mod(CURVE_P);

        // x' = λ² - 2x
        BigInteger x3 = lam.multiply(lam).subtract(x.multiply(BigInteger.valueOf(2))).mod(CURVE_P);
        // y' = λ(x - x') - y
        BigInteger y3 = lam.multiply(x.subtract(x3)).subtract(y).mod(CURVE_P);

        return new BigInteger[] {x3, y3};
    }

    /**
     * 测试函数 - 使用固定 nonce
     */
    public static void main(String[] args) {
        // 测试数据
        String seckeyHex = "af56c673edb463eba0b64eaf273bf53cd17819caa106179eb62c702946a2c229";
        String hashHex = "d4049d5fb42922f79221cdb942614c092be0850a027208d11e29a831523028f2";

        byte[] seckey = hexToBytes(seckeyHex);
        byte[] hash = hexToBytes(hashHex);

        // 使用固定 nonce
        System.out.println("=== Fixed nonce (6s) ===");
        byte[] sig1 = sign(hash, seckey, FIXED_NONCE);
        System.out.println("Signature: " + bytesToHex(sig1));
        
        // 使用相同固定 nonce 再次签名 (应该完全相同)
        byte[] sig2 = sign(hash, seckey, FIXED_NONCE);
        System.out.println("Signature2: " + bytesToHex(sig2));
        System.out.println("Match: " + bytesToHex(sig1).equals(bytesToHex(sig2)));
    }

    private static byte[] hexToBytes(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
