package com.anonymous.crypt.sm2;

import android.util.Base64;

import java.io.IOException;
import java.math.BigInteger;

/**
 * 国密SM2对称性算法
 */
public class SM2Utils {
    /**
     * SM3->生成秘钥对
     *
     * @return 密钥对
     */
    public static SM2Impl.SM2KeyPair createKeyPair() {
        return new SM2Impl().genKeyPair();
    }

    /**
     * SM3->获取私钥
     *
     * @param keyPair 密钥对
     * @return 被Base64转码加密过的私钥
     */
    public static String getPrivateKey(SM2Impl.SM2KeyPair keyPair) {
        if (null == keyPair) {
            return null;
        }
        BigInteger privateKeyInteger = keyPair.getPrivateKey();
        byte[] privateKeyBytes = SM2.bigInteger2Bytes(privateKeyInteger);
        return (null == privateKeyBytes ? null : Base64.encodeToString(privateKeyBytes, Base64.NO_WRAP));
    }

    /**
     * SM3->获取公钥
     *
     * @param keyPair 密钥对
     * @return 被Base64转码加密过的公钥
     */
    public static String getPublicKey(SM2Impl.SM2KeyPair keyPair) {
        if (null == keyPair) {
            return null;
        }
        byte[] publicKeyBytes = keyPair.getPublicKey().getEncoded();
        return (null == publicKeyBytes ? null : Base64.encodeToString(publicKeyBytes, Base64.NO_WRAP));
    }

    /**
     * SM3->加密
     *
     * @param publicKey
     * @param data
     * @return
     * @throws IOException
     */
    public static byte[] encrypt(byte[] publicKey, byte[] data) throws IOException {
        return new SM2Impl().encrypt(data, publicKey);
    }

    /**
     * SM3->解密
     *
     * @param privateKey
     * @param encryptedData
     * @return
     * @throws IOException
     */
    public static byte[] decrypt(byte[] privateKey, byte[] encryptedData) throws IOException {
        return new SM2Impl().decrypt(encryptedData, privateKey);
    }

    /**
     * SM3->加签
     *
     * @param userId
     * @param privateKey
     * @param sourceData
     * @return
     * @throws IOException
     */
    public static byte[] sign(byte[] userId, byte[] privateKey, byte[] sourceData) throws IOException {
        return new SM2Impl().sign(userId, privateKey, sourceData);
    }

    /**
     * SM3->验签
     *
     * @param userId
     * @param publicKey
     * @param sourceData
     * @param signData
     * @return
     * @throws IOException
     */
    public static boolean verifySign(byte[] userId, byte[] publicKey, byte[] sourceData, byte[] signData) throws IOException {
        return new SM2Impl().verifySign(userId, publicKey, sourceData, signData);
    }
}
