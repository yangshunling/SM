package com.anonymous.crypt.sm3;

import com.anonymous.utils.HexUtils;

/**
 * 国密SM3不可逆算法
 */
public class SM3Utils {

    /**
     * SM3->加密
     *
     * @param sourceBytes 原始数组
     * @param toLowerCase 是否小写输出
     * @return 64位十六进制字符串
     */
    public static String encrypt(byte[] sourceBytes, boolean toLowerCase) {
        byte[] digestBytes = encryptInner(sourceBytes);
        return new String(HexUtils.encodeHex(digestBytes, toLowerCase));
    }

    /**
     * SM3->加密实现
     *
     * @param sourceBytes 原始数组
     * @return 加密后的，32位数组
     */
    private static byte[] encryptInner(byte[] sourceBytes) {
        SM3Digest digest = new SM3Digest();
        digest.update(sourceBytes, 0, sourceBytes.length);
        byte[] result = new byte[32];
        digest.doFinal(result, 0);
        return result;
    }
}
