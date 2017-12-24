package upost.com.dataencryptiondemo.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * SHA加密工具类
 */

public class SHA256Util {

    /**
     * SHA加密
     *
     * @param plainStr 明文
     * @return 加密后密文
     */
    public static String shaEncrypt(String plainStr) {
        MessageDigest md = null;
        String cipherStr = null;
        byte[] plaintextBytes = plainStr.getBytes();
        try {
            md = MessageDigest.getInstance("SHA-256");//可用SHA-1、SHA-256、SHA-512、SHA-384等参数替代
            md.update(plaintextBytes);
            cipherStr = bytes2Hex(md.digest()); // to HexString
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
        return cipherStr;
    }

    /**
     * byte数组转换为16进制字符串
     *
     * @param plaintextBytes 数据源
     * @return 16进制字符串
     */
    private static String bytes2Hex(byte[] plaintextBytes) {
        String des = "";
        String tmp = null;
        for (int i = 0; i < plaintextBytes.length; i++) {
            tmp = (Integer.toHexString(plaintextBytes[i] & 0xFF));
            if (tmp.length() == 1) {
                des += "0";
            }
            des += tmp;
        }
        return des;
    }
}
