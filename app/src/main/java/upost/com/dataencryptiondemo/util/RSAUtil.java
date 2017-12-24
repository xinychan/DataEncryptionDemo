package upost.com.dataencryptiondemo.util;

import android.util.Base64;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * RSA加密解密工具类
 */

public class RSAUtil {

    /**
     * 产生密钥对
     *
     * @param keyLength 密钥长度，小于1024长度的密钥已经被证实是不安全的，通常设置为1024或者2048，建议2048
     * @return 密钥对对象
     */
    public static KeyPair generateRSAKeyPair(int keyLength) {
        KeyPair keyPair = null;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(keyLength);//设置密钥长度
            keyPair = keyPairGenerator.generateKeyPair();//产生密钥对
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return keyPair;
    }

    /**
     * 加密或解密数据的通用方法
     *
     * @param srcData 待处理的数据
     * @param key     公钥或者私钥
     * @param mode    指定是加密还是解密，值为Cipher.ENCRYPT_MODE或者Cipher.DECRYPT_MODE
     * @return 返回的加密或解密结果
     */
    private static byte[] processData(byte[] srcData, Key key, int mode) {
        //用来保存处理结果
        byte[] resultBytes = null;
        try {
            //构建Cipher对象，需要传入一个字符串，格式必须为"algorithm/mode/padding"或者"algorithm/"
            //意为"算法/加密模式/填充方式"
            Cipher cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding");
            //初始化Cipher，mode指定是加密还是解密，key为公钥或私钥
            cipher.init(mode, key);
            //处理数据
            resultBytes = cipher.doFinal(srcData);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return resultBytes;
    }

    /**
     * 使用公钥加密数据，结果用Base64转码
     *
     * @param srcData   待处理的数据
     * @param publicKey 公钥
     * @return 加密后数据
     */
    public static String encryptDataByPublicKey(byte[] srcData, PublicKey publicKey) {
        byte[] resultBytes = processData(srcData, publicKey, Cipher.ENCRYPT_MODE);
        return Base64.encodeToString(resultBytes, Base64.DEFAULT);
    }

    /**
     * 使用私钥解密，返回解码数据
     *
     * @param encryptedData 待处理的数据
     * @param privateKey    私钥
     * @return 解密数据
     */
    public static byte[] decryptDataByPrivate(String encryptedData, PrivateKey privateKey) {
        byte[] bytes = Base64.decode(encryptedData, Base64.DEFAULT);
        return processData(bytes, privateKey, Cipher.DECRYPT_MODE);
    }

    /**
     * 使用私钥进行解密，解密数据转换为字符串，使用utf-8编码格式
     *
     * @param encryptedData 待处理数据
     * @param privateKey    私钥
     * @return 解密数据
     */
    public static String decryptedToStrByPrivate(String encryptedData, PrivateKey privateKey) {
        return new String(decryptDataByPrivate(encryptedData, privateKey));
    }

    /**
     * 使用私钥解密，解密数据转换为字符串，并指定字符集
     *
     * @param encryptedData 待处理数据
     * @param privateKey    私钥
     * @param charset       指定字符集编码
     * @return 解密数据
     */
    public static String decryptedToStrByPrivate(String encryptedData, PrivateKey privateKey, String charset) {
        try {
            return new String(decryptDataByPrivate(encryptedData, privateKey), charset);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 使用私钥加密，结果用Base64转码
     *
     * @param srcData    待处理数据
     * @param privateKey 私钥
     * @return 加密后数据
     */
    public static String encryptDataByPrivateKey(byte[] srcData, PrivateKey privateKey) {
        byte[] resultBytes = processData(srcData, privateKey, Cipher.ENCRYPT_MODE);
        return Base64.encodeToString(resultBytes, Base64.DEFAULT);
    }

    /**
     * 使用公钥解密，返回解密数据
     *
     * @param encryptedData 待处理数据
     * @param publicKey     公钥
     * @return 解密数据
     */
    public static byte[] decryptDataByPublicKey(String encryptedData, PublicKey publicKey) {
        byte[] bytes = Base64.decode(encryptedData, Base64.DEFAULT);
        return processData(bytes, publicKey, Cipher.DECRYPT_MODE);
    }

    /**
     * 使用公钥解密，结果转换为字符串，使用默认字符集utf-8
     *
     * @param encryptedData 待处理数据
     * @param publicKey     公钥
     * @return 解密数据
     */
    public static String decryptedToStrByPublicKey(String encryptedData, PublicKey publicKey) {
        return new String(decryptDataByPublicKey(encryptedData, publicKey));
    }

    /**
     * 使用公钥解密，结果转换为字符串，使用指定字符集
     *
     * @param encryptedData 待处理数据
     * @param publicKey     公钥
     * @param charset       指定字符集编码
     * @return 解密数据
     */
    public static String decryptedToStrByPublicKey(String encryptedData, PublicKey publicKey, String charset) {
        try {
            return new String(decryptDataByPublicKey(encryptedData, publicKey), charset);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 将字符串形式的公钥转换为公钥对象
     *
     * @param publicKeyStr 公钥字符串
     * @return 公钥
     */
    public static PublicKey keyStrToPublicKey(String publicKeyStr) {
        PublicKey publicKey = null;
        byte[] keyBytes = Base64.decode(publicKeyStr, Base64.DEFAULT);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    /**
     * 将字符串形式的私钥，转换为私钥对象
     *
     * @param privateKeyStr 私钥字符串
     * @return 私钥
     */
    public static PrivateKey keyStrToPrivate(String privateKeyStr) {
        PrivateKey privateKey = null;
        byte[] keyBytes = Base64.decode(privateKeyStr, Base64.DEFAULT);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return privateKey;
    }
}
