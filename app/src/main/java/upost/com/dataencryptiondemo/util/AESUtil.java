package upost.com.dataencryptiondemo.util;

import android.util.Base64;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES加密解密工具类
 * 说明：
 * 1--ECB模式和其他模式不同，仅仅在于初始化Cipher对象时，是否需要提供初始化向量IV，
 * 这个字节数组是任意的，只要大小和数据块大小（也就是密钥大小）一致即可。
 * 2--获取Cipher实例时，传入的字符串并不是任意的，例如Cipher.getInstance("AES/ECB/PKCS5Padding"),
 * 首先，格式要固定，必须为"algorithm/mode/padding"或者"algorithm",意为"算法/加密模式/填充方式"。
 * 其次，需要Android支持该组合模式。如何知道Android是否支持呢，Cipher的Api文档给出了答案，请查看官方文档。
 * 3--因为CFB、OFB模式可以以小于数据块的单元进行加密，那么在指定假面模式时可以指定加密单元，
 * 如："AES/CFB8/PKCS5Padding",表示以8位为加密单元，不同的加密单元加密后的结果也是不一致的，
 * 如果不指定，默认以数据块为加密单元。
 */

public class AESUtil {

    public static String ECB_MODE = "AES/ECB/PKCS5Padding";//ECB加密模式
    public static String CBC_MODE = "AES/CBC/PKCS5Padding";//CCB加密模式

    /**
     * 产生一把AES密钥
     *
     * @param keySize 密钥大小，只能是128位（16字节）、192位（24字节）、256位（32字节）
     * @return 字节数组形式的AES密钥
     */
    public static byte[] generateAESKey(int keySize) {
        //保存AES密钥的字节数组
        byte[] keyBytes = null;
        try {
            //获取密钥生成器
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            //设置密钥长度，如果不调用该方法，默认生成256位的密钥
            keyGenerator.init(keySize);
            //获得密钥对象
            SecretKey secretKey = keyGenerator.generateKey();
            //转成字节数组
            keyBytes = secretKey.getEncoded();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return keyBytes;
    }


    /**
     * ECB模式解密
     *
     * @param data      data为待解密的数据
     * @param keyBytes  keyBytes为加密时所使用的密钥
     * @param transform transform为加密时所采取的加密模式和填充模式
     * @return 返回的解密数据
     */
    public static byte[] decryptDataEBC(String data, byte[] keyBytes, String transform) {
        byte[] clearData = null;
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        try {
            //根据格式获取Cipher实例，需与加密时一致
            Cipher cipher = Cipher.getInstance(transform);
            //初始化Cipher，注意这里变为解密模式
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            //先Base64解码
            byte[] temp = Base64.decode(data, Base64.DEFAULT);
            //解密数据
            clearData = cipher.doFinal(temp);
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
        return clearData;
    }

    /**
     * 其他需要IV解密的，以CBC为例
     *
     * @param data      data为待解密的数据
     * @param keyBytes  keyBytes为加密时所使用的密钥
     * @param ivBytes   ivBytes为初始化向量
     * @param transform transform为加密时所采取的加密模式和填充模式
     * @return 返回的解密数据
     */
    public static byte[] decryptDataCBC(String data, byte[] keyBytes, byte[] ivBytes, String transform) {
        byte[] clearData = null;
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        try {
            //根据格式获取Cipher实例，需与加密时一致
            Cipher cipher = Cipher.getInstance(transform);
            //初始化Cipher，注意这里变为解密模式
            IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            //先Base64解码
            byte[] temp = Base64.decode(data, Base64.DEFAULT);
            //解密数据
            clearData = cipher.doFinal(temp);
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
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return clearData;
    }

    /**
     * 初始化向量IV
     * CBC,CFB,OFB,CTR加密模式需要初始化向量IV
     *
     * @param blockSize 初始化向量的数据块大小
     * @return
     */
    public static byte[] generatorIvBytes(int blockSize) {
        Random random = new Random();
        byte[] ivParam = new byte[blockSize];
        for (int index = 0; index < blockSize; index++) {
            ivParam[index] = (byte) random.nextInt(256);
        }
        return ivParam;
    }

    /**
     * ECB模式不需要初始化向量IV（也称为偏移量）
     *
     * @param keyBytes  AES密钥的字节数组
     * @param clearText 待加密数据
     * @return 加密后密文
     */
    public static String encryptECB(byte[] keyBytes, String clearText) {
        String finalResult = null;//加密后密文
        //产生密钥
        //byte[] keyBytes = generateAESKey(256);
        //构建SecretKeySpec，初始化Cipher对象时需要该参数
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        try {
            //构建Cipher对象，需要传入一个字符串，格式必须为"algorithm/mode/padding"或者"algorithm/",意为"算法/加密模式/填充方式"
            Cipher cipher = Cipher.getInstance(ECB_MODE);
            //初始化Cipher对象
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            //加密数据
            byte[] resultBytes = cipher.doFinal(clearText.getBytes());
            //结果用Base64转码
            finalResult = Base64.encodeToString(resultBytes, Base64.DEFAULT);
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
        return finalResult;
    }

    /**
     * BC,CFB,OFB,CTR需要初始化向量IV,以CBC为例
     *
     * @param keyBytes  AES密钥的字节数组
     * @param ivBytes   初始化向量IV
     * @param clearText 待加密数据
     * @return 加密后密文
     */
    public static String encryptCBC(byte[] keyBytes, byte[] ivBytes, String clearText) {
        String finalResult = null;//加密后密文
        //产生密钥
        //byte[] keyBytes = generateAESKey(256);
        //构建SecretKeySpec，初始化Cipher对象时需要该参数
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        try {
            //构建Cipher对象，需要传入一个字符串，格式必须为"algorithm/mode/padding"或者"algorithm/",意为"算法/加密模式/填充方式"
            Cipher cipher = Cipher.getInstance(CBC_MODE);
            //初始化向量IV
            //byte[] ivBytes = generatorIvBytes(keyBytes.length);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            //加密数据
            byte[] resultBytes = cipher.doFinal(clearText.getBytes());
            //结果用Base64转码
            finalResult = Base64.encodeToString(resultBytes, Base64.DEFAULT);
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
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return finalResult;
    }
}
