package upost.com.dataencryptiondemo;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.text.TextUtils;
import android.view.View;
import android.widget.EditText;

import java.security.PublicKey;

import upost.com.dataencryptiondemo.util.AESUtil;
import upost.com.dataencryptiondemo.util.LogUtil;
import upost.com.dataencryptiondemo.util.MD5Util;
import upost.com.dataencryptiondemo.util.RSAUtil;
import upost.com.dataencryptiondemo.util.SHA256Util;
import upost.com.dataencryptiondemo.util.SHAUtil;
import upost.com.dataencryptiondemo.util.ToastUtil;

/**
 * 数据加密和解密Demo
 * 1--MD5与SHA1都是Hash算法,加密过程不可逆不能进行解密。
 * 2--RSA是一种非对称加密算法，加密和解密使用不同的密钥（公钥/私钥）。
 * RSA对要加密的数据的长度有限制，待加密的字节数不能超过密钥的长度值除以 8 再减去 11（即：KeySize / 8 - 11）。
 * 一般密钥长度为1024，若以1024为例，则待加密的字节数最大值为117。
 * 3--AES是一种对称加密算法，即加密解密使用同一把秘钥。
 */
public class MainActivity extends AppCompatActivity {

    private MainActivity activity;
    private EditText et_main;
    private String content;//输入的内容

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        activity = this;
        et_main = (EditText) findViewById(R.id.et_main);
    }

    /**
     * MD5加密
     */
    public void encryption_MD5(View view) {
        if (contentIsNotEmpty()) {
            String encryptContent = MD5Util.getMD5String(content);
            ToastUtil.showToast(activity, encryptContent);
            LogUtil.showLog("encryption_MD5");
            LogUtil.showLog("加密前content == " + content);
            LogUtil.showLog("加密后content == " + encryptContent);
        }
    }

    /**
     * SHA1加密
     */
    public void encryption_SHA1(View view) {
        if (contentIsNotEmpty()) {
            String encryptContent = SHAUtil.shaEncrypt(content);
            ToastUtil.showToast(activity, encryptContent);
            LogUtil.showLog("encryption_SHA1");
            LogUtil.showLog("加密前content == " + content);
            LogUtil.showLog("加密后content == " + encryptContent);
        }
    }

    /**
     * SHA256加密
     */
    public void encryption_SHA256(View view) {
        if (contentIsNotEmpty()) {
            String encryptContent = SHA256Util.shaEncrypt(content);
            ToastUtil.showToast(activity, encryptContent);
            LogUtil.showLog("encryption_SHA256");
            LogUtil.showLog("加密前content == " + content);
            LogUtil.showLog("加密后content == " + encryptContent);
        }
    }

    /**
     * RSA加密
     */
    public void encryption_RSA(View view) {
        if (contentIsNotEmpty()) {
            PublicKey publicKey = RSAUtil.keyStrToPublicKey(AppConstants.PUBLIC_KEY_STR);//生成公钥
            String encryptContent = RSAUtil.encryptDataByPublicKey(content.getBytes(), publicKey);//用公钥加密
            ToastUtil.showToast(activity, encryptContent);
            LogUtil.showLog("encryption_RSA");
            LogUtil.showLog("加密前content == " + content);
            LogUtil.showLog("加密后content == " + encryptContent);
        }
    }

    /**
     * AES加密_EBC
     */
    public void encryption_AES_EBC(View view) {
        if (contentIsNotEmpty()) {
            //加密步骤
            byte[] keyBytes = AESUtil.generateAESKey(256);//生成一把AES密钥
            String encryptContent = AESUtil.encryptECB(keyBytes, content);
            LogUtil.showLog("encryption_AES_EBC");
            LogUtil.showLog("加密前content == " + content);
            LogUtil.showLog("加密后content == " + encryptContent);
            //解密步骤
            //"AES/ECB/PKCS5Padding"--加密时所采取的加密模式和填充模式，解密要保证和加密时的一致
            byte[] decryptData = AESUtil.decryptDataEBC(encryptContent, keyBytes, AESUtil.ECB_MODE);
            LogUtil.showLog("encryption_AES_EBC");
            LogUtil.showLog("解密前content == " + encryptContent);
            LogUtil.showLog("解密后content == " + new String(decryptData));//字节数组转String，用String(byte[] bytes)
            ToastUtil.showToast(activity, encryptContent);
        }
    }

    /**
     * AES加密_CBC
     */
    public void encryption_AES_CBC(View view) {
        if (contentIsNotEmpty()) {
            //加密步骤
            //生成一把AES密钥
            //Android下如果用CBC模式（需要初始化向量IV）加密，则密码只能是16字节的，若为32字节则会超出报如下异常
            //java.security.InvalidAlgorithmParameterException: expected IV length of 16 but was 32.
            //无效的算法参数异常：需要初始化向量IV期望的阈值是16但是给的是32
            //byte[] keyBytes = AESUtil.generateAESKey(256);//这里用CBC模式加密，不能用256位密钥
            byte[] keyBytes = AESUtil.generateAESKey(128);
            byte[] ivBytes = AESUtil.generatorIvBytes(keyBytes.length);//获取CBC模式加密时初始化向量IV
            String encryptContent = AESUtil.encryptCBC(keyBytes, ivBytes, content);
            LogUtil.showLog("encryption_AES_CBC");
            LogUtil.showLog("加密前content == " + content);
            LogUtil.showLog("加密后content == " + encryptContent);
            //解密步骤
            //"AES/CBC/PKCS5Padding"--加密时所采取的加密模式和填充模式，解密要保证和加密时的一致
            byte[] decryptData = AESUtil.decryptDataCBC(encryptContent, keyBytes, ivBytes, AESUtil.CBC_MODE);
            LogUtil.showLog("encryption_AES_CBC");
            LogUtil.showLog("解密前content == " + encryptContent);
            LogUtil.showLog("解密后content == " + new String(decryptData));//字节数组转String，用String(byte[] bytes)
            ToastUtil.showToast(activity, encryptContent);
        }
    }

    /**
     * 判断输入内容
     */
    private boolean contentIsNotEmpty() {
        content = et_main.getText().toString().trim();
        if (TextUtils.isEmpty(content)) {
            ToastUtil.showToast(activity, "请输入内容");
            return false;
        } else {
            return true;
        }
    }

}
