package com.yline.sm;

import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;

import com.anonymous.crypt.sm2.SM2Impl;
import com.anonymous.crypt.sm2.SM2Utils;
import com.anonymous.crypt.sm3.SM3Utils;
import com.anonymous.crypt.sm4.SM4Utils;


public class MainActivity extends AppCompatActivity {

    private String TAG = "sm";


    private Button mButton;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main_activity);

        mButton = findViewById(R.id.button);
        mButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Log.v(TAG, "--------------- SM2加密 ------------------");
                testSM2();
                Log.v(TAG, "--------------- SM3加密 ------------------");
                testSM3();
                Log.v(TAG, "--------------- SM4加密 ------------------");
                testSM4();
            }
        });
    }

    /**
     * 国密SM2
     */
    public void testSM2() {
        //获取密钥对
        SM2Impl.SM2KeyPair keyPair = SM2Utils.createKeyPair();
        Log.v("TAG", keyPair + "");
        //获取私钥
        String privateKey = SM2Utils.getPrivateKey(keyPair);
        Log.v(TAG, "生成私钥：" + privateKey);
        //获取公钥
        String publicKey = SM2Utils.getPublicKey(keyPair);
        Log.v(TAG, "生成公钥：" + publicKey);

        //原始数据
        String source = "123456789";
        //用户ID（加签、验签）
        String userId = "anonymous";

        //测试，加密、解密、签名、验签过程
        try {
            byte[] cipherBytes = SM2Utils.encrypt(Base64.decode(publicKey, Base64.NO_WRAP), source.getBytes());
            Log.v(TAG, "加密：" + Base64.encodeToString(cipherBytes, Base64.NO_WRAP));

            byte[] plainBytes = SM2Utils.decrypt(Base64.decode(privateKey, Base64.NO_WRAP), cipherBytes);
            String plainText = null == plainBytes ? null : new String(plainBytes);
            Log.v(TAG, "解密：" + plainText);

            byte[] signBytes = SM2Utils.sign(userId.getBytes(), Base64.decode(privateKey, Base64.NO_WRAP), source.getBytes());
            Log.v(TAG, "签名：" + Base64.encodeToString(signBytes, Base64.NO_WRAP));

            boolean signResult = SM2Utils.verifySign(userId.getBytes(), Base64.decode(publicKey, Base64.NO_WRAP), source.getBytes(), signBytes);
            Log.v(TAG, "验签：" + signResult);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 国密SM3
     */
    public void testSM3() {
        Log.v(TAG, "加密大写：" + SM3Utils.encrypt("123456789".getBytes(), false));

        Log.v(TAG, "加密小写：" + SM3Utils.encrypt("123456789".getBytes(), true));
    }

    /**
     * 国密SM4
     */
    public void testSM4() {
        String sourceText = "anonymous123";

        byte[] keyBytes = SM4Utils.createSM4Key();
        Log.v(TAG, "密钥生成：" + Base64.encodeToString(keyBytes, Base64.NO_WRAP));
        String cipherText = SM4Utils.encryptECB(sourceText, keyBytes);
        Log.v(TAG, "ECB模式-加密：" + cipherText);

        String plainText = SM4Utils.decryptECB(cipherText, keyBytes);
        Log.v(TAG, "ECB模式-解密：" + plainText);

        cipherText = SM4Utils.encryptCBC(sourceText, keyBytes);
        Log.v(TAG, "CBC模式-加密：" + cipherText);

        plainText = SM4Utils.decryptCBC(cipherText, keyBytes);
        Log.v(TAG, "CBC模式-解密：" + plainText);
    }
}
