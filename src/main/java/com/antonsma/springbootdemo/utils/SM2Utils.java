package com.antonsma.springbootdemo.utils;

import cn.hutool.core.util.HexUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.SM2;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Base64;

public class SM2Utils {
    public static KeyPair SM2generateKeyPair(){
        return SecureUtil.generateKeyPair("SM2");
    }

    public static String SM2encrypt(String text, String pri_key,String pub_key){
        SM2 sm2 = SmUtil.sm2(pri_key, pub_key);
        byte[] result_byte = sm2.encrypt(text,KeyType.PublicKey);
        return Base64.getEncoder().encodeToString(result_byte);
    }

    public static String SM2decrypt(String text, String pri_key,String pub_key){
        SM2 sm2 = SmUtil.sm2(pri_key, pub_key);
        byte[] byte_text = sm2.decrypt(text,KeyType.PrivateKey);
        return new String(byte_text);
    }
    public static String SM2signature(String text) {
        KeyPair keypair = SM2generateKeyPair();
        PrivateKey pri_key =  keypair.getPrivate();
        SM2 sm2 = new SM2(pri_key, null);
        String signature = sm2.signHex(HexUtil.encodeHexStr(text));
        String publicKeyString = Base64.getEncoder().encodeToString(keypair.getPublic().getEncoded());
        return "签名  " + signature + "验证用公钥  " + publicKeyString;
    }

    public static boolean SM2sign_check(String text, String pub_key,String sign){
        SM2 sm2 = new SM2(null, pub_key);
        return sm2.verifyHex(HexUtil.encodeHexStr(text), sign);
    }
}
