package com.antonsma.springbootdemo.utils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class ECDSAUtils {
    // 生成 ECDSA 密钥对
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // 生成 ECDSA 密钥对
    public static KeyPair ECDSAgenerateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256k1");
        keyGen.initialize(ecSpec);
        return keyGen.generateKeyPair();
    }

    // 对消息进行签名
    public static String ECDSAsignMessage(String message, PrivateKey privateKey) throws Exception {
        Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");
        ecdsaSign.initSign(privateKey);
        ecdsaSign.update(message.getBytes());
        byte[] signatureBytes = ecdsaSign.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    // 验证签名
    public static boolean ECDSAverifySignature(String message, String signature, String publicKey) throws Exception {
        Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", "BC");
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        PublicKey public_Key = keyFactory.generatePublic(keySpec);
        ecdsaVerify.initVerify(public_Key);
        ecdsaVerify.update(message.getBytes());
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return ecdsaVerify.verify(signatureBytes);
    }
}