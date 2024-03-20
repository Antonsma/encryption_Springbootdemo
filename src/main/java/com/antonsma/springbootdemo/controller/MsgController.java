package com.antonsma.springbootdemo.controller;
import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Objects;
import static com.antonsma.springbootdemo.utils.AESUtils.encryptAES;
import static com.antonsma.springbootdemo.utils.AESUtils.decryptAES;
import static com.antonsma.springbootdemo.utils.SM2Utils.SM2generateKeyPair;
import static com.antonsma.springbootdemo.utils.SM2Utils.SM2encrypt;
import static com.antonsma.springbootdemo.utils.SM2Utils.SM2decrypt;
import static com.antonsma.springbootdemo.utils.SM2Utils.SM2signature;
import static com.antonsma.springbootdemo.utils.SM2Utils.SM2sign_check;
import static com.antonsma.springbootdemo.utils.SM3Utils.calculateSM3Hash;
import static com.antonsma.springbootdemo.utils.SM4Utils.encryptSM4;
import static com.antonsma.springbootdemo.utils.SM4Utils.decryptSM4;
import static com.antonsma.springbootdemo.utils.ECDSAUtils.ECDSAgenerateKeyPair;
import static com.antonsma.springbootdemo.utils.ECDSAUtils.ECDSAsignMessage;
import static com.antonsma.springbootdemo.utils.ECDSAUtils.ECDSAverifySignature;
import static com.antonsma.springbootdemo.utils.SHA256Utils.calculateSHA256Hash;
@RestController
public class MsgController {

    @PostMapping("/api")
    public ResponseEntity<String> processMessage(@RequestBody MessageData message){
        String action = message.getAction();
        String algorithm = message.getAlgorithm();
        String text = message.getText();
        String pri_key = message.getPri_key();
        String pub_key = message.getPub_key();
        String key = message.getKey();
        String sign = message.getSign();
        if(key != null)
        {
            if(Objects.equals(algorithm, "AES"))
            {
                if(Objects.equals(action,"encrypt"))
                {
                    try {
                        String encrypted_text = encryptAES(text, key);
                        message.setResult(encrypted_text);
                        String responseStatus = "success";
                        String responseText = message.getResult();
                        String responseJson = "{\"status\": \"" + responseStatus + "\", \"text\": \"" + responseText + "\"}";
                        return ResponseEntity.status(HttpStatus.OK).body(responseJson);
                    }
                    catch (Exception e)
                    {
                        e.printStackTrace();
                        message.setResult("加密出错");
                        String responseStatus = "fail";
                        String responseText = message.getResult();
                        String responseJson = "{\"status\": \"" + responseStatus + "\", \"text\": \"" + responseText + "\"}";
                        return ResponseEntity.status(HttpStatus.OK).body(responseJson);
                    }
                }
                else if (Objects.equals(action,"decrypt"))
                {
                    try {
                        String decrypted_text = decryptAES(text, key);
                        message.setResult(decrypted_text);
                        String responseStatus = "success";
                        String responseText = message.getResult();
                        String responseJson = "{\"status\": \"" + responseStatus + "\", \"text\": \"" + responseText + "\"}";
                        return ResponseEntity.status(HttpStatus.OK).body(responseJson);
                    }
                    catch (Exception e)
                    {
                        e.printStackTrace();
                        message.setResult("解密出错");
                        String responseStatus = "fail";
                        String responseText = message.getResult();
                        String responseJson = "{\"status\": \"" + responseStatus + "\", \"text\": \"" + responseText + "\"}";
                        return ResponseEntity.status(HttpStatus.OK).body(responseJson);
                    }
                }
            }
            else if (Objects.equals(algorithm,"SM4"))
            {
                if (Objects.equals(action,"encrypt"))
                {
                    try {
                        String encrypted_text = encryptSM4(text,key);
                        message.setResult(encrypted_text);
                        String responseStatus = "success";
                        String responseText = message.getResult();
                        String responseJson = "{\"status\": \"" + responseStatus + "\", \"text\": \"" + responseText + "\"}";
                        return ResponseEntity.status(HttpStatus.OK).body(responseJson);
                    }
                    catch (Exception e)
                    {
                        e.printStackTrace();
                        message.setResult("加密出错");
                        String responseStatus = "fail";
                        String responseText = message.getResult();
                        String responseJson = "{\"status\": \"" + responseStatus + "\", \"text\": \"" + responseText + "\"}";
                        return ResponseEntity.status(HttpStatus.OK).body(responseJson);
                    }
                }
                else if (Objects.equals(action,"decrypt"))
                {
                    try{
                        String decrypted_text = decryptSM4(text,key);
                        message.setResult(decrypted_text);
                        System.out.print(message.getResult());
                        String responseStatus = "success";
                        String responseText = message.getResult();
                        String responseJson = "{\"status\": \"" + responseStatus + "\", \"text\": \"" + responseText + "\"}";
                        return ResponseEntity.status(HttpStatus.OK).body(responseJson);
                    }
                    catch (Exception e)
                    {
                        System.out.print(message.getText());
                        e.printStackTrace();
                        message.setResult("解密出错");
                        String responseStatus = "fail";
                        String responseText = message.getResult();
                        String responseJson = "{\"status\": \"" + responseStatus + "\", \"text\": \"" + responseText + "\"}";
                        return ResponseEntity.status(HttpStatus.OK).body(responseJson);
                    }
                }
            }
        }
        else if (Objects.equals(algorithm,"ECDSA"))
        {
            if(Objects.equals(action,"encrypt"))
            {
                try{
                    KeyPair keypair = ECDSAgenerateKeyPair();
                    PrivateKey private_key = keypair.getPrivate();
                    PublicKey public_key = keypair.getPublic();
                    byte[] publicKeyBytes = public_key.getEncoded();
                    String publicKeyString = Base64.getEncoder().encodeToString(publicKeyBytes);
                    try {
                        String signature = ECDSAsignMessage(text,private_key);
                        String result = "签名  " + signature + "验证用公钥  " + publicKeyString;
                        message.setResult(result);
                        String responseStatus = "success";
                        String responseText = message.getResult();
                        String responseJson = "{\"status\": \"" + responseStatus + "\", \"text\": \"" + responseText + "\"}";
                        return ResponseEntity.status(HttpStatus.OK).body(responseJson);
                    }
                    catch (Exception e)
                    {
                        e.printStackTrace();
                        message.setResult("签名出错");
                        String responseStatus = "fail";
                        String responseText = message.getResult();
                        String responseJson = "{\"status\": \"" + responseStatus + "\", \"text\": \"" + responseText + "\"}";
                        return ResponseEntity.status(HttpStatus.OK).body(responseJson);
                    }
                }
                catch (Exception e){
                    e.printStackTrace();
                    message.setResult("密钥对生成出错");
                    String responseStatus = "fail";
                    String responseText = message.getResult();
                    String responseJson = "{\"status\": \"" + responseStatus + "\", \"text\": \"" + responseText + "\"}";
                    return ResponseEntity.status(HttpStatus.OK).body(responseJson);
                }
            } else if (Objects.equals(action,"decrypt"))
            {
                try {
                        if(ECDSAverifySignature(text,sign,pub_key))
                        {
                            message.setResult("验证成功");
                        }
                        else {
                            message.setResult("验证失败");
                        }
                    String responseStatus = "success";
                    String responseText = message.getResult();
                    String responseJson = "{\"status\": \"" + responseStatus + "\", \"text\": \"" + responseText + "\"}";
                    return ResponseEntity.status(HttpStatus.OK).body(responseJson);
                }
                catch (Exception e)
                {
                    e.printStackTrace();
                    message.setResult("签名验证过程出错");
                    String responseStatus = "fail";
                    String responseText = message.getResult();
                    String responseJson = "{\"status\": \"" + responseStatus + "\", \"text\": \"" + responseText + "\"}";
                    return ResponseEntity.status(HttpStatus.OK).body(responseJson);
                }
            }
        }
        else if (Objects.equals(algorithm,"SM2"))
        {
            if(pri_key.isEmpty() || pub_key.isEmpty())
            {
                KeyPair keypair = SM2generateKeyPair();
                if (keypair != null) {
                    PublicKey public_key = keypair.getPublic();
                    PrivateKey private_key = keypair.getPrivate();
                    byte[] publicKeyBytes = public_key.getEncoded();
                    String publicKeyString = Base64.getEncoder().encodeToString(publicKeyBytes);
                    byte[] privateKeyBytes = private_key.getEncoded();
                    String privateKeyString = Base64.getEncoder().encodeToString(privateKeyBytes);
                    String result = "公钥:" + publicKeyString +"私钥:" +privateKeyString;
                    message.setResult(result);
                    String responseStatus = "success";
                    String responseText = "密钥为"+message.getResult();
                    String responseJson = "{\"status\": \"" + responseStatus + "\", \"text\": \"" + responseText + "\"}";
                    return ResponseEntity.status(HttpStatus.OK).body(responseJson);
                } else{
                    message.setResult("公私钥生成失败");
                    String responseStatus = "fail";
                    String responseText = message.getResult();
                    String responseJson = "{\"status\": \"" + responseStatus + "\", \"text\": \"" + responseText + "\"}";
                    return ResponseEntity.status(HttpStatus.OK).body(responseJson);
                }
            }
            else if(Objects.equals(action,"encrypt"))
            {
                String resultstring = SM2encrypt(text,pri_key,pub_key);
                message.setResult(resultstring);
                String responseStatus = "success";
                String responseText = message.getResult();
                String responseJson = "{\"status\": \"" + responseStatus + "\", \"text\": \"" + responseText + "\"}";
                return ResponseEntity.status(HttpStatus.OK).body(responseJson);
            }
            else if (Objects.equals(action,"decrypt"))
            {
                String result = SM2decrypt(text,pri_key,pub_key);
                message.setResult(result);
                String responseStatus = "success";
                String responseText = message.getResult();
                String responseJson = "{\"status\": \"" + responseStatus + "\", \"text\": \"" + responseText + "\"}";
                return ResponseEntity.status(HttpStatus.OK).body(responseJson);
            }
        }
        else if (Objects.equals(algorithm,"SM2_sign"))
        {
            if (Objects.equals(action,"encrypt")) {
                String result = SM2signature(text);
                message.setResult(result);
                String responseStatus = "success";
                String responseText = message.getResult();
                String responseJson = "{\"status\": \"" + responseStatus + "\", \"text\": \"" + responseText + "\"}";
                return ResponseEntity.status(HttpStatus.OK).body(responseJson);
            }
            else if (Objects.equals(action,"decrypt")){
                if(SM2sign_check(text,pub_key,sign)){
                    message.setResult("验证成功");
                }
                else {
                    message.setResult("验证失败");
                }
                String responseStatus = "success";
                String responseText = message.getResult();
                String responseJson = "{\"status\": \"" + responseStatus + "\", \"text\": \"" + responseText + "\"}";
                return ResponseEntity.status(HttpStatus.OK).body(responseJson);
            }
        }
        else
        {
            if(Objects.equals(algorithm,"SM3"))
            {
                message.setResult(calculateSM3Hash(text));
                String responseStatus = "success";
                String responseText = message.getResult();
                String responseJson = "{\"status\": \"" + responseStatus + "\", \"text\": \"" + responseText + "\"}";
                return ResponseEntity.status(HttpStatus.OK).body(responseJson);
            }
            else if(Objects.equals(algorithm,"SHA256"))
            {
                message.setResult(calculateSHA256Hash(text));
                String responseStatus = "success";
                String responseText = message.getResult();
                String responseJson = "{\"status\": \"" + responseStatus + "\", \"text\": \"" + responseText + "\"}";
                return ResponseEntity.status(HttpStatus.OK).body(responseJson);
            }
        }

//在此处补全加密操作
        if(message.getResult() != null){
            String responseStatus = "success";
            String responseText = message.getResult();
            String responseJson = "{\"status\": \"" + responseStatus + "\", \"text\": \"" + responseText + "\"}";
            return ResponseEntity.status(HttpStatus.OK).body(responseJson);
        }
        else {
            message.setResult("消息处理过程出错");
            String responseStatus = "fail";
            String responseText = message.getResult();
            String responseJson = "{\"status\": \"" + responseStatus + "\", \"text\": \"" + responseText + "\"}";
            return ResponseEntity.status(HttpStatus.OK).body(responseJson);
        }
    }
    @Setter
    @Getter
    public static class MessageData {
        private String action;
        private String algorithm;
        private String text;
        private String pub_key;
        private String pri_key;
        private String key;
        private String sign;
        private String result;
    }
}

