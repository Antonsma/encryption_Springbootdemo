package com.antonsma.springbootdemo.utils;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.nio.charset.StandardCharsets;
import java.util.Base64;


public class SM4Utils {
    private static final String FIXED_IV = "0123456789ABCDEF0123456789ABCDEF";
    public static byte[] getFixedIVBytes() {
        return Hex.decode(FIXED_IV);
    }

    public static String ensureKeyLength(String key) {
        String hexKey = stringToHex(key);
        if (hexKey.length() < 32) {
            key = key+key;
            hexKey = ensureKeyLength(key);
        }
        return hexKey.substring(0, 32);
    }

    private static String stringToHex(String input) {
        StringBuilder hexString = new StringBuilder();
        for (char c : input.toCharArray()) {
            hexString.append(String.format("%02X", (int) c));
        }
        return hexString.toString();
    }

    public static String encryptSM4(String plainText, String key) throws Exception {
        String Hex_key = ensureKeyLength(key);
        byte[] keyBytes = Hex.decode(Hex_key);
        byte[] ivBytes = getFixedIVBytes();

        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new SM4Engine()));
        cipher.init(true, new ParametersWithIV(new KeyParameter(keyBytes), ivBytes));

        byte[] input = plainText.getBytes(StandardCharsets.UTF_8);
        byte[] output = new byte[cipher.getOutputSize(input.length)];

        int bytesProcessed = cipher.processBytes(input, 0, input.length, output, 0);
        cipher.doFinal(output, bytesProcessed);

        return Base64.getEncoder().encodeToString(output);
    }

    public static String decryptSM4(String encryptedText, String key) throws Exception {
        String Hex_key = ensureKeyLength(key);
        byte[] keyBytes = Hex.decode(Hex_key);
        byte[] ivBytes = getFixedIVBytes();

        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new SM4Engine()));
        cipher.init(false, new ParametersWithIV(new KeyParameter(keyBytes), ivBytes));

        byte[] input = Base64.getDecoder().decode(encryptedText);
        byte[] output = new byte[cipher.getOutputSize(input.length)];

        int bytesProcessed = cipher.processBytes(input, 0, input.length, output, 0);
        cipher.doFinal(output, bytesProcessed);

        return new String(output, StandardCharsets.UTF_8).trim();
    }
}