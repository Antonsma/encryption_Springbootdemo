package com.antonsma.springbootdemo.utils;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.util.encoders.Hex;
public class SM3Utils {
    public static String calculateSM3Hash(String text) {
        byte[] data = text.getBytes();
        SM3Digest digest = new SM3Digest();
        digest.update(data, 0, data.length);

        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        return Hex.toHexString(hash);
    }
}
