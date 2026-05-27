package com.example.vuln;

import java.security.MessageDigest;
import javax.crypto.Cipher;

public class VulnerableCrypto {
    public byte[] encryptDes(byte[] plaintext, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("DES");
        return cipher.doFinal(plaintext);
    }

    public byte[] encryptAesEcb(byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        return cipher.doFinal(plaintext);
    }

    public byte[] md5(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }

    public byte[] sha1(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(data);
    }
}
