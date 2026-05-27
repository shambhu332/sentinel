package com.example.clean;

import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import java.security.MessageDigest;
import javax.crypto.Cipher;

public class CleanCode {
    public byte[] encryptAesGcm(byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        return cipher.doFinal(plaintext);
    }

    public byte[] sha256(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }

    public Cursor lookup(SQLiteDatabase db, String userId) {
        return db.rawQuery(
            "SELECT * FROM users WHERE id = ?",
            new String[] { userId }
        );
    }
}
