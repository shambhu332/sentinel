package com.example.vuln;

import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;

public class VulnerableSql {
    public Cursor lookup(SQLiteDatabase db, String userInput) {
        return db.rawQuery("SELECT * FROM users WHERE id = " + userInput, null);
    }

    public void delete(SQLiteDatabase db, String userInput) {
        db.execSQL("DELETE FROM sessions WHERE token = '" + userInput + "'");
    }
}
