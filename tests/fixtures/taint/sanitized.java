package fixtures.taint;

import android.content.Intent;
import android.database.sqlite.SQLiteDatabase;

/**
 * The tainted Intent extra is coerced to int via Integer.parseInt
 * before it reaches rawQuery. parseInt is in the sanitizer table for
 * SQL_INJECTION, so the flow must NOT be reported.
 * Expected: zero findings.
 */
public class Sanitized {
    private SQLiteDatabase db;

    public void handle(Intent intent) {
        String raw = intent.getStringExtra("id");
        int idNumeric = Integer.parseInt(raw);
        db.rawQuery("SELECT * FROM rows WHERE id = " + idNumeric, null);
    }
}
