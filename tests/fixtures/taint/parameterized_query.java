package fixtures.taint;

import android.content.Intent;
import android.database.sqlite.SQLiteDatabase;

/**
 * Parameterised query — the tainted value is bound via the second
 * argument to rawQuery as a ? placeholder. The SQL itself contains no
 * user input. The first rawQuery argument is a static string literal,
 * so the backward slice from arg 0 should not find any taint.
 * Expected: zero findings.
 */
public class ParameterizedQuery {
    private SQLiteDatabase db;

    public void handle(Intent intent) {
        String name = intent.getStringExtra("name");
        db.rawQuery("SELECT * FROM users WHERE n = ?", new String[]{ name });
    }
}
