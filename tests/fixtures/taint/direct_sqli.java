package fixtures.taint;

import android.content.Intent;
import android.database.sqlite.SQLiteDatabase;

/**
 * Direct intra-procedural SQL injection: untrusted Intent extra is
 * concatenated straight into a rawQuery call inside the same method.
 * Expected: 1 finding, vuln_class SQL_INJECTION, depth 0.
 */
public class DirectSqli {
    void handle(Intent intent, SQLiteDatabase db) {
        String username = intent.getStringExtra("user");
        String query = "SELECT * FROM users WHERE name = '" + username + "'";
        db.rawQuery(query, null);
    }
}
