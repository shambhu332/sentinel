package fixtures.taint;

import android.database.sqlite.SQLiteDatabase;

/**
 * The SQL string is a compile-time constant, no untrusted source ever
 * touches it. The tracer must produce no findings here.
 * Expected: zero findings.
 */
public class NoTaint {
    private SQLiteDatabase db;

    public void load() {
        String query = "SELECT * FROM static_table";
        db.rawQuery(query, null);
    }
}
