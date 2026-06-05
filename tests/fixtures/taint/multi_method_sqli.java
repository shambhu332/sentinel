package fixtures.taint;

import android.content.Intent;
import android.database.sqlite.SQLiteDatabase;

/**
 * Inter-procedural (1-hop) SQL injection. The source lives in
 * MultiMethodSqli.entry, which then calls MultiMethodSqli.lookup(name)
 * — and lookup() is where the rawQuery fires. The tracer must walk
 * one caller hop back from `name` to find the getStringExtra source.
 * Expected: 1 finding, depth 1, confidence 0.8.
 */
public class MultiMethodSqli {
    private SQLiteDatabase db;

    public void entry(Intent intent) {
        String name = intent.getStringExtra("name");
        lookup(name);
    }

    private void lookup(String userInput) {
        db.rawQuery("SELECT * FROM accounts WHERE n = '" + userInput + "'", null);
    }
}
