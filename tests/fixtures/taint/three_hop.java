package fixtures.taint;

import android.content.Intent;
import android.database.sqlite.SQLiteDatabase;

/**
 * Three-hop chain: entry -> middle -> sinkSite. The tracer must walk
 * back two parameter hops (sinkSite.q  →  middle.s  →  entry's
 * intent.getStringExtra) to identify taint.
 * Expected: 1 finding, depth 2, confidence 0.7.
 */
public class ThreeHop {
    private SQLiteDatabase db;

    public void entry(Intent intent) {
        String userInput = intent.getStringExtra("payload");
        middle(userInput);
    }

    private void middle(String s) {
        sinkSite(s);
    }

    private void sinkSite(String q) {
        db.rawQuery("SELECT * FROM t WHERE col = '" + q + "'", null);
    }
}
