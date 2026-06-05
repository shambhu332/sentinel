package fixtures.taint;

import android.content.Intent;
import android.database.sqlite.SQLiteDatabase;

/**
 * Five-level chain: entry → a → b → c → sinkSite (4 inter-procedural
 * hops back from the sink). With MAX_IPA_DEPTH=3 the walk stops
 * before reaching the original Intent source and must produce NO
 * finding. This is the depth-limit boundary case.
 */
public class FourHop {
    private SQLiteDatabase db;

    public void entry(Intent intent) {
        String userInput = intent.getStringExtra("p");
        a(userInput);
    }

    private void a(String s) { b(s); }
    private void b(String s) { c(s); }
    private void c(String s) { sinkSite(s); }
    private void sinkSite(String q) {
        db.rawQuery("SELECT * FROM t WHERE col = '" + q + "'", null);
    }
}
