package fixtures.taint;

import android.content.Intent;
import android.util.Log;

/**
 * Intent extra is logged via Log.d. SENSITIVE_LOG should be reported
 * with severity LOW (per the SinkSpec table).
 * Expected: 1 finding, vuln_class SENSITIVE_LOG, severity Low.
 */
public class SensitiveLog {
    public void check(Intent intent) {
        String token = intent.getStringExtra("token");
        Log.d("Auth", token);
    }
}
