"""SharedPreferences security agents."""
from sentinel.agents.shared_prefs.insecure_prefs_agent import InsecureSharedPrefsAgent
from sentinel.agents.shared_prefs.stg007_insecure_file_provider import (
    InsecureFileProviderAgent,
)
from sentinel.agents.shared_prefs.stg008_external_storage_credential import (
    ExternalStorageCredentialAgent,
)
from sentinel.agents.shared_prefs.stg009_backup_rules import BackupRulesAgent
from sentinel.agents.shared_prefs.stg010_plaintext_password_file import (
    PlaintextPasswordFileAgent,
)
from sentinel.agents.shared_prefs.stg011_sqlite_wal_leak import (
    SqliteWalLeakAgent,
)

__all__ = [
    "BackupRulesAgent",
    "ExternalStorageCredentialAgent",
    "InsecureFileProviderAgent",
    "InsecureSharedPrefsAgent",
    "PlaintextPasswordFileAgent",
    "SqliteWalLeakAgent",
]
