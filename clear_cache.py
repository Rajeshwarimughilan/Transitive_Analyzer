# clear_cache.py
import sqlite3
conn = sqlite3.connect('cve_cache/transrisk.db')

before = conn.execute('SELECT COUNT(*) FROM osv_cache').fetchone()[0]
conn.execute('DELETE FROM osv_cache')
conn.execute('DELETE FROM nvd_cache')
conn.commit()
print(f"Cleared {before} OSV cache entries")
conn.close()