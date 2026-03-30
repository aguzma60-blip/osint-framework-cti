import sqlite3

conn = sqlite3.connect("osint_framework.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS threat_actors (
    id TEXT PRIMARY KEY,
    name TEXT,
    description TEXT,
    aliases TEXT,
    country TEXT,
    target_industries TEXT,
    first_seen TEXT,
    last_seen TEXT,
    status TEXT,
    ransom_notes TEXT,
    yara_rules TEXT,
    mitre_techniques TEXT,
    iocs TEXT,
    reference_links TEXT
)
""")

conn.commit()
conn.close()

print("✅ Tabla threat_actors creada correctamente")