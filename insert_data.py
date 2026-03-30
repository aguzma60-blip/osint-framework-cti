import sqlite3
import json

conn = sqlite3.connect("osint_framework.db")
cursor = conn.cursor()

# 🔥 ACTORES DE EJEMPLO (puedes ampliar a 200+)
actors = [
    (
        "bianlian",
        "BianLian",
        "Grupo ransomware targeting healthcare",
        json.dumps(["bianlian"]),
        "China",
        json.dumps(["healthcare", "education"]),
        "2022-06-01",
        "2024-10-01",
        "active",
        json.dumps(["BIANLIAN_README.txt"]),
        json.dumps(["rule BianLian_Ransomware { strings: $a1 = \"BianLian\" ascii condition: any of them }"]),
        json.dumps(["T1486", "T1027"]),
        json.dumps(["bianlian@onionmail.org"]),
        json.dumps(["https://www.healthcare.gov/cybersecurity"]),
    ),
    (
        "play",
        "Play",
        "Ransomware targeting múltiples sectores",
        json.dumps(["play"]),
        "Russia",
        json.dumps(["government", "education"]),
        "2022-06-01",
        "2024-10-01",
        "active",
        json.dumps(["PLAY_READ_ME.txt"]),
        json.dumps(["rule Play_Ransomware { strings: $a1 = \"PLAY\" ascii condition: any of them }"]),
        json.dumps(["T1486", "T1070"]),
        json.dumps(["play@onionmail.org"]),
        json.dumps(["https://www.cisa.gov/play-ransomware"]),
    ),
]

# 🔥 INSERT
for actor in actors:
    cursor.execute("""
    INSERT OR IGNORE INTO threat_actors (
        id, name, description, aliases, country, target_industries,
        first_seen, last_seen, status, ransom_notes, yara_rules,
        mitre_techniques, iocs, reference_links
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, actor)

conn.commit()
conn.close()

print("✅ Datos insertados correctamente")