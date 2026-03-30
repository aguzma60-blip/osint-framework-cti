#!/usr/bin/env python3
"""
Crea los archivos de datos automáticamente
Ejecutar: python create_files.py
"""

import os

BASE_DIR = "/home/Foc4/OSINT"
DATA_DIR = os.path.join(BASE_DIR, "data")

# Asegurar que existe la carpeta
os.makedirs(DATA_DIR, exist_ok=True)

# === tools_data.py ===
tools_lines = [
    '"""',
    'Datos de herramientas OSINT',
    '"""',
    '',
    'TOOLS_DATA = [',
    '    # YARA Rules',
    '    ("yara-rules-github", "YARA Rules GitHub", "Official community YARA rules", ',
    '     "https://github.com/Yara-Rules/rules", "yara", ["yara","rules","malware"], "Community", True),',
    '    ("yara-python", "YARA Python", "Official Python bindings for YARA",',
    '     "https://github.com/VirusTotal/yara-python", "yara", ["yara","python","development"], "VirusTotal", True),',
    '    ("yara-editor", "YARA Editor", "Visual rule editor for YARA",',
    '     "https://github.com/YaraEditor/YaraEditor", "yara", ["yara","editor","gui"], "Community", True),',
    '',
    '    # Ransomware',
    '    ("ransomware-live", "Ransomware.live", "Track ransomware groups in real-time",',
    '     "https://ransomware.live", "ransomware", ["ransomware","tracker","groups"], "Community", True),',
    '    ("id-ransomware", "ID Ransomware", "Identify ransomware by note or sample",',
    '     "https://id-ransomware.malwarehunterteam.com", "ransomware", ["ransomware","identification"], "MalwareHunterTeam", True),',
    '    ("nomoreransom", "No More Ransom", "Free decryption tools",',
    '     "https://www.nomoreransom.org", "ransomware", ["ransomware","decryption"], "Europol", True),',
    '',
    '    # MITRE',
    '    ("mitre-attack", "MITRE ATT&CK", "Knowledge base of tactics & techniques",',
    '     "https://attack.mitre.org", "mitre", ["mitre","tactics","techniques"], "MITRE", True),',
    '',
    '    # Malware Analysis',
    '    ("virustotal", "VirusTotal", "Multi-engine file & URL scanner",',
    '     "https://www.virustotal.com", "malware", ["malware","scan","url"], "Google", True),',
    '    ("malwarebazaar", "MalwareBazaar", "Community malware sample exchange",',
    '     "https://bazaar.abuse.ch", "malware", ["malware","samples","sharing"], "abuse.ch", True),',
    '    ("hybrid-analysis", "Hybrid Analysis", "Free malware sandbox",',
    '     "https://www.hybrid-analysis.com", "malware", ["sandbox","dynamic","analysis"], "CrowdStrike", True),',
    '',
    '    # OSINT',
    '    ("maltego", "Maltego", "OSINT and link analysis tool",',
    '     "https://www.maltego.com", "osint", ["osint","mining","analysis"], "Maltego", True),',
    '    ("shodan", "Shodan", "Search engine for Internet devices",',
    '     "https://www.shodan.io", "osint", ["search","iot","scan"], "Shodan", True),',
    '',
    '    # Recon',
    '    ("censys", "Censys", "Attack surface management",',
    '     "https://search.censys.io", "recon", ["recon","assets","scan"], "Censys", True),',
    '',
    '    # Network',
    '    ("nmap", "Nmap", "Network mapper & port scanner",',
    '     "https://nmap.org", "active", ["scan","ports","network"], "Nmap", True),',
    ']',
]

# === actors_data.py ===
actors_lines = [
    '"""',
    'Datos de actores de amenazas',
    '"""',
    '',
    'from datetime import date',
    '',
    'ACTORS_DATA = [',
    '    {',
    '        "id": "lockbit",',
    '        "name": "LockBit",',
    '        "description": "Ransomware muy activo con programa de afiliados",',
    '        "aliases": ["lockbit3"],',
    '        "country": "Russia",',
    '        "target_industries": ["critical_infrastructure", "government"],',
    '        "first_seen": date(2019, 9, 1),',
    '        "last_seen": date(2024, 10, 1),',
    '        "status": "active",',
    '        "threat_level": "critical",',
    '        "ransom_notes": ["Restore-My-Files.txt"],',
    '        "yara_rules": ["rule LockBit {strings: $a=\\"LockBit\\" ascii condition: any of them}"],',
    '        "mitre_techniques": ["T1486", "T1078"],',
    '        "iocs": ["lockbit3@onionmail.org"],',
    '        "reference_links": ["https://attack.mitre.org/groups/G0080/"]',
    '    },',
    '    {',
    '        "id": "akira",',
    '        "name": "Akira",',
    '        "description": "Grupo ransomware RaaS targeting educacion y manufactura",',
    '        "aliases": ["akira"],',
    '        "country": "Russia",',
    '        "target_industries": ["education", "manufacturing"],',
    '        "first_seen": date(2023, 3, 1),',
    '        "last_seen": date(2024, 10, 1),',
    '        "status": "active",',
    '        "threat_level": "high",',
    '        "ransom_notes": ["AKIRA-RECOVER-FILES.txt"],',
    '        "yara_rules": ["rule Akira {strings: $a=\\"AKIRA\\" ascii condition: any of them}"],',
    '        "mitre_techniques": ["T1486", "T1566.001"],',
    '        "iocs": ["9f393516edf6b8e011df6ee991758480c5b99a0efbfd68347786061f0e04426c"],',
    '        "reference_links": ["https://www.cisa.gov/akira-ransomware"]',
    '    },',
    ']',
]

# === __init__.py ===
init_lines = [
    'from .tools_data import TOOLS_DATA',
    'from .actors_data import ACTORS_DATA',
    '',
    '__all__ = ["TOOLS_DATA", "ACTORS_DATA"]',
]

# Escribir archivos
files = {
    'tools_data.py': '\n'.join(tools_lines),
    'actors_data.py': '\n'.join(actors_lines),
    '__init__.py': '\n'.join(init_lines)
}

for filename, content in files.items():
    filepath = os.path.join(DATA_DIR, filename)
    with open(filepath, 'w') as f:
        f.write(content)
    print(f"Creado: {filepath}")

print("Archivos creados correctamente")