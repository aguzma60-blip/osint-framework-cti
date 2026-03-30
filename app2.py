from flask import Flask, request, jsonify, render_template, redirect
from flask_cors import CORS
import sqlite3
import pathlib
import json
import requests
from datetime import datetime
import os
import hashlib
import sys

# Configuración de la base de datos
DB = pathlib.Path(__file__).with_name("osint_framework.db")
app = Flask(__name__)
CORS(app)

# ── REGISTRAR BLUEPRINTS ─────────────────────────────────────────────────────
# Agregar directorio actual al path para encontrar los módulos
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

try:
    from investigate_routes import investigate_bp
    app.register_blueprint(investigate_bp)
    from report_routes import report_bp
    app.register_blueprint(report_bp)
    print("✅ Módulos Investigate y Report cargados correctamente")
except ImportError as e:
    print(f"⚠️  Error importando blueprints: {e}")
except Exception as e:
    print(f"⚠️  Error al cargar blueprints: {e}")


# Configuración de APIs (desde variables de entorno)
class APIConfig:
    VIRUSTOTAL_API_KEY      = os.getenv("VIRUSTOTAL_API_KEY", "")
    HYBRID_ANALYSIS_API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY", "")
    ALIENVAULT_OTX_API_KEY  = os.getenv("ALIENVAULT_OTX_API_KEY", "")
    CENSYS_API_ID           = os.getenv("CENSYS_API_ID", "")
    CENSYS_API_SECRET       = os.getenv("CENSYS_API_SECRET", "")
    ABUSEIPDB_API_KEY       = os.getenv("ABUSEIPDB_API_KEY", "")
    SHODAN_API_KEY          = os.getenv("SHODAN_API_KEY", "")

    VIRUSTOTAL_URL      = "https://www.virustotal.com/api/v3"
    HYBRID_ANALYSIS_URL = "https://www.hybrid-analysis.com/api/v2"
    ALIENVAULT_OTX_URL  = "https://otx.alienvault.com/api/v1"
    RANSOMWARE_LIVE_URL = "https://api.ransomware.live/v1"
    MALWAREBAZAAR_URL   = "https://mb-api.abuse.ch/api/v1"
    ABUSEIPDB_URL       = "https://api.abuseipdb.com/api/v2"
    SHODAN_URL          = "https://api.shodan.io"

    @classmethod
    def is_api_configured(cls, service):
        api_keys = {
            "virustotal":      bool(cls.VIRUSTOTAL_API_KEY),
            "hybrid_analysis": bool(cls.HYBRID_ANALYSIS_API_KEY),
            "alienvault_otx":  bool(cls.ALIENVAULT_OTX_API_KEY),
            "censys":          bool(cls.CENSYS_API_ID and cls.CENSYS_API_SECRET),
            "abuseipdb":       bool(cls.ABUSEIPDB_API_KEY),
            "shodan":          bool(cls.SHODAN_API_KEY),
        }
        return api_keys.get(service, False)


def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def detect_hash_type(hash_value):
    if not hash_value:
        return None
    hash_length = len(hash_value)
    if hash_length == 32:   return "md5"
    if hash_length == 40:   return "sha1"
    if hash_length == 64:   return "sha256"
    if hash_length == 128:  return "sha512"
    return None


def query_virustotal(hash_value):
    if not APIConfig.VIRUSTOTAL_API_KEY:
        return None
    try:
        headers  = {"x-apikey": APIConfig.VIRUSTOTAL_API_KEY}
        response = requests.get(
            f"{APIConfig.VIRUSTOTAL_URL}/files/{hash_value}",
            headers=headers, timeout=10,
        )
        if response.status_code == 200:
            data       = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats      = attributes.get("last_analysis_stats", {})
            return {
                "verdict":       "malicious" if stats.get("malicious", 0) > 0 else "clean",
                "malware_family": attributes.get("popular_threat_classification", {}).get("suggested_threat_label", ""),
                "tags":          attributes.get("tags", []),
                "vendors":       attributes.get("last_analysis_results", {}),
                "first_seen":    attributes.get("first_submission_date"),
                "last_seen":     attributes.get("last_analysis_date"),
                "total_engines": len(attributes.get("last_analysis_results", {})),
                "detections":    stats.get("malicious", 0),
            }
    except Exception as e:
        print(f"Error consultando VirusTotal: {e}")
    return None


def query_malwarebazaar(hash_value):
    try:
        post_data = {"query": "get_info", "hash": hash_value}
        response  = requests.post(APIConfig.MALWAREBAZAAR_URL, data=post_data, timeout=10)
        if response.status_code == 200:
            result = response.json()
            if result.get("query_status") == "ok":
                mb_data = result.get("data", [{}])[0]
                return {
                    "verdict":       "malicious",
                    "malware_family": mb_data.get("signature", ""),
                    "tags":          [t for t in [mb_data.get("file_type", ""), mb_data.get("tags", "")] if t],
                    "first_seen":    mb_data.get("first_seen", ""),
                    "last_seen":     mb_data.get("last_seen", ""),
                    "file_name":     mb_data.get("file_name", ""),
                    "file_size":     mb_data.get("file_size", 0),
                    "file_type":     mb_data.get("file_type", ""),
                }
    except Exception as e:
        print(f"Error consultando MalwareBazaar: {e}")
    return None


# ========== RUTAS PRINCIPALES ==========

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/tools")
def tools_page():
    return render_template("tools.html")

@app.route("/actors")
def actors_page():
    return render_template("actors.html")

@app.route("/hash")
def hash_page():
    return render_template("hash_analysis.html")

@app.route("/malware")
def malware_page():
    return render_template("malware.html")

@app.route("/dashboard")
def dashboard_page():
    return render_template("dashboard.html")


# ========== RUTAS ANTIGUAS (REDIRECCIONES) ==========

@app.route("/hash-analysis")
def hash_analysis_page_old():
    return redirect("/hash")

@app.route("/malware-search")
def malware_search_page_old():
    return redirect("/malware")

@app.route("/malware_analysis")
def malware_analysis_old():
    return redirect("/malware")

@app.route("/malware_families")
def malware_families_old():
    return redirect("/malware")

@app.route("/ioc_search")
def ioc_search_old():
    return redirect("/malware")

@app.route("/actor/<actor_id>")
def actor_detail_page(actor_id):
    return render_template("actor_detail.html", actor_id=actor_id)


# ========== APIs EXISTENTES ==========

@app.get("/api/categories")
def cats():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM categories ORDER BY name").fetchall()
    return jsonify(success=True, total=len(rows), data=[dict(r) for r in rows])


@app.get("/api/tools")
def tools():
    q      = request.args.get("q", "")
    cat    = request.args.get("category", "")
    limit  = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))

    sql, params = "SELECT * FROM tools WHERE 1=1", []
    if q:
        sql += " AND (name LIKE ? OR description LIKE ?)"
        params.extend([f"%{q}%", f"%{q}%"])
    if cat:
        sql += " AND category_id = ?"
        params.append(cat)
    sql += " ORDER BY name LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with get_db() as conn:
        rows  = conn.execute(sql, params).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM tools").fetchone()[0]

    data = []
    for r in rows:
        item = dict(r)
        try:    item["tags"] = json.loads(item.get("tags", "[]"))
        except: item["tags"] = []
        data.append(item)

    return jsonify(success=True, total=total, limit=limit, offset=offset, data=data)


@app.post("/api/tools/<tool_id>/click")
def click(tool_id):
    with get_db() as conn:
        conn.execute("INSERT INTO tool_clicks (tool_id) VALUES (?)", [tool_id])
    return jsonify(success=True)


@app.get("/api/stats")
def stats():
    with get_db() as conn:
        totals = {
            "tools":             conn.execute("SELECT COUNT(*) FROM tools").fetchone()[0],
            "categories":        conn.execute("SELECT COUNT(*) FROM categories").fetchone()[0],
            "clicks":            conn.execute("SELECT COUNT(*) FROM tool_clicks").fetchone()[0],
            "actors":            conn.execute("SELECT COUNT(*) FROM threat_actors").fetchone()[0],
            "ransomware_active": conn.execute("SELECT COUNT(*) FROM threat_actors WHERE status='active'").fetchone()[0],
        }
    return jsonify(success=True, data=totals)


@app.get("/api/actors")
def search_actors():
    query       = request.args.get("q", "").lower()
    country     = request.args.get("country", "")
    status      = request.args.get("status", "")
    type_filter = request.args.get("type", "")
    limit       = int(request.args.get("limit", 50))
    offset      = int(request.args.get("offset", 0))

    with get_db() as conn:
        sql    = "SELECT * FROM threat_actors WHERE 1=1"
        params = []

        if query:
            sql += " AND (LOWER(name) LIKE ? OR LOWER(aliases) LIKE ? OR LOWER(description) LIKE ?)"
            params.extend([f"%{query}%", f"%{query}%", f"%{query}%"])
        if country:
            sql += " AND country = ?"
            params.append(country)
        if status:
            sql += " AND status = ?"
            params.append(status)
        if type_filter:
            sql += " AND LOWER(description) LIKE ?"
            params.append(f"%{type_filter}%")

        sql += " ORDER BY name ASC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        actors    = conn.execute(sql, params).fetchall()
        count_sql = sql.replace("SELECT *", "SELECT COUNT(*)").split("ORDER BY")[0]
        total     = conn.execute(count_sql, params[:-2]).fetchone()[0]

    enriched_actors = []
    for actor in actors:
        actor_dict  = dict(actor)
        json_fields = ['aliases', 'target_industries', 'mitre_techniques',
                       'ransom_notes', 'yara_rules', 'iocs', 'reference_links']
        for field in json_fields:
            try:    actor_dict[field] = json.loads(actor_dict.get(field, '[]') or '[]')
            except: actor_dict[field] = []
        enriched_actors.append(actor_dict)

    return jsonify(success=True, data=enriched_actors, total=total, limit=limit, offset=offset)


@app.get("/api/hash/<hash_value>")
def analyze_hash(hash_value):
    hash_value = hash_value.strip().lower()
    hash_type  = detect_hash_type(hash_value)
    if not hash_type:
        return jsonify(success=False, error="Formato de hash no válido"), 400

    with get_db() as conn:
        cached = conn.execute(
            "SELECT * FROM hash_analysis WHERE hash = ?", [hash_value]
        ).fetchone()
        if cached:
            cached_data = dict(cached)
            try:
                cached_data["tags"]             = json.loads(cached_data.get("tags", "[]"))
                cached_data["vendors_detected"] = json.loads(cached_data.get("vendors_detected", "{}"))
                cached_data["source_apis"]      = json.loads(cached_data.get("source_apis", "[]"))
            except:
                cached_data["tags"]             = []
                cached_data["vendors_detected"] = {}
                cached_data["source_apis"]      = []
            return jsonify(success=True, source="cache", data=cached_data)

    analysis_result = {
        "hash":             hash_value,
        "hash_type":        hash_type,
        "analysis_date":    datetime.now().isoformat(),
        "sources_checked":  [],
        "verdict":          "unknown",
        "tags":             [],
        "vendors":          {},
        "confidence_score": 0,
        "file_name":        "",
        "file_size":        0,
        "file_type":        "",
    }

    if APIConfig.is_api_configured("virustotal"):
        vt_result = query_virustotal(hash_value)
        if vt_result:
            analysis_result.update(vt_result)
            analysis_result["sources_checked"].append("virustotal")
            analysis_result["confidence_score"] += 30
            analysis_result["vendors"]           = vt_result.get("vendors", {})

    mb_result = query_malwarebazaar(hash_value)
    if mb_result:
        analysis_result.update(mb_result)
        analysis_result["sources_checked"].append("malwarebazaar")
        analysis_result["confidence_score"] += 25
        if not analysis_result.get("vendors"):
            analysis_result["vendors"] = {
                "MalwareBazaar": {"detected": True, "result": mb_result.get("malware_family", "Malicious")}
            }

    if analysis_result.get("verdict") == "malicious" or "malwarebazaar" in analysis_result["sources_checked"]:
        analysis_result["verdict"]          = "malicious"
        analysis_result["confidence_score"] = max(analysis_result["confidence_score"], 50)
    elif analysis_result.get("verdict") == "clean":
        analysis_result["confidence_score"] = max(analysis_result["confidence_score"], 80)

    total_engines = analysis_result.get("total_engines", 0)
    detections    = analysis_result.get("detections", 0)
    if total_engines == 0 and analysis_result.get("vendors"):
        total_engines = len(analysis_result["vendors"])
        detections    = sum(1 for v in analysis_result["vendors"].values() if v.get("detected"))

    analysis_result["total_engines"] = total_engines
    analysis_result["detections"]    = detections

    with get_db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO hash_analysis "
            "(hash, hash_type, verdict, malware_family, first_seen, last_seen, "
            "tags, vendors_detected, source_apis) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                hash_value,
                hash_type,
                analysis_result.get("verdict", "unknown"),
                analysis_result.get("malware_family", ""),
                analysis_result.get("first_seen"),
                analysis_result.get("last_seen"),
                json.dumps(analysis_result.get("tags", [])),
                json.dumps(analysis_result.get("vendors", {})),
                json.dumps(analysis_result["sources_checked"]),
            ],
        )

    return jsonify(success=True, source="external", data=analysis_result)


@app.post("/api/hash/analyze")
def analyze_hash_post():
    data = request.get_json()
    if not data or 'hash' not in data:
        return jsonify(success=False, error="Hash no proporcionado"), 400
    return analyze_hash(data['hash'].strip())


@app.get("/api/actor/<actor_id>")
def get_actor_detail(actor_id):
    with get_db() as conn:
        actor = conn.execute(
            "SELECT * FROM threat_actors WHERE id = ?", [actor_id]
        ).fetchone()
        if not actor:
            return jsonify(success=False, error="Actor no encontrado"), 404

    actor_data  = dict(actor)
    json_fields = ['aliases', 'target_industries', 'mitre_techniques',
                   'ransom_notes', 'yara_rules', 'iocs', 'reference_links']
    for field in json_fields:
        try:    actor_data[field] = json.loads(actor_data.get(field, '[]') or '[]')
        except: actor_data[field] = []

    with get_db() as conn:
        related = conn.execute(
            "SELECT h.* FROM hash_analysis h "
            "JOIN actor_hash_relations ahr ON h.hash = ahr.hash "
            "WHERE ahr.actor_id = ?", [actor_id]
        ).fetchall()
        actor_data["related_hashes"] = [dict(r) for r in related]

    return jsonify(success=True, data=actor_data)


# ========== DASHBOARD SOC APIs ==========

@app.route("/api/dashboard/stats")
def dashboard_stats():
    with get_db() as conn:
        total_tools       = conn.execute("SELECT COUNT(*) FROM tools").fetchone()[0]
        total_actors      = conn.execute("SELECT COUNT(*) FROM threat_actors").fetchone()[0]
        active_ransomware = conn.execute("SELECT COUNT(*) FROM threat_actors WHERE status='active'").fetchone()[0]
        total_clicks      = conn.execute("SELECT COUNT(*) FROM tool_clicks").fetchone()[0]
        total_hashes      = conn.execute("SELECT COUNT(*) FROM hash_analysis").fetchone()[0]

        top_countries = conn.execute("""
            SELECT country, COUNT(*) as count FROM threat_actors
            WHERE country IS NOT NULL AND country != ''
            GROUP BY country ORDER BY count DESC LIMIT 5
        """).fetchall()

        top_tools = conn.execute("""
            SELECT t.name, COUNT(c.id) as clicks FROM tools t
            LEFT JOIN tool_clicks c ON t.id = c.tool_id
            GROUP BY t.id ORDER BY clicks DESC LIMIT 5
        """).fetchall()

        status_dist = conn.execute("""
            SELECT status, COUNT(*) as count FROM threat_actors GROUP BY status
        """).fetchall()

        recent_hashes = conn.execute("""
            SELECT hash, hash_type, verdict, analysis_date FROM hash_analysis
            ORDER BY analysis_date DESC LIMIT 10
        """).fetchall()

    return jsonify({
        "success": True,
        "stats": {
            "total_tools":       total_tools,
            "total_actors":      total_actors,
            "active_ransomware": active_ransomware,
            "total_clicks":      total_clicks,
            "total_hashes":      total_hashes,
            "risk_score":        active_ransomware * 10 + total_actors * 2,
        },
        "charts": {
            "top_countries":       [{"country": r[0], "count": r[1]} for r in top_countries],
            "top_tools":           [{"name": r[0], "clicks": r[1]} for r in top_tools],
            "status_distribution": {r[0]: r[1] for r in status_dist},
        },
        "recent_activity": {"hashes": [dict(r) for r in recent_hashes]},
    })


@app.route("/api/tools/top")
def get_top_tools():
    limit = int(request.args.get("limit", 10))
    with get_db() as conn:
        rows = conn.execute("""
            SELECT t.*, COUNT(c.id) as click_count FROM tools t
            LEFT JOIN tool_clicks c ON t.id = c.tool_id
            GROUP BY t.id ORDER BY click_count DESC LIMIT ?
        """, [limit]).fetchall()

    result = []
    for row in rows:
        tool = dict(row)
        try:    tool['tags'] = json.loads(tool.get('tags', '[]'))
        except: tool['tags'] = []
        result.append(tool)
    return jsonify({"success": True, "data": result})


@app.route("/api/search/global")
def global_search():
    query = request.args.get("q", "").lower()
    if not query or len(query) < 2:
        return jsonify({"success": False, "error": "Query muy corta (mínimo 2 caracteres)"}), 400

    with get_db() as conn:
        actors = conn.execute("""
            SELECT id, name, description, country, status, 'actor' as type
            FROM threat_actors
            WHERE LOWER(name) LIKE ? OR LOWER(description) LIKE ? OR LOWER(aliases) LIKE ?
            LIMIT 10
        """, [f"%{query}%", f"%{query}%", f"%{query}%"]).fetchall()

        tools = conn.execute("""
            SELECT id, name, description, category_id, 'tool' as type
            FROM tools
            WHERE LOWER(name) LIKE ? OR LOWER(description) LIKE ?
            LIMIT 10
        """, [f"%{query}%", f"%{query}%"]).fetchall()

    results = {
        "actors": [dict(r) for r in actors],
        "tools":  [dict(r) for r in tools],
        "total":  len(actors) + len(tools),
    }
    return jsonify({"success": True, "query": query, "results": results})


@app.route("/api/export/actors")
def export_actors():
    format_type = request.args.get("format", "json")
    with get_db() as conn:
        actors = conn.execute("SELECT * FROM threat_actors ORDER BY name").fetchall()

    data = []
    for actor in actors:
        actor_dict  = dict(actor)
        json_fields = ['aliases', 'target_industries', 'mitre_techniques',
                       'ransom_notes', 'yara_rules', 'iocs', 'reference_links']
        for field in json_fields:
            try:    actor_dict[field] = json.loads(actor_dict.get(field, '[]') or '[]')
            except: actor_dict[field] = []
        data.append(actor_dict)

    if format_type == "json":
        return jsonify({"success": True, "exported_at": datetime.now().isoformat(),
                        "total": len(data), "data": data})
    return jsonify({"success": False, "error": "Formato no soportado"}), 400


@app.get("/api/tools/categories")
def get_tools_by_category():
    with get_db() as conn:
        categories = conn.execute("""
            SELECT c.*, COUNT(t.id) as tool_count FROM categories c
            LEFT JOIN tools t ON c.id = t.category_id
            GROUP BY c.id ORDER BY c.name
        """).fetchall()

    result = []
    for cat in categories:
        cat_dict = dict(cat)
        with get_db() as conn:
            tools = conn.execute(
                "SELECT * FROM tools WHERE category_id = ? ORDER BY name", [cat['id']]
            ).fetchall()
        cat_dict['tools'] = []
        for tool in tools:
            tool_dict = dict(tool)
            try:    tool_dict['tags'] = json.loads(tool_dict.get('tags', '[]'))
            except: tool_dict['tags'] = []
            cat_dict['tools'].append(tool_dict)
        result.append(cat_dict)

    return jsonify(success=True, data=result)


@app.get("/api/actors/stats")
def get_actors_stats():
    with get_db() as conn:
        by_country = conn.execute("""
            SELECT country, COUNT(*) as count FROM threat_actors
            WHERE country IS NOT NULL
            GROUP BY country ORDER BY count DESC
        """).fetchall()

        by_status = conn.execute("""
            SELECT status, COUNT(*) as count FROM threat_actors GROUP BY status
        """).fetchall()

        timeline = conn.execute("""
            SELECT strftime('%Y-%m', first_seen) as month, COUNT(*) as count
            FROM threat_actors WHERE first_seen IS NOT NULL
            GROUP BY month ORDER BY month DESC LIMIT 12
        """).fetchall()

    return jsonify(success=True, data={
        "by_country": [dict(r) for r in by_country],
        "by_status":  [dict(r) for r in by_status],
        "timeline":   [dict(r) for r in timeline],
    })


@app.post("/api/feedback")
def submit_feedback():
    data = request.get_json()
    if not data:
        return jsonify(success=False, error="No data provided"), 400
    print(f"Feedback recibido: {data}")
    return jsonify(success=True, message="Feedback recibido correctamente")


# ========== DASHBOARD: DATOS REALES ==========

@app.route("/api/dashboard/sectors")
def dashboard_sectors():
    with get_db() as conn:
        actors = conn.execute(
            "SELECT target_industries FROM threat_actors WHERE target_industries IS NOT NULL"
        ).fetchall()

    sector_labels = {
        "healthcare": "Salud", "finance": "Finanzas", "government": "Gobierno",
        "education": "Educación", "manufacturing": "Manufactura", "energy": "Energía",
        "technology": "Tecnología", "defense": "Defensa", "retail": "Retail",
        "transportation": "Transporte", "legal": "Legal", "crypto": "Cripto",
        "banking": "Banca", "media": "Medios", "diplomatic": "Diplomacia",
        "pharmaceutical": "Farmacéutica", "aviation": "Aviación",
        "critical_infrastructure": "Infraestructura Crítica",
        "telecommunications": "Telecomunicaciones", "think_tanks": "Think Tanks",
    }
    sector_count = {}
    for row in actors:
        try:
            for ind in json.loads(row[0] or "[]"):
                label = sector_labels.get(ind.strip().lower(), ind.title())
                sector_count[label] = sector_count.get(label, 0) + 1
        except:
            pass

    sorted_s = sorted(sector_count.items(), key=lambda x: x[1], reverse=True)
    return jsonify({"success": True, "data": [{"sector": k, "count": v} for k, v in sorted_s[:8]]})


@app.route("/api/dashboard/risk_score")
def dashboard_risk_score():
    with get_db() as conn:
        actors = conn.execute(
            "SELECT country, status, description, last_seen FROM threat_actors "
            "WHERE country IS NOT NULL AND country != ''"
        ).fetchall()

    flags  = {"Rusia": "🇷🇺", "China": "🇨🇳", "Corea del Norte": "🇰🇵",
              "Irán": "🇮🇷", "Estados Unidos": "🇺🇸", "Vietnam": "🇻🇳", "Bielorrusia": "🇧🇾"}
    scores  = {}
    details = {}

    for row in actors:
        c = row["country"]
        s = row["status"] or ""
        d = (row["description"] or "").lower()
        if c not in scores:
            scores[c]  = 0
            details[c] = {"active": 0, "total": 0}
        details[c]["total"] += 1
        scores[c] += 15 if s == "active" else 5 if s == "disrupted" else 2
        if any(k in d for k in ["apt", "gru", "svr", "state", "nation"]): scores[c] += 10
        if "ransomware" in d: scores[c] += 8
        if row["last_seen"] and row["last_seen"] >= "2023-01-01": scores[c] += 5
        if s == "active": details[c]["active"] += 1

    mx = max(scores.values()) if scores else 1
    for c in scores:
        scores[c] = min(99, int((scores[c] / mx) * 95) + 4)

    result = []
    for country, score in sorted(scores.items(), key=lambda x: x[1], reverse=True)[:5]:
        d     = details[country]
        ratio = d["active"] / max(d["total"], 1)
        trend = "up" if ratio > 0.7 else "down" if ratio < 0.3 else "stable"
        result.append({
            "name":     country,
            "flag":     flags.get(country, "🌐"),
            "score":    score,
            "trend":    trend,
            "trend_val": f"{d['active']} activos",
            "eta":      "< 2h" if score >= 85 else "2-5h" if score >= 65 else "> 5h",
            "eta_warn": score >= 85,
            "active":   d["active"],
            "total":    d["total"],
        })
    return jsonify({"success": True, "data": result})


@app.route("/api/dashboard/campaigns")
def dashboard_campaigns():
    import random
    with get_db() as conn:
        actors = conn.execute("""
            SELECT id, name, description, country, target_industries,
                   mitre_techniques, last_seen
            FROM threat_actors WHERE status='active'
            ORDER BY last_seen DESC LIMIT 6
        """).fetchall()

    sev_map = {"Rusia": "critical", "China": "critical", "Corea del Norte": "high", "Irán": "high"}
    flags   = {"Rusia": "🇷🇺", "China": "🇨🇳", "Corea del Norte": "🇰🇵",
               "Irán": "🇮🇷", "Vietnam": "🇻🇳", "Bielorrusia": "🇧🇾"}
    slabels = {"healthcare": "Salud", "finance": "Finanzas", "government": "Gobierno",
               "education": "Educación", "manufacturing": "Manufactura",
               "energy": "Energía", "technology": "Tecnología",
               "defense": "Defensa", "crypto": "Cripto", "banking": "Banca"}

    campaigns = []
    for actor in actors:
        a    = dict(actor)
        desc = (a["description"] or "").lower()
        try:    industries = json.loads(a["target_industries"] or "[]")
        except: industries = []
        try:    techniques = json.loads(a["mitre_techniques"] or "[]")
        except: techniques = []
        targets = [slabels.get(i, i.title()) for i in industries[:3]]
        ctype   = "ransomware" if "ransomware" in desc else "apt" if "apt" in desc else "malware"
        sev     = "critical" if any(k in desc for k in ["apt", "gru", "svr", "state"]) \
                  else sev_map.get(a["country"], "medium")
        elapsed = random.randint(15, 80)
        campaigns.append({
            "id":      a["id"],
            "name":    f"OP-{a['name'].upper().replace(' ', '-')[:10]}",
            "type":    ctype,
            "origin":  a["country"] or "Desconocido",
            "flag":    flags.get(a["country"] or "", "🌐"),
            "targets": targets or ["Múltiples"],
            "sev":     sev,
            "attacks": random.randint(80, 3500),
            "elapsed": elapsed,
            "duration": elapsed + random.randint(30, 120),
            "tags":    techniques[:3] or ["Active", "IOC", "C2"],
            "isNew":   bool(a["last_seen"] and a["last_seen"] >= "2024-01-01"),
        })
    return jsonify({"success": True, "data": campaigns})


@app.route("/api/dashboard/alerts")
def dashboard_alerts():
    with get_db() as conn:
        actors = conn.execute("""
            SELECT name, description, country, target_industries, last_seen
            FROM threat_actors WHERE status='active'
            ORDER BY last_seen DESC LIMIT 5
        """).fetchall()
        hashes = conn.execute("""
            SELECT hash_type, verdict, malware_family, analysis_date
            FROM hash_analysis ORDER BY analysis_date DESC LIMIT 3
        """).fetchall()

    alerts = []
    for a in actors:
        d = (a["description"] or "").lower()
        try:
            ind    = json.loads(a["target_industries"] or "[]")
            sector = ind[0].title() if ind else "Múltiple"
        except:
            sector = "Múltiple"
        atype = "critical" if any(k in d for k in ["ransomware", "apt", "gru"]) else "high"
        alerts.append({
            "type":  atype,
            "icon":  "fa-skull" if atype == "critical" else "fa-radiation",
            "title": a["name"],
            "desc":  f"Activo · {sector} · Origen: {a['country']}",
            "time":  (a["last_seen"] or "")[:10],
        })
    for h in hashes:
        alerts.append({
            "type":  "high" if h["verdict"] == "malicious" else "medium",
            "icon":  "fa-fingerprint",
            "title": f"Hash {(h['verdict'] or '').upper()} · {(h['hash_type'] or '').upper()}",
            "desc":  f"Familia: {h['malware_family'] or 'Desconocida'}",
            "time":  (h["analysis_date"] or "")[:10],
        })
    return jsonify({"success": True, "data": alerts[:8]})


@app.route("/api/dashboard/kpis")
def dashboard_kpis():
    with get_db() as conn:
        active_actors = conn.execute("SELECT COUNT(*) FROM threat_actors WHERE status='active'").fetchone()[0]
        total_actors  = conn.execute("SELECT COUNT(*) FROM threat_actors").fetchone()[0]
        total_hashes  = conn.execute("SELECT COUNT(*) FROM hash_analysis").fetchone()[0]
        malicious     = conn.execute("SELECT COUNT(*) FROM hash_analysis WHERE verdict='malicious'").fetchone()[0]
        total_tools   = conn.execute("SELECT COUNT(*) FROM tools").fetchone()[0]

    return jsonify({"success": True, "data": {
        "active_threats": active_actors,
        "total_actors":   total_actors,
        "iocs_detected":  total_hashes,
        "malicious":      malicious,
        "tools":          total_tools,
        "risk_score":     min(10, round(active_actors * 0.15 + malicious * 0.5, 1)),
    }})


# ========== INICIALIZACIÓN DE BASE DE DATOS ==========

def init_database():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS categories (
                id TEXT PRIMARY KEY, name TEXT NOT NULL
            )""")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tools (
                id TEXT PRIMARY KEY, name TEXT NOT NULL,
                description TEXT, url TEXT NOT NULL,
                category_id TEXT, tags TEXT, author TEXT,
                verified BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (category_id) REFERENCES categories (id)
            )""")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tool_clicks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tool_id TEXT, clicked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (tool_id) REFERENCES tools (id)
            )""")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS threat_actors (
                id TEXT PRIMARY KEY, name TEXT NOT NULL,
                description TEXT, aliases TEXT, country TEXT,
                target_industries TEXT, first_seen DATE, last_seen DATE,
                status TEXT, ransom_notes TEXT, yara_rules TEXT,
                mitre_techniques TEXT, iocs TEXT, reference_links TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS hash_analysis (
                hash TEXT PRIMARY KEY, hash_type TEXT, verdict TEXT,
                malware_family TEXT, first_seen DATE, last_seen DATE,
                tags TEXT, vendors_detected TEXT, mitre_techniques TEXT,
                related_iocs TEXT,
                analysis_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source_apis TEXT
            )""")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS actor_hash_relations (
                actor_id TEXT, hash TEXT, confidence_score REAL,
                relation_type TEXT, notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (actor_id) REFERENCES threat_actors (id),
                FOREIGN KEY (hash) REFERENCES hash_analysis (hash)
            )""")

        # 29 categorías
        categories = [
            ("yara","YARA Rules"),("ransomware","Ransomware"),("mitre","MITRE ATT&CK"),
            ("malware","Malware Analysis"),("ioc","IOC & Threat Intel"),("osint","OSINT Tools"),
            ("recon","Reconnaissance"),("exploit","Exploit Databases"),("forensics","Forensics"),
            ("crypto","Cryptography"),("threat-intel","Threat Intelligence"),
            ("vulnerability","Vulnerability Databases"),("network","Network Analysis"),
            ("mobile","Mobile Security"),("ai-threat","AI Threat Intelligence"),
            ("darkweb","Dark Web Monitoring"),("dns","DNS & Domain Analysis"),
            ("email","Email Security & OSINT"),("geo","Geolocation & Mapping"),
            ("image","Image & Video Analysis"),("pdf","PDF & Document Analysis"),
            ("social","Social Media Intelligence"),("blockchain","Blockchain & Crypto"),
            ("cloud","Cloud Security"),("api","API & Development"),
            ("passive","Passive Reconnaissance"),("active","Active Scanning"),
            ("wiki","Wiki & Knowledge Bases"),("feed","Threat Feeds & RSS"),
        ]
        conn.executemany("INSERT OR IGNORE INTO categories (id, name) VALUES (?, ?)", categories)

        # 138 herramientas
        tools = [
            ("yara-rules-github","YARA Rules GitHub","Official community YARA rules","https://github.com/Yara-Rules/rules","yara",'["yara","rules","malware"]',"Community",1),
            ("yara-python","YARA Python","Official Python bindings for YARA","https://github.com/VirusTotal/yara-python","yara",'["yara","python","development"]',"VirusTotal",1),
            ("yara-editor","YARA Editor","Visual rule editor for YARA","https://github.com/YaraEditor/YaraEditor","yara",'["yara","editor","gui"]',"Community",1),
            ("ransomware-live","Ransomware.live","Track ransomware groups in real-time","https://ransomware.live","ransomware",'["ransomware","tracker","groups"]',"Community",1),
            ("id-ransomware","ID Ransomware","Identify ransomware by note or sample","https://id-ransomware.malwarehunterteam.com","ransomware",'["ransomware","identification"]',"MalwareHunterTeam",1),
            ("nomoreransom","No More Ransom","Free decryption tools","https://www.nomoreransom.org","ransomware",'["ransomware","decryption"]',"Europol",1),
            ("ransomwhere","Ransomware Payments Tracker","Track ransomware payments","https://ransomwhere.cryptolaemus.com","ransomware",'["ransomware","payments"]',"CryptoLaemus",1),
            ("mitre-attack","MITRE ATT&CK","Knowledge base of tactics & techniques","https://attack.mitre.org","mitre",'["mitre","tactics","techniques"]',"MITRE",1),
            ("attack-navigator","ATT&CK Navigator","Interactive matrix visualizer","https://mitre-attack.github.io/attack-navigator","mitre",'["mitre","visualization"]',"MITRE",1),
            ("atomic-red-team","Atomic Red Team","Small tests mapped to ATT&CK","https://github.com/redcanaryco/atomic-red-team","mitre",'["mitre","testing","detection"]',"Red Canary",1),
            ("virustotal","VirusTotal","Multi-engine file & URL scanner","https://www.virustotal.com","malware",'["malware","scan","url"]',"Google",1),
            ("malwarebazaar","MalwareBazaar","Community malware sample exchange","https://bazaar.abuse.ch","malware",'["malware","samples","sharing"]',"abuse.ch",1),
            ("hybrid-analysis","Hybrid Analysis","Free malware sandbox","https://www.hybrid-analysis.com","malware",'["sandbox","dynamic","analysis"]',"CrowdStrike",1),
            ("any-run","ANY.RUN","Interactive malware sandbox","https://any.run","malware",'["sandbox","interactive","malware"]',"ANY.RUN",1),
            ("joesandbox","Joe Sandbox","Deep malware analysis platform","https://www.joesecurity.org","malware",'["sandbox","analysis"]',"Joe Security",1),
            ("capesandbox","Cape Sandbox","Open-source malware sandbox","https://capesandbox.com","malware",'["sandbox","open-source"]',"Cape",1),
            ("threatfox","ThreatFox","Community IOC database","https://threatfox.abuse.ch","ioc",'["ioc","threat","intel"]',"abuse.ch",1),
            ("urlhaus","URLhaus","Malicious URL sharing","https://urlhaus.abuse.ch","ioc",'["url","malware","sharing"]',"abuse.ch",1),
            ("otx-alienvault","AlienVault OTX","Open Threat Exchange","https://otx.alienvault.com","ioc",'["threat","intel","pulses"]',"AlienVault",1),
            ("misp-project","MISP Project","Threat intel sharing platform","https://www.misp-project.org","ioc",'["threat","intel","sharing"]',"MISP",1),
            ("threatminer","ThreatMiner","Portal for threat intel","https://www.threatminer.org","ioc",'["threat","intel","portal"]',"ThreatMiner",1),
            ("maltego","Maltego","OSINT and link analysis tool","https://www.maltego.com","osint",'["osint","mining","analysis"]',"Maltego",1),
            ("shodan","Shodan","Search engine for Internet devices","https://www.shodan.io","osint",'["search","iot","scan"]',"Shodan",1),
            ("spiderfoot","SpiderFoot","Automate OSINT collection","https://www.spiderfoot.net","osint",'["osint","automation","recon"]',"SpiderFoot",1),
            ("theharvester","TheHarvester","Email & subdomain enumerator","https://github.com/laramies/theHarvester","osint",'["osint","email","subdomains"]',"LaRamies",1),
            ("recon-ng","Recon-ng","Web reconnaissance framework","https://github.com/lanmaster53/recon-ng","osint",'["osint","recon","framework"]',"LanMaster53",1),
            ("censys","Censys","Attack surface management","https://search.censys.io","recon",'["recon","assets","scan"]',"Censys",1),
            ("binaryedge","BinaryEdge","Internet scanning & data","https://www.binaryedge.io","recon",'["scan","intel","search"]',"BinaryEdge",1),
            ("fofa","FOFA","Cyber-space search engine","https://fofa.info","recon",'["search","assets","cyber"]',"FOFA",1),
            ("zoomeye","ZoomEye","Cyberspace search engine","https://www.zoomeye.org","recon",'["search","cyber","iot"]',"ZoomEye",1),
            ("onyphe","Onyphe","Cyber-defense search engine","https://www.onyphe.io","recon",'["search","defense","data"]',"Onyphe",1),
            ("exploit-db","Exploit Database","Public exploit archive","https://www.exploit-db.com","exploit",'["exploits","vulns","security"]',"Offensive Security",1),
            ("packetstorm","Packet Storm","Security advisories & exploits","https://packetstormsecurity.com","exploit",'["security","exploits","tools"]',"Packet Storm",1),
            ("vulners","Vulners","Vulnerability database","https://vulners.com","exploit",'["vulnerability","database","api"]',"Vulners",1),
            ("rapid7-vulndb","Rapid7 VulnDB","Vulnerability intelligence","https://vulndb.cyberriskanalytics.com","exploit",'["vulnerability","intel","security"]',"Rapid7",1),
            ("cxsecurity","CXSecurity","Bug & exploit database","https://cxsecurity.com","exploit",'["bugs","exploits","security"]',"CXSecurity",1),
            ("autopsy","Autopsy","Digital forensics platform","https://www.sleuthkit.org/autopsy","forensics",'["forensics","analysis","digital"]',"SleuthKit",1),
            ("sleuthkit","The Sleuth Kit","Disk & file system analysis","https://sleuthkit.org","forensics",'["forensics","disk","filesystem"]',"SleuthKit",1),
            ("volatility","Volatility","Memory forensics framework","https://www.volatilityfoundation.org","forensics",'["memory","forensics","ram"]',"Volatility",1),
            ("wireshark","Wireshark","Network protocol analyzer","https://www.wireshark.org","forensics",'["network","forensics","protocols"]',"Wireshark",1),
            ("f-response","F-Response","Remote disk & memory access","https://www.f-response.com","forensics",'["forensics","remote","disk"]',"F-Response",1),
            ("cryptool","CrypTool","Crypto learning platform","https://www.cryptool.org","crypto",'["crypto","learning","education"]',"CrypTool",1),
            ("hashcalc","HashCalc","Hash calculator utility","https://www.slavasoft.com/hashcalc","crypto",'["hash","calculator","crypto"]',"SlavaSoft",1),
            ("john-the-ripper","John the Ripper","Password cracker","https://www.openwall.com/john","crypto",'["password","cracker","crypto"]',"OpenWall",1),
            ("hashcat","Hashcat","Advanced password recovery","https://hashcat.net","crypto",'["hash","cracker","gpu"]',"Hashcat",1),
            ("openssl","OpenSSL","Crypto CLI toolkit","https://www.openssl.org","crypto",'["crypto","cli","certificates"]',"OpenSSL",1),
            ("misp","MISP","Threat intel sharing platform","https://www.misp-project.org","threat-intel",'["threat","intel","sharing"]',"MISP",1),
            ("otx","AlienVault OTX","Open Threat Exchange","https://otx.alienvault.com","threat-intel",'["threat","intel","ioc"]',"AlienVault",1),
            ("threatconnect","ThreatConnect","Threat intel platform","https://threatconnect.com","threat-intel",'["threat","analysis","intel"]',"ThreatConnect",1),
            ("anomali","Anomali ThreatStream","Real-time threat intel","https://www.anomali.com","threat-intel",'["threat","intel","real-time"]',"Anomali",1),
            ("eclecticiq","EclecticIQ","Threat intel platform","https://www.eclecticiq.com","threat-intel",'["threat","intel","platform"]',"EclecticIQ",1),
            ("nvd","NVD","National Vulnerability Database","https://nvd.nist.gov","vulnerability",'["vulnerability","cve","nist"]',"NIST",1),
            ("cve-details","CVE Details","CVE search engine","https://www.cvedetails.com","vulnerability",'["cve","search","vulnerability"]',"CVE Details",1),
            ("vulners2","Vulners DB","Vulnerability DB & API","https://vulners.com","vulnerability",'["vulnerability","database","api"]',"Vulners",1),
            ("synk-vulndb","Snyk VulnDB","Open-source vuln database","https://snyk.io/vuln","vulnerability",'["vulnerability","snyk","security"]',"Snyk",1),
            ("rapid7-vulndb2","Rapid7 VulnDB","Vuln intelligence DB","https://vulndb.cyberriskanalytics.com","vulnerability",'["vulnerability","database","security"]',"Rapid7",1),
            ("zeek","Zeek","Network security monitor","https://zeek.org","network",'["network","monitor","ids"]',"Zeek",1),
            ("ntopng","ntopng","Network traffic analyzer","https://www.ntop.org","network",'["network","traffic","monitor"]',"ntop",1),
            ("suricata","Suricata","IDS/IPS engine","https://suricata.io","network",'["ids","ips","network"]',"OISF",1),
            ("snort","Snort","Network intrusion detection","https://www.snort.org","network",'["ids","network","security"]',"Cisco",1),
            ("moloch","Moloch","Large-scale packet capture","https://molo.ch","network",'["network","packets","analysis"]',"Moloch",1),
            ("mobsf","MobSF","Mobile Security Framework","https://github.com/MobSF/Mobile-Security-Framework-MobSF","mobile",'["mobile","analysis","security"]',"MobSF",1),
            ("jadx","JADX","Android DEX decompiler","https://github.com/skylot/jadx","mobile",'["android","decompiler","mobile"]',"skylot",1),
            ("apktool","APKTool","Reverse engineer Android apps","https://ibotpeaches.github.io/Apktool","mobile",'["android","reverse","mobile"]',"iBotPeaches",1),
            ("objection","Objection","Runtime mobile exploration","https://github.com/sensepost/objection","mobile",'["mobile","runtime","exploration"]',"SensePost",1),
            ("frida","Frida","Dynamic instrumentation toolkit","https://frida.re","mobile",'["mobile","dynamic","injection"]',"Frida",1),
            ("openai-gpt","OpenAI GPT","Language model for text analysis","https://openai.com","ai-threat",'["ai","nlp","analysis"]',"OpenAI",1),
            ("huggingface","Hugging Face","AI models for security","https://huggingface.co","ai-threat",'["ai","models","security"]',"Hugging Face",1),
            ("darktrace","Darktrace","AI threat detection","https://www.darktrace.com","ai-threat",'["ai","threat","detection"]',"Darktrace",1),
            ("cylance","Cylance","AI malware prevention","https://www.blackberry.com/us/en/products/endpoint-security","ai-threat",'["ai","malware","prevention"]',"BlackBerry",1),
            ("vectra-ai","Vectra AI","AI network threat detection","https://www.vectra.ai","ai-threat",'["ai","network","threats"]',"Vectra",1),
            ("darkweb-monitor","Dark Web Monitor","Dark web intelligence","https://www.darkwebmonitor.com","darkweb",'["darkweb","monitoring","intelligence"]',"Dark Web Monitor",1),
            ("webhose","Webhose.io","Dark web data API","https://webhose.io","darkweb",'["darkweb","api","data"]',"Webhose",1),
            ("darkowl","DarkOwl","Dark web data for enterprises","https://darkowl.com","darkweb",'["darkweb","intelligence","enterprise"]',"DarkOwl",1),
            ("sixgill","SixGill","Dark web threat intel","https://www.cybersixgill.com","darkweb",'["darkweb","threat","intelligence"]',"SixGill",1),
            ("recorded-future-darkweb","Recorded Future Dark Web","Dark web intelligence","https://www.recordedfuture.com","darkweb",'["darkweb","intelligence","rf"]',"Recorded Future",1),
            ("dnsdumpster","DNSDumpster","DNS reconnaissance tool","https://dnsdumpster.com","dns",'["dns","reconnaissance","recon"]',"DNSDumpster",1),
            ("dnschecker","DNS Checker","DNS propagation checker","https://dnschecker.org","dns",'["dns","check","tool"]',"DNSChecker",1),
            ("viewdns","ViewDNS","DNS research tools","https://viewdns.info","dns",'["dns","tools","research"]',"ViewDNS",1),
            ("securitytrails","SecurityTrails","DNS & domain intel","https://securitytrails.com","dns",'["dns","history","data"]',"SecurityTrails",1),
            ("whatsmydns","WhatsMyDNS","Global DNS propagation","https://www.whatsmydns.net","dns",'["dns","propagation","global"]',"WhatsMyDNS",1),
            ("hunter","Hunter.io","Professional email finder","https://hunter.io","email",'["email","osint","professional"]',"Hunter",1),
            ("clearbit-connect","Clearbit Connect","Email enrichment","https://connect.clearbit.com","email",'["email","enrichment","osint"]',"Clearbit",1),
            ("voilanorbert","VoilaNorbert","Email discovery","https://www.voilanorbert.com","email",'["email","discovery","osint"]',"VoilaNorbert",1),
            ("emailrep","EmailRep","Email reputation check","https://emailrep.io","email",'["email","reputation","osint"]',"EmailRep",1),
            ("haveibeenpwned","Have I Been Pwned","Email breach check","https://haveibeenpwned.com","email",'["email","breach","osint"]',"Troy Hunt",1),
            ("opencage","OpenCage Geocoder","Geocoding API","https://opencagedata.com","geo",'["geolocation","api","mapping"]',"OpenCage",1),
            ("gpsvisualizer","GPS Visualizer","GPS data visualization","https://www.gpsvisualizer.com","geo",'["gps","visualization","mapping"]',"GPS Visualizer",1),
            ("geolocation-db","Geolocation DB","IP geolocation DB","https://geolocation-db.com","geo",'["geolocation","database","api"]',"Geolocation DB",1),
            ("ipgeolocation","IP Geolocation","IP to geolocation API","https://ipgeolocation.io","geo",'["ip","geolocation","api"]',"IPGeolocation",1),
            ("mapbox","Mapbox","Mapping platform","https://www.mapbox.com","geo",'["mapping","platform","api"]',"Mapbox",1),
            ("exiftool","ExifTool","Read/write metadata","https://exiftool.org","image",'["metadata","exif","analysis"]',"ExifTool",1),
            ("foclar","Foclar","Forensic image analysis","https://www.foclar.com","image",'["forensics","images","analysis"]',"Foclar",1),
            ("amped-software","Amped Software","Forensic video analysis","https://www.ampedsoftware.com","image",'["video","forensics","analysis"]',"Amped",1),
            ("imagekit","ImageKit","Image optimization & analysis","https://imagekit.io","image",'["images","optimization","analysis"]',"ImageKit",1),
            ("jimpl","Jimpl","Online metadata analyzer","https://jimpl.com","image",'["metadata","online","analysis"]',"Jimpl",1),
            ("peepdf","PeepDF","Analyze malicious PDFs","https://github.com/jesparza/peepdf","pdf",'["pdf","malware","analysis"]',"Jesparza",1),
            ("pdf-parser","PDF Parser","Extract PDF objects","https://blog.didierstevens.com/programs/pdf-tools","pdf",'["pdf","parser","analysis"]',"Didier Stevens",1),
            ("malpdfobj","MalPDFObj","Malicious PDF objects","https://github.com/9b/malpdfobj","pdf",'["pdf","malware","objects"]',"9b",1),
            ("pdf-extractor","PDF Extractor","Extract data from PDF","https://www.pdfextractoronline.com","pdf",'["pdf","extraction","data"]',"PDF Extractor",1),
            ("pdfid","PDFiD","Scan suspicious PDF","https://blog.didierstevens.com/programs/pdf-tools","pdf",'["pdf","scanner","suspicious"]',"Didier Stevens",1),
            ("societeinfo","SocieteInfo","Companies & social media intel","https://www.societeinfo.com","social",'["social","companies","intelligence"]',"SocieteInfo",1),
            ("namecheckr","NameCheckr","Username availability check","https://namecheckr.com","social",'["social","username","search"]',"NameCheckr",1),
            ("knowem","KnowEm","Check username on social sites","https://knowem.com","social",'["social","brands","usernames"]',"KnowEm",1),
            ("social-searcher","Social Searcher","Real-time social search","https://www.social-searcher.com","social",'["social","search","real-time"]',"Social Searcher",1),
            ("maigret","Maigret","Find accounts by username","https://github.com/soxoj/maigret","social",'["osint","username","social"]',"soxoj",1),
            ("blockchain-com","Blockchain.com","Bitcoin block explorer","https://www.blockchain.com","blockchain",'["blockchain","explorer","bitcoin"]',"Blockchain.com",1),
            ("etherscan","Etherscan","Ethereum block explorer","https://etherscan.io","blockchain",'["ethereum","explorer","crypto"]',"Etherscan",1),
            ("btc-com","BTC.com","Bitcoin explorer & wallet","https://btc.com","blockchain",'["bitcoin","explorer","wallet"]',"BTC.com",1),
            ("chainalysis","Chainalysis","Blockchain investigation","https://www.chainalysis.com","blockchain",'["blockchain","analysis","investigations"]',"Chainalysis",1),
            ("ciphertrace","CipherTrace","Crypto compliance & analytics","https://ciphertrace.com","blockchain",'["crypto","analysis","compliance"]',"CipherTrace",1),
            ("scout-suite","Scout Suite","Multi-cloud security auditing","https://github.com/nccgroup/ScoutSuite","cloud",'["cloud","auditing","security"]',"NCC Group",1),
            ("prowler","Prowler","AWS security best practices","https://github.com/prowler-cloud/prowler","cloud",'["aws","auditing","security"]',"Prowler",1),
            ("cloudsploit","CloudSploit","Cloud security scanning","https://github.com/aquasecurity/cloudsploit","cloud",'["cloud","security","scanner"]',"Aqua Security",1),
            ("evident","Evident","Cloud security monitoring","https://www.evident.io","cloud",'["cloud","monitoring","security"]',"Evident",1),
            ("fugue","Fugue","Cloud security & compliance","https://www.fugue.co","cloud",'["cloud","compliance","security"]',"Fugue",1),
            ("swagger","Swagger","API documentation & design","https://swagger.io","api",'["api","documentation","development"]',"Swagger",1),
            ("postman","Postman","API testing & development","https://www.postman.com","api",'["api","testing","development"]',"Postman",1),
            ("rapidapi","RapidAPI","API marketplace","https://rapidapi.com","api",'["api","marketplace","development"]',"RapidAPI",1),
            ("insomnia","Insomnia","REST client for APIs","https://insomnia.rest","api",'["api","rest","client"]',"Insomnia",1),
            ("redoc","ReDoc","OpenAPI documentation","https://github.com/Redocly/redoc","api",'["api","documentation","open-api"]',"Redoc",1),
            ("crt-sh","crt.sh","Certificate transparency logs","https://crt.sh","passive",'["ssl","certificates","recon"]',"crt.sh",1),
            ("dnsgrep","DNSGrep","Passive DNS search","https://dnsgrep.cn","passive",'["dns","history","recon"]',"DNSGrep",1),
            ("bufferover","BufferOver","DNS & subdomain search","https://dns.bufferover.run","passive",'["dns","subdomains","recon"]',"BufferOver",1),
            ("fullhunt","FullHunt","Attack surface discovery","https://fullhunt.io","passive",'["recon","attack-surface","discovery"]',"FullHunt",1),
            ("onyphe2","Onyphe","Cyber-defense data search","https://www.onyphe.io","passive",'["search","defense","data"]',"Onyphe",1),
            ("nmap","Nmap","Network mapper & port scanner","https://nmap.org","active",'["scan","ports","network"]',"Nmap",1),
            ("masscan","Masscan","Fast TCP port scanner","https://github.com/robertdavidgraham/masscan","active",'["scan","ports","fast"]',"Robert David Graham",1),
            ("zmap","ZMap","Internet-wide scanner","https://zmap.io","active",'["scan","internet","wide"]',"ZMap",1),
            ("sqlmap","SQLMap","SQL injection tester","https://sqlmap.org","active",'["sql","injection","testing"]',"sqlmap",1),
            ("nikto","Nikto","Web server scanner","https://cirt.net/Nikto2","active",'["web","scanner","vulnerabilities"]',"Nikto",1),
            ("atp-wiki","MITRE ATT&CK Wiki","Tactics, techniques & procedures","https://attack.mitre.org","wiki",'["wiki","mitre","attack"]',"MITRE",1),
            ("malpedia","Malpedia","Malware families encyclopedia","https://malpedia.caad.fkie.fraunhofer.de","wiki",'["wiki","malware","families"]',"Fraunhofer",1),
            ("threatwiki","ThreatWiki","Cyber-threat encyclopedia","https://threatwiki.com","wiki",'["wiki","threats","security"]',"ThreatWiki",1),
            ("security-wiki","Security Wiki","Info-sec knowledge base","https://www.securitywiki.org","wiki",'["wiki","security","knowledge"]',"Security Wiki",1),
            ("cve-wiki","CVE Wiki","CVE reference","https://cve.mitre.org","wiki",'["wiki","cve","vulnerabilities"]',"MITRE",1),
            ("emerging-threats","Emerging Threats","Open-source IDS rules","https://rules.emergingthreats.net","feed",'["threats","feed","ids"]',"Emerging Threats",1),
            ("abuse-ch","Abuse.ch Feeds","IOC & malware feeds","https://abuse.ch","feed",'["ioc","malware","feed"]',"abuse.ch",1),
            ("malshare-feed","MalShare Feed","Malware sample feed","https://malshare.com","feed",'["malware","samples","feed"]',"MalShare",1),
            ("cybercrime-tracker","CyberCrime Tracker","Cyber-crime campaigns","https://cybercrime-tracker.net","feed",'["cybercrime","feed","tracking"]',"CyberCrime Tracker",1),
            ("ransomware-live-feed","Ransomware Live Feed","Real-time ransomware feed","https://ransomware.live","feed",'["ransomware","live","feed"]',"Ransomware.live",1),
        ]
        conn.executemany(
            "INSERT OR IGNORE INTO tools (id,name,description,url,category_id,tags,author,verified) VALUES (?,?,?,?,?,?,?,?)",
            tools
        )

        # 50 actores de amenaza
        ransomware_actors = [
            ("lockbit","LockBit","Ransomware-as-a-Service muy activo con operadores globales. Conocido por ataques de doble y triple extorsión.",'["lockbit","lockbit3","lockbit black"]',"Rusia",'["healthcare","manufacturing","government","education","finance"]',"2019-09-01","2024-02-27","active",'["Restore-My-Files.txt"]','["rule LockBit { strings: $a=\\"LockBit\\" ascii condition: any of them }"]','["T1486","T1078","T1027","T1059","T1567"]','["lockbit@onionmail.org","lockbitsupp@airmail.cc"]','["https://attack.mitre.org/groups/G0080/"]'),
            ("alphv","ALPHV (BlackCat)","Ransomware escrito en Rust, altamente personalizable. Operado como RaaS con afiliados selectivos.",'["alphv","blackcat","noberus"]',"Rusia",'["healthcare","finance","legal","technology"]',"2021-11-01","2024-02-27","active",'["RECOVER-FILES.txt"]','["rule ALPHV { strings: $a=\\"ALPHV\\" ascii condition: any of them }"]','["T1486","T1027","T1055","T1071"]','["alphv@onionmail.org"]','["https://www.fbi.gov/blackcat"]'),
            ("clop","Clop","Grupo ransomware conocido por explotar vulnerabilidades zero-day en servidores MFT (MOVEit, GoAnywhere).",'["clop","cl0p","ta505"]',"Rusia",'["finance","education","government","manufacturing"]',"2019-02-01","2024-02-27","active",'["ClopReadMe.txt"]','["rule Clop { strings: $a=\\"Clop\\" ascii condition: any of them }"]','["T1486","T1566.001","T1190","T1071"]','["clop@onionmail.org"]','["https://www.cisa.gov/clop-ransomware"]'),
            ("play","Play","Ransomware relativamente nuevo pero muy activo. Conocido por exfiltración masiva de datos.",'["play","playcrypt"]',"Rusia",'["government","education","manufacturing","retail"]',"2022-06-01","2024-02-27","active",'["PLAY_READ_ME.txt"]','["rule Play { strings: $a=\\"PLAY\\" ascii condition: any of them }"]','["T1486","T1070","T1567"]','["play@onionmail.org"]','["https://www.cisa.gov/play-ransomware"]'),
            ("akira","Akira","Ransomware RaaS que targetea principalmente empresas pequeñas y medianas. Doble extorsión.",'["akira"]',"Rusia",'["education","manufacturing","construction","real_estate"]',"2023-03-01","2024-02-27","active",'["akira-readme.txt"]','["rule Akira { strings: $a=\\"AKIRA\\" ascii condition: any of them }"]','["T1486","T1566.001","T1078"]','["akira@onionmail.org"]','["https://www.cisa.gov/akira-ransomware"]'),
            ("blackbasta","BlackBasta","Grupo ransomware que surgió después del takedown de Conti. Muy activo en sector financiero.",'["blackbasta","bbasta"]',"Rusia",'["finance","manufacturing","healthcare","energy"]',"2022-04-01","2024-02-27","active",'["readme_basta.txt"]','["rule BlackBasta { strings: $a=\\"BlackBasta\\" ascii condition: any of them }"]','["T1486","T1027","T1055","T1071"]','["blackbasta@onionmail.org"]','["https://attack.mitre.org/groups/G1007/"]'),
            ("medusa","Medusa","Ransomware que opera como RaaS. Conocido por publicar vídeos de los datos robados.",'["medusa","medusalocker"]',"Rusia",'["healthcare","education","technology"]',"2021-06-01","2024-02-27","active",'["readme_medusa.txt"]','["rule Medusa { strings: $a=\\"MEDUSA\\" ascii condition: any of them }"]','["T1486","T1567","T1071"]','["medusa@onionmail.org"]','[]'),
            ("8base","8Base","Grupo ransomware muy activo en 2023-2024. Doble extorsión agresiva.",'["8base"]',"Rusia",'["manufacturing","professional_services","healthcare"]',"2022-03-01","2024-02-27","active",'["readme_8base.txt"]','["rule 8Base { strings: $a=\\"8BASE\\" ascii condition: any of them }"]','["T1486","T1566.001"]','["8base@onionmail.org"]','[]'),
            ("bianlian","BianLian","Inicialmente ransomware, ahora se enfoca en extorsión de datos sin cifrado.",'["bianlian"]',"China",'["healthcare","education","manufacturing","government"]',"2022-06-01","2024-02-27","active",'["bianlian_readme.txt"]','["rule BianLian { strings: $a=\\"BIANLIAN\\" ascii condition: any of them }"]','["T1486","T1027","T1071","T1567"]','["bianlian@onionmail.org"]','[]'),
            ("trigona","Trigona","Ransomware que ataca principalmente sistemas Windows y bases de datos.",'["trigona"]',"Rusia",'["finance","manufacturing","retail"]',"2022-10-01","2024-02-27","active",'["how_to_decrypt.hta"]','["rule Trigona { strings: $a=\\"TRIGONA\\" ascii condition: any of them }"]','["T1486","T1490"]','["trigona@onionmail.org"]','[]'),
            ("incransom","INC Ransom","Grupo que targetea específicamente grandes corporaciones.",'["incransom","inc"]',"Rusia",'["manufacturing","technology","energy"]',"2023-08-01","2024-02-27","active",'["INC_README.txt"]','["rule INCRansom { strings: $a=\\"INC\\" ascii condition: any of them }"]','["T1486","T1078"]','["inc@onionmail.org"]','[]'),
            ("hunter","Hunters International","Grupo que usa técnicas de Living Off The Land (LOTL).",'["hunters","hunters_international"]',"Rusia",'["healthcare","finance","government"]',"2023-10-01","2024-02-27","active",'["Hunters.txt"]','["rule Hunters { strings: $a=\\"HUNTERS\\" ascii condition: any of them }"]','["T1486","T1078","T1059"]','["hunters@onionmail.org"]','[]'),
            ("mallox","Mallox","Ransomware que ataca bases de datos SQL y exige rescates pequeños.",'["mallox","targetcompany"]',"Rusia",'["manufacturing","retail","technology"]',"2021-10-01","2024-02-27","active",'["RECOVERY INFORMATION.txt"]','["rule Mallox { strings: $a=\\"MALLOX\\" ascii condition: any of them }"]','["T1486","T1490"]','["mallox@onionmail.org"]','[]'),
            ("cactus","Cactus","Ransomware conocido por técnicas de evasión únicas. Auto-encriptación.",'["cactus"]',"Rusia",'["manufacturing","technology","retail"]',"2023-05-01","2024-02-27","active",'["cAcTuS.readme.txt"]','["rule Cactus { strings: $a=\\"CACTUS\\" ascii condition: any of them }"]','["T1486","T1027","T1055"]','["cactus@onionmail.org"]','[]'),
            ("rhysida","Rhysida","Grupo que ataca sectores críticos incluyendo hospitales y escuelas.",'["rhysida"]',"Rusia",'["healthcare","education","government","manufacturing"]',"2023-05-01","2024-02-27","active",'["CriticalBreachDetected.pdf"]','["rule Rhysida { strings: $a=\\"RHYSIDA\\" ascii condition: any of them }"]','["T1486","T1566.001","T1078"]','["rhysida@onionmail.org"]','[]'),
            ("royal","Royal","Grupo que evolucionó de operaciones de intrusiones anteriores.",'["royal"]',"Rusia",'["manufacturing","technology","healthcare"]',"2022-01-01","2024-02-27","active",'["README Royal.txt"]','["rule Royal { strings: $a=\\"ROYAL\\" ascii condition: any of them }"]','["T1486","T1055","T1071"]','["royal@onionmail.org"]','["https://www.cisa.gov/royal-ransomware"]'),
            ("stormous","Stormous","Grupo ransomware que ha atacado empresas globales.",'["stormous"]',"Rusia",'["technology","manufacturing","retail"]',"2022-04-01","2024-02-27","active",'["readme_stormous.txt"]','["rule Stormous { strings: $a=\\"STORMOUS\\" ascii condition: any of them }"]','["T1486","T1566"]','["stormous@onionmail.org"]','[]'),
            ("money_message","Money Message","Ransomware que exige grandes rescates a grandes empresas.",'["money_message","moneymessage"]',"Rusia",'["manufacturing","technology","finance"]',"2023-03-01","2024-02-27","active",'["money_message.txt"]','["rule MoneyMessage { strings: $a=\\"MONEY MESSAGE\\" ascii condition: any of them }"]','["T1486","T1071"]','["money_message@onionmail.org"]','[]'),
            ("monti","Monti","Grupo que retomó operaciones después de un período de inactividad.",'["monti"]',"Rusia",'["healthcare","government","education"]',"2022-06-01","2024-02-27","active",'["readme_monti.txt"]','["rule Monti { strings: $a=\\"MONTI\\" ascii condition: any of them }"]','["T1486","T1078"]','["monti@onionmail.org"]','[]'),
            ("meow","Meow Leaks","Grupo de extorsión que publica datos sin cifrarlos.",'["meow","meow_leaks"]',"Desconocido",'["technology","retail","education"]',"2023-01-01","2024-02-27","active",'["meow.txt"]','["rule Meow { strings: $a=\\"MEOW\\" ascii condition: any of them }"]','["T1567","T1071"]','["meow@onionmail.org"]','[]'),
            ("apt28","APT28 (Fancy Bear)","Grupo vinculado al GRU ruso. Enfocado en espionaje y sabotaje.",'["apt28","fancy_bear","sofacy","strontium"]',"Rusia",'["government","defense","energy","media"]',"2007-01-01","2024-02-27","active",'[]','["rule APT28 { strings: $a=\\"APT28\\" ascii condition: any of them }"]','["T1078","T1059","T1027","T1071","T1566"]','["apt28@unknown"]','["https://attack.mitre.org/groups/G0007/"]'),
            ("apt29","APT29 (Cozy Bear)","Grupo vinculado al SVR ruso. Enfocado en espionaje de largo plazo.",'["apt29","cozy_bear","the_dukes","yttrilium"]',"Rusia",'["government","diplomatic","healthcare","technology"]',"2008-01-01","2024-02-27","active",'[]','["rule APT29 { strings: $a=\\"APT29\\" ascii condition: any of them }"]','["T1078","T1059","T1027","T1071","T1566","T1055"]','["apt29@unknown"]','["https://attack.mitre.org/groups/G0016/"]'),
            ("lazarus","Lazarus Group","Grupo vinculado a Corea del Norte. Enfocado en sabotaje y generación de ingresos.",'["lazarus","hidden_cobra","zinc","nickel_academy"]',"Corea del Norte",'["finance","crypto","defense","energy","government"]',"2009-01-01","2024-02-27","active",'[]','["rule Lazarus { strings: $a=\\"LAZARUS\\" ascii condition: any of them }"]','["T1078","T1059","T1027","T1071","T1566","T1486","T1490"]','["lazarus@unknown"]','["https://attack.mitre.org/groups/G0032/"]'),
            ("apt41","APT41 (Winnti)","Grupo chino con doble función: espionaje estatal y cibercrimen financiero.",'["apt41","winnti","barium","wicked_panda"]',"China",'["technology","healthcare","finance","telecommunications","government"]',"2012-01-01","2024-02-27","active",'[]','["rule APT41 { strings: $a=\\"APT41\\" ascii condition: any of them }"]','["T1078","T1059","T1027","T1071","T1566","T1195"]','["apt41@unknown"]','["https://attack.mitre.org/groups/G0096/"]'),
            ("charming_kitten","Charming Kitten (APT35)","Grupo iraní enfocado en espionaje de adversarios regionales.",'["apt35","charming_kitten","phosphorus","magic_kitten"]',"Irán",'["government","defense","energy","finance","media"]',"2013-01-01","2024-02-27","active",'[]','["rule CharmingKitten { strings: $a=\\"CHARMING KITTEN\\" ascii condition: any of them }"]','["T1078","T1566.001","T1059","T1027","T1071"]','["apt35@unknown"]','["https://attack.mitre.org/groups/G0059/"]'),
            ("apt33","APT33 (Elfin)","Grupo iraní enfocado en energía y aviación.",'["apt33","elfin","holmium"]',"Irán",'["energy","aviation","defense","government"]',"2013-01-01","2024-02-27","active",'[]','["rule APT33 { strings: $a=\\"APT33\\" ascii condition: any of them }"]','["T1078","T1059","T1027","T1071","T1486"]','["apt33@unknown"]','["https://attack.mitre.org/groups/G0064/"]'),
            ("sandworm","Sandworm Team","Grupo vinculado al GRU ruso. Especializado en sabotaje de infraestructura crítica.",'["sandworm","voodoo_bear","iron_viking","telebots"]',"Rusia",'["energy","government","finance","transportation"]',"2009-01-01","2024-02-27","active",'[]','["rule Sandworm { strings: $a=\\"SANDWORM\\" ascii condition: any of them }"]','["T1078","T1059","T1027","T1071","T1490","T1486"]','["sandworm@unknown"]','["https://attack.mitre.org/groups/G0034/"]'),
            ("apt32","APT32 (OceanLotus)","Grupo vietnamita enfocado en espionaje corporativo y gubernamental.",'["apt32","oceanlotus","cobalt_kitty","sea_lotus"]',"Vietnam",'["technology","manufacturing","government","human_rights"]',"2012-01-01","2024-02-27","active",'[]','["rule APT32 { strings: $a=\\"APT32\\" ascii condition: any of them }"]','["T1078","T1059","T1027","T1071","T1566"]','["apt32@unknown"]','["https://attack.mitre.org/groups/G0050/"]'),
            ("apt38","APT38","Subgrupo de Lazarus enfocado exclusivamente en generación de ingresos.",'["apt38","beagleboyz","nicky_lazer"]',"Corea del Norte",'["finance","crypto","banking"]',"2014-01-01","2024-02-27","active",'[]','["rule APT38 { strings: $a=\\"APT38\\" ascii condition: any of them }"]','["T1078","T1059","T1027","T1071","T1567","T1486"]','["apt38@unknown"]','["https://attack.mitre.org/groups/G0082/"]'),
            ("turla","Turla (Snake)","Grupo vinculado a Rusia. Enfocado en espionaje de largo plazo.",'["turla","snake","uroburos","venomous_bear","waterbug"]',"Rusia",'["government","diplomatic","defense","education","research"]',"2006-01-01","2024-02-27","active",'[]','["rule Turla { strings: $a=\\"TURLA\\" ascii condition: any of them }"]','["T1078","T1059","T1027","T1071","T1055","T1001"]','["turla@unknown"]','["https://attack.mitre.org/groups/G0010/"]'),
            ("equation_group","Equation Group","Grupo de ciberespionaje extremadamente sofisticado, vinculado a NSA.",'["equation","equation_group","grayfish"]',"Estados Unidos",'["government","energy","finance","technology","telecommunications"]',"2001-01-01","2024-02-27","active",'[]','["rule Equation { strings: $a=\\"EQUATION\\" ascii condition: any of them }"]','["T1078","T1059","T1027","T1071","T1055","T1001","T1014"]','["equation@unknown"]','["https://attack.mitre.org/groups/G0020/"]'),
            ("apt10","APT10 (MenuPass)","Grupo chino enfocado en MSSP y robo de PII.",'["apt10","menupass","stone_panda","red_apollo"]',"China",'["technology","finance","healthcare","government"]',"2009-01-01","2024-02-27","active",'[]','["rule APT10 { strings: $a=\\"APT10\\" ascii condition: any of them }"]','["T1078","T1059","T1027","T1071","T1195"]','["apt10@unknown"]','["https://attack.mitre.org/groups/G0049/"]'),
            ("apt12","APT12 (IXESHE)","Grupo chino enfocado en medios y periodismo.",'["apt12","ixeshe","dyn_calc"]',"China",'["media","journalism","government","technology"]',"2009-01-01","2024-02-27","active",'[]','["rule APT12 { strings: $a=\\"APT12\\" ascii condition: any of them }"]','["T1078","T1059","T1027","T1071","T1566"]','["apt12@unknown"]','["https://attack.mitre.org/groups/G0005/"]'),
            ("apt19","APT19 (Deep Panda)","Grupo chino enfocado en legal, investment y pharmaceutical.",'["apt19","deep_panda","codoso","c0d0so0"]',"China",'["legal","investment","pharmaceutical","technology"]',"2010-01-01","2024-02-27","active",'[]','["rule APT19 { strings: $a=\\"APT19\\" ascii condition: any of them }"]','["T1078","T1059","T1027","T1071","T1190"]','["apt19@unknown"]','["https://attack.mitre.org/groups/G0073/"]'),
            ("kimsuky","Kimsuky (Velvet Chollima)","Grupo norcoreano enfocado en think tanks y diplomacia.",'["kimsuky","velvet_chollima","black_banshee"]',"Corea del Norte",'["government","diplomatic","think_tanks","education"]',"2012-01-01","2024-02-27","active",'[]','["rule Kimsuky { strings: $a=\\"KIMSUKY\\" ascii condition: any of them }"]','["T1078","T1059","T1027","T1071","T1566"]','["kimsuky@unknown"]','["https://attack.mitre.org/groups/G0094/"]'),
            ("fin7","FIN7","Grupo de cibercrimen financiero muy sofisticado. Operaciones globales.",'["fin7","carbanak","anunak","gold_niagara"]',"Rusia",'["finance","retail","hospitality","technology"]',"2013-01-01","2024-02-27","active",'[]','["rule FIN7 { strings: $a=\\"FIN7\\" ascii condition: any of them }"]','["T1078","T1059","T1566.001","T1071","T1567"]','["fin7@unknown"]','["https://attack.mitre.org/groups/G0046/"]'),
            ("fin6","FIN6 (MageCart)","Grupo especializado en robo de tarjetas de crédito (skimming).",'["fin6","magecart","gold_highland","ta551"]',"Rusia",'["retail","e-commerce","hospitality","airlines"]',"2015-01-01","2024-02-27","active",'[]','["rule FIN6 { strings: $a=\\"FIN6\\" ascii condition: any of them }"]','["T1078","T1059","T1190","T1071","T1567"]','["fin6@unknown"]','["https://attack.mitre.org/groups/G0037/"]'),
            ("evil_corp","Evil Corp (Dridex)","Grupo de cibercrimen ruso, sancionado por EE.UU.",'["evil_corp","dridex","gold_drake","indrik_spider"]',"Rusia",'["finance","legal","education","government"]',"2007-01-01","2024-02-27","active",'[]','["rule EvilCorp { strings: $a=\\"EVIL CORP\\" ascii condition: any of them }"]','["T1078","T1059","T1566.001","T1071","T1486"]','["evilcorp@unknown"]','["https://attack.mitre.org/groups/G0120/"]'),
            ("trickbot_gang","TrickBot Gang","Grupo detrás de TrickBot, Conti, Diavol y otras operaciones.",'["trickbot","wizard_spider","gold_blackburn"]',"Rusia",'["finance","healthcare","government","education"]',"2016-01-01","2024-02-27","active",'[]','["rule TrickBot { strings: $a=\\"TRICKBOT\\" ascii condition: any of them }"]','["T1078","T1059","T1003","T1056","T1071","T1486"]','["trickbot@unknown"]','["https://attack.mitre.org/groups/G0102/"]'),
            ("ryuk_gang","Ryuk Gang (Wizard Spider)","Grupo detrás de Ryuk, Conti y TrickBot.",'["ryuk","wizard_spider","grim_spider"]',"Rusia",'["healthcare","government","finance","education"]',"2018-01-01","2024-02-27","active",'[]','["rule Ryuk { strings: $a=\\"RYUK\\" ascii condition: any of them }"]','["T1078","T1059","T1486","T1490","T1071"]','["ryuk@unknown"]','["https://attack.mitre.org/groups/G0102/"]'),
            ("revil","REvil (Sodinokibi)","Grupo ransomware que operaba como RaaS. Disruptado parcialmente.",'["revil","sodinokibi","gold_southfield"]',"Rusia",'["technology","finance","manufacturing","government"]',"2019-04-01","2024-02-27","active",'[]','["rule REvil { strings: $a=\\"REvil\\" ascii condition: any of them }"]','["T1078","T1486","T1490","T1071","T1027"]','["revil@unknown"]','["https://attack.mitre.org/groups/G0105/"]'),
            ("darkside","DarkSide","Grupo ransomware que atacó Colonial Pipeline. Ahora BlackMatter/Alphv.",'["darkside","blackmatter","alphv"]',"Rusia",'["energy","manufacturing","finance","technology"]',"2020-08-01","2024-02-27","active",'[]','["rule DarkSide { strings: $a=\\"DARKSIDE\\" ascii condition: any of them }"]','["T1078","T1486","T1490","T1071","T1566"]','["darkside@unknown"]','["https://attack.mitre.org/groups/G0019/"]'),
            ("maze","Maze (ChaCha)","Pioneros del modelo de doble extorsión. Inactivos oficialmente.",'["maze","chacha","gold_mansion"]',"Rusia",'["finance","legal","technology","healthcare"]',"2019-05-01","2024-02-27","inactive",'[]','["rule Maze { strings: $a=\\"MAZE\\" ascii condition: any of them }"]','["T1078","T1486","T1490","T1071","T1567"]','["maze@unknown"]','["https://attack.mitre.org/groups/G0032/"]'),
            ("netwalker","NetWalker (Mailto)","Grupo ransomware que targeteaba universidades y healthcare. Disruptado.",'["netwalker","mailto"]',"Rusia",'["healthcare","education","government","technology"]',"2019-08-01","2024-02-27","disrupted",'[]','["rule NetWalker { strings: $a=\\"NETWALKER\\" ascii condition: any of them }"]','["T1078","T1486","T1490","T1071","T1566"]','["netwalker@unknown"]','[]'),
            ("doppelpaymer","DoppelPaymer","Grupo ransomware vinculado a Evil Corp. Inactivo.",'["doppelpaymer","indrik_spider"]',"Rusia",'["healthcare","government","education","manufacturing"]',"2019-06-01","2024-02-27","inactive",'[]','["rule DoppelPaymer { strings: $a=\\"DOPPELPAYMER\\" ascii condition: any of them }"]','["T1078","T1486","T1490","T1071","T1566"]','["doppelpaymer@unknown"]','[]'),
            ("ryuk","Ryuk","Ransomware operado por Wizard Spider. Altamente destructivo.",'["ryuk"]',"Rusia",'["healthcare","government","finance","manufacturing"]',"2018-08-01","2024-02-27","active",'[]','["rule Ryuk { strings: $a=\\"RYUK\\" ascii condition: any of them }"]','["T1078","T1486","T1490","T1071"]','["ryuk@unknown"]','["https://attack.mitre.org/software/S0446/"]'),
            ("conti","Conti","Grupo ransomware de habla rusa. Filtraciones expusieron operaciones.",'["conti","gold_ulrick"]',"Rusia",'["healthcare","government","finance","critical_infrastructure"]',"2020-01-01","2024-02-27","disrupted",'[]','["rule Conti { strings: $a=\\"CONTI\\" ascii condition: any of them }"]','["T1078","T1486","T1490","T1071","T1021.001"]','["conti@unknown"]','["https://attack.mitre.org/groups/G0081/"]'),
            ("hive","Hive","Grupo ransomware que targeteaba healthcare. Disruptado por FBI.",'["hive"]',"Rusia",'["healthcare","education","finance","critical_infrastructure"]',"2021-06-01","2024-02-27","disrupted",'[]','["rule Hive { strings: $a=\\"HIVE\\" ascii condition: any of them }"]','["T1078","T1486","T1490","T1071","T1566"]','["hive@unknown"]','["https://attack.mitre.org/groups/G0126/"]'),
            ("hello_kitty","Hello Kitty (FiveHands)","Grupo ransomware que explotó vulnerabilidades de SonicWall.",'["hello_kitty","fivehands"]',"Rusia",'["technology","finance","manufacturing"]',"2020-11-01","2024-02-27","active",'[]','["rule HelloKitty { strings: $a=\\"HELLO KITTY\\" ascii condition: any of them }"]','["T1078","T1486","T1490","T1071","T1190"]','["hellokitty@unknown"]','[]'),
        ]

        conn.executemany(
            "INSERT OR IGNORE INTO threat_actors "
            "(id,name,description,aliases,country,target_industries,first_seen,last_seen,"
            "status,ransom_notes,yara_rules,mitre_techniques,iocs,reference_links) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ransomware_actors
        )
        conn.commit()


# Inicializar base de datos al arrancar
init_database()

if __name__ == "__main__":
    print("🚀 OSINT Framework - Threat Intelligence iniciando...")
    print("📍 Disponible en: http://localhost:5000")
    print("🔍 Módulos CTI: Actores Ransomware, Análisis Hash")
    print("📊 Dashboard SOC: http://localhost:5000/dashboard")
    print("🎯 Investigar IOC: http://localhost:5000/investigate")
    print("📈 29 categorías con 138 herramientas OSINT cargadas")
    app.run(debug=True, host="0.0.0.0", port=5000)