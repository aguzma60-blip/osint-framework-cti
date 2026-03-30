# ============================================================
#  report_routes.py
#  INSTRUCCIONES: Añadir en app2.py después de registrar investigate_bp:
#    from report_routes import report_bp
#    app.register_blueprint(report_bp)
#  Módulo: Generación de Reportes CTI Estructurados
#  Añadir a app2.py:
#    from report_routes import report_bp
#    app.register_blueprint(report_bp)
# ============================================================

from flask import Blueprint, render_template, request, jsonify
from datetime import datetime
import json

# Importar funciones de consulta desde investigate_routes
from investigate_routes import (
    detect_ioc_type,
    query_virustotal,
    query_malwarebazaar,
    query_abuseipdb,
    query_shodan,
    correlate_results,
)
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

report_bp = Blueprint('report', __name__)


def run_full_investigation(ioc: str) -> dict:
    """Ejecuta investigación completa en paralelo y retorna todos los datos."""
    ioc_type = detect_ioc_type(ioc)
    if ioc_type == 'unknown':
        return None

    start = time.time()
    tasks = {
        'virustotal':    lambda: query_virustotal(ioc, ioc_type),
        'malwarebazaar': lambda: query_malwarebazaar(ioc, ioc_type),
        'abuseipdb':     lambda: query_abuseipdb(ioc, ioc_type),
        'shodan':        lambda: query_shodan(ioc, ioc_type),
    }
    source_results = {}
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(fn): name for name, fn in tasks.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                source_results[name] = future.result()
            except Exception as e:
                source_results[name] = {'source': name, 'available': False, 'error': str(e)}

    correlation = correlate_results(list(source_results.values()), ioc_type, ioc)
    elapsed = round(time.time() - start, 2)

    return {
        'ioc':         ioc,
        'ioc_type':    ioc_type,
        'elapsed':     elapsed,
        'correlation': correlation,
        'sources':     source_results,
        'generated_at': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
        'report_id':   f"CTI-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
    }


# ── RUTAS ────────────────────────────────────────────────────────────────────

@report_bp.route('/report')
def report_page():
    """Página de reporte. Acepta ?ioc=... para auto-investigar."""
    ioc = request.args.get('ioc', '').strip()
    return render_template('report.html', ioc=ioc)


@report_bp.route('/api/report/generate', methods=['POST'])
def api_generate_report():
    """
    POST JSON: { "ioc": "8.8.8.8" }
    Genera reporte completo con datos reales de todas las fuentes.
    """
    body = request.get_json(silent=True) or {}
    ioc  = (body.get('ioc') or '').strip()

    if not ioc:
        return jsonify({'success': False, 'error': 'Debes proporcionar un IOC'}), 400

    data = run_full_investigation(ioc)
    if data is None:
        return jsonify({'success': False,
                        'error': 'Tipo de indicador no reconocido'}), 400

    return jsonify({'success': True, 'data': data})


@report_bp.route('/api/report/json', methods=['POST'])
def api_report_json():
    """
    POST JSON: { "ioc": "..." }
    Devuelve el reporte completo en JSON estructurado para descarga.
    """
    body = request.get_json(silent=True) or {}
    ioc  = (body.get('ioc') or '').strip()

    if not ioc:
        return jsonify({'success': False, 'error': 'IOC requerido'}), 400

    data = run_full_investigation(ioc)
    if data is None:
        return jsonify({'success': False, 'error': 'Tipo no reconocido'}), 400

    # Reporte estructurado para analistas
    report = {
        'report_metadata': {
            'report_id':     data['report_id'],
            'generated_at':  data['generated_at'],
            'generated_by':  'OSINT Framework CTI - Automated Intelligence Report',
            'version':       '1.0',
            'classification':'TLP:AMBER',
        },
        'indicator': {
            'value':    ioc,
            'type':     data['ioc_type'],
            'analysis_time_seconds': data['elapsed'],
        },
        'executive_summary': {
            'verdict':    data['correlation']['global_verdict'],
            'confidence': data['correlation']['confidence'],
            'summary':    data['correlation']['summary'],
            'tags':       data['correlation']['tags'],
        },
        'findings': data['correlation']['findings'],
        'source_intelligence': {
            'sources_consulted': data['correlation']['sources_consulted'],
            'sources_with_data': data['correlation']['sources_found'],
            'details': data['sources'],
        },
        'recommendations': _build_recommendations(data['correlation']),
        'mitre_context':   _build_mitre_context(data['sources']),
    }

    from flask import Response
    filename = f"CTI_Report_{ioc.replace('.','_').replace('/','_')[:30]}_{datetime.utcnow().strftime('%Y%m%d')}.json"
    return Response(
        json.dumps(report, indent=2, ensure_ascii=False),
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'}
    )


def _build_recommendations(correlation: dict) -> list:
    """Genera recomendaciones accionables según el veredicto."""
    verdict = correlation.get('global_verdict', 'unknown')
    confidence = correlation.get('confidence', 0)
    recs = []

    if verdict == 'malicious':
        recs = [
            {'priority': 'CRÍTICA', 'action': 'Bloquear inmediatamente el indicador en firewall, proxy y EDR'},
            {'priority': 'CRÍTICA', 'action': 'Aislar cualquier sistema que haya tenido contacto con este IOC'},
            {'priority': 'ALTA',    'action': 'Escalar al equipo de respuesta a incidentes (IR)'},
            {'priority': 'ALTA',    'action': 'Revisar logs de los últimos 30 días buscando conexiones previas'},
            {'priority': 'MEDIA',   'action': 'Añadir el IOC a la lista de observación en SIEM'},
            {'priority': 'MEDIA',   'action': 'Notificar a equipos de seguridad de sistemas afectados'},
            {'priority': 'BAJA',    'action': 'Documentar el incidente y actualizar playbooks de respuesta'},
        ]
    elif verdict == 'suspicious':
        recs = [
            {'priority': 'ALTA',  'action': 'Monitorizar activamente el indicador en todos los sistemas'},
            {'priority': 'ALTA',  'action': 'Revisar conexiones recientes con este IOC en logs de red'},
            {'priority': 'MEDIA', 'action': 'Considerar bloqueo preventivo según política de riesgo'},
            {'priority': 'MEDIA', 'action': 'Solicitar análisis adicional a fuentes externas de inteligencia'},
            {'priority': 'BAJA',  'action': 'Mantener en lista de observación durante 30 días mínimo'},
        ]
    elif verdict == 'clean':
        recs = [
            {'priority': 'BAJA', 'action': 'No se requiere acción inmediata — continuar monitorización estándar'},
            {'priority': 'BAJA', 'action': 'Registrar consulta en base de datos de inteligencia interna'},
            {'priority': 'INFO', 'action': 'Considerar re-análisis periódico ya que el estado puede cambiar'},
        ]
    else:
        recs = [
            {'priority': 'MEDIA', 'action': 'Indicador desconocido — aplicar principio de mínima confianza'},
            {'priority': 'MEDIA', 'action': 'Ampliar investigación con fuentes adicionales (OTX, MISP)'},
            {'priority': 'BAJA',  'action': 'Monitorizar el indicador durante 7 días antes de determinar estado'},
        ]

    if confidence < 40 and verdict != 'clean':
        recs.append({'priority': 'MEDIA', 'action': f'Confianza baja ({confidence}%) — validar con analista humano antes de tomar acción'})

    return recs


def _build_mitre_context(sources: dict) -> dict:
    """Extrae contexto MITRE ATT&CK de los resultados."""
    techniques = []
    vt = sources.get('virustotal', {})
    if vt.get('tags'):
        tag_to_technique = {
            'trojan':      ('T1059', 'Command and Scripting Interpreter'),
            'ransomware':  ('T1486', 'Data Encrypted for Impact'),
            'stealer':     ('T1555', 'Credentials from Password Stores'),
            'backdoor':    ('T1071', 'Application Layer Protocol'),
            'downloader':  ('T1105', 'Ingress Tool Transfer'),
            'dropper':     ('T1027', 'Obfuscated Files or Information'),
            'botnet':      ('T1071', 'Application Layer Protocol'),
            'miner':       ('T1496', 'Resource Hijacking'),
            'rat':         ('T1021', 'Remote Services'),
            'worm':        ('T1091', 'Replication Through Removable Media'),
            'exploit':     ('T1190', 'Exploit Public-Facing Application'),
            'spyware':     ('T1113', 'Screen Capture'),
            'adware':      ('T1176', 'Browser Extensions'),
        }
        for tag in vt.get('tags', []):
            t = tag.lower()
            for keyword, (tid, tname) in tag_to_technique.items():
                if keyword in t:
                    entry = {'id': tid, 'name': tname, 'source': 'VirusTotal tags'}
                    if entry not in techniques:
                        techniques.append(entry)

    mb = sources.get('malwarebazaar', {})
    if mb.get('found') and mb.get('signature'):
        techniques.append({
            'id': 'T1204',
            'name': 'User Execution',
            'source': f"MalwareBazaar: {mb.get('signature','')}"
        })

    ab = sources.get('abuseipdb', {})
    if ab.get('found'):
        cats = ab.get('categories', [])
        cat_map = {
            'SSH':           ('T1110', 'Brute Force'),
            'Brute-Force':   ('T1110', 'Brute Force'),
            'Port Scan':     ('T1046', 'Network Service Discovery'),
            'DDoS Attack':   ('T1499', 'Endpoint Denial of Service'),
            'Phishing':      ('T1566', 'Phishing'),
            'SQL Injection': ('T1190', 'Exploit Public-Facing Application'),
            'Hacking':       ('T1078', 'Valid Accounts'),
        }
        for cat in cats:
            if cat in cat_map:
                entry = {'id': cat_map[cat][0], 'name': cat_map[cat][1], 'source': f'AbuseIPDB: {cat}'}
                if entry not in techniques:
                    techniques.append(entry)

    sh = sources.get('shodan', {})
    if sh.get('vulns'):
        techniques.append({
            'id': 'T1190',
            'name': 'Exploit Public-Facing Application',
            'source': f"Shodan CVEs: {', '.join(sh['vulns'][:3])}"
        })

    return {
        'framework': 'MITRE ATT&CK v14',
        'techniques_identified': techniques,
        'reference': 'https://attack.mitre.org',
    }
