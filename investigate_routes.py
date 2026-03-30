# ============================================================
#  investigate_routes.py
#  Módulo: Consultas Automáticas a Múltiples Fuentes CTI
#  Añadir a app2.py:
#    from investigate_routes import investigate_bp
#    app.register_blueprint(investigate_bp)
# ============================================================

import os, json, re, time, hashlib
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from flask import Blueprint, render_template, request, jsonify

investigate_bp = Blueprint('investigate', __name__)

# ── API KEYS (configura en .env o directamente aquí) ─────────────────────────
VT_KEY       = os.getenv('VIRUSTOTAL_API_KEY',  '')   # VirusTotal v3
ABUSEIPDB_KEY= os.getenv('ABUSEIPDB_API_KEY',   '')   # AbuseIPDB
SHODAN_KEY   = os.getenv('SHODAN_API_KEY',       '')   # Shodan

# ← VERIFICACIÓN DE APIs (se muestra en logs)
print(f"✓ VIRUSTOTAL_API_KEY: {'CONFIGURADA' if VT_KEY else 'NO CONFIGURADA'}")
print(f"✓ ABUSEIPDB_API_KEY: {'CONFIGURADA' if ABUSEIPDB_KEY else 'NO CONFIGURADA'}")
print(f"✓ SHODAN_API_KEY: {'CONFIGURADA' if SHODAN_KEY else 'NO CONFIGURADA'}")

TIMEOUT = 12   # segundos por llamada

# ── DETECCIÓN DE TIPO DE INDICADOR ───────────────────────────────────────────
def detect_ioc_type(value: str) -> str:
    """Detecta automáticamente el tipo de IOC."""
    v = value.strip()
    # Hash
    if re.fullmatch(r'[a-fA-F0-9]{32}',  v): return 'md5'
    if re.fullmatch(r'[a-fA-F0-9]{40}',  v): return 'sha1'
    if re.fullmatch(r'[a-fA-F0-9]{64}',  v): return 'sha256'
    if re.fullmatch(r'[a-fA-F0-9]{128}', v): return 'sha512'
    # IP (básica + IPv6 parcial)
    if re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', v): return 'ip'
    if ':' in v and re.search(r'[0-9a-fA-F]', v): return 'ipv6'
    # URL
    if v.startswith(('http://', 'https://', 'ftp://')): return 'url'
    # Dominio
    if re.fullmatch(r'([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}', v): return 'domain'
    return 'unknown'

def hash_type_label(ioc_type: str) -> str:
    return ioc_type.upper() if ioc_type in ('md5','sha1','sha256','sha512') else ioc_type

# ── VIRUSTOTAL ────────────────────────────────────────────────────────────────
def query_virustotal(value: str, ioc_type: str) -> dict:
    if not VT_KEY:
        return {'source': 'VirusTotal', 'available': False,
                'error': 'API key no configurada (VIRUSTOTAL_API_KEY)'}
    try:
        base = 'https://www.virustotal.com/api/v3'
        headers = {'x-apikey': VT_KEY}

        if ioc_type in ('md5','sha1','sha256','sha512'):
            url = f'{base}/files/{value}'
        elif ioc_type == 'ip':
            url = f'{base}/ip_addresses/{value}'
        elif ioc_type == 'domain':
            url = f'{base}/domains/{value}'
        elif ioc_type == 'url':
            # VT requiere codificar la URL en base64 sin padding
            import base64
            url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip('=')
            url = f'{base}/urls/{url_id}'
        else:
            return {'source': 'VirusTotal', 'available': False,
                    'error': f'Tipo {ioc_type} no soportado'}

        r = requests.get(url, headers=headers, timeout=TIMEOUT)

        if r.status_code == 404:
            return {'source': 'VirusTotal', 'available': True, 'found': False,
                    'message': 'No encontrado en VirusTotal'}
        if r.status_code == 401:
            return {'source': 'VirusTotal', 'available': False,
                    'error': 'API key inválida o expirada'}
        r.raise_for_status()
        data = r.json().get('data', {})
        attrs = data.get('attributes', {})

        # Extraer estadísticas de análisis
        stats = attrs.get('last_analysis_stats', {})
        malicious   = stats.get('malicious', 0)
        suspicious  = stats.get('suspicious', 0)
        undetected  = stats.get('undetected', 0)
        harmless    = stats.get('harmless', 0)
        total       = malicious + suspicious + undetected + harmless

        # Veredicto
        if malicious > 0:
            verdict = 'malicious'
        elif suspicious > 0:
            verdict = 'suspicious'
        elif total > 0:
            verdict = 'clean'
        else:
            verdict = 'unknown'

        # Motores que detectaron
        engines_hit = []
        for engine, result in attrs.get('last_analysis_results', {}).items():
            if result.get('category') in ('malicious','suspicious'):
                engines_hit.append({
                    'engine': engine,
                    'category': result.get('category'),
                    'result': result.get('result', '')
                })

        result_dict = {
            'source':      'VirusTotal',
            'available':   True,
            'found':       True,
            'verdict':     verdict,
            'malicious':   malicious,
            'suspicious':  suspicious,
            'undetected':  undetected,
            'harmless':    harmless,
            'total':       total,
            'engines_hit': engines_hit[:15],  # top 15
            'reputation':  attrs.get('reputation', 0),
            'tags':        attrs.get('tags', []),
            'link':        f'https://www.virustotal.com/gui/{"file" if ioc_type in ("md5","sha1","sha256","sha512") else ioc_type}/{value}'
        }

        # Campos extra según tipo
        if ioc_type in ('md5','sha1','sha256','sha512'):
            result_dict.update({
                'name':       attrs.get('meaningful_name', ''),
                'size':       attrs.get('size', 0),
                'type':       attrs.get('type_description', ''),
                'first_seen': attrs.get('first_submission_date', ''),
                'last_seen':  attrs.get('last_analysis_date', ''),
                'ssdeep':     attrs.get('ssdeep', ''),
            })
        elif ioc_type in ('ip', 'domain'):
            result_dict.update({
                'country':    attrs.get('country', ''),
                'asn':        attrs.get('asn', ''),
                'as_owner':   attrs.get('as_owner', ''),
                'categories': attrs.get('categories', {}),
            })
        return result_dict

    except requests.exceptions.Timeout:
        return {'source': 'VirusTotal', 'available': False, 'error': 'Timeout (>12s)'}
    except Exception as e:
        return {'source': 'VirusTotal', 'available': False, 'error': str(e)}


# ── MALWAREBAZAAR ─────────────────────────────────────────────────────────────
def query_malwarebazaar(value: str, ioc_type: str) -> dict:
    if ioc_type not in ('md5','sha1','sha256','sha512'):
        return {'source': 'MalwareBazaar', 'available': True, 'found': False,
                'message': 'MalwareBazaar solo analiza hashes de malware'}
    try:
        r = requests.post(
            'https://mb-api.abuse.ch/api/v1/',
            data={'query': 'get_info', 'hash': value},
            timeout=TIMEOUT
        )
        r.raise_for_status()
        data = r.json()

        if data.get('query_status') == 'hash_not_found':
            return {'source': 'MalwareBazaar', 'available': True, 'found': False,
                    'message': 'Hash no encontrado en MalwareBazaar'}

        if data.get('query_status') != 'ok':
            return {'source': 'MalwareBazaar', 'available': True, 'found': False,
                    'message': f"Estado: {data.get('query_status')}"}

        info = data['data'][0] if data.get('data') else {}
        return {
            'source':         'MalwareBazaar',
            'available':      True,
            'found':          True,
            'verdict':        'malicious',
            'sha256':         info.get('sha256_hash', ''),
            'sha1':           info.get('sha1_hash', ''),
            'md5':            info.get('md5_hash', ''),
            'file_name':      info.get('file_name', ''),
            'file_size':      info.get('file_size', 0),
            'file_type':      info.get('file_type', ''),
            'mime_type':      info.get('file_type_mime', ''),
            'first_seen':     info.get('first_seen', ''),
            'last_seen':      info.get('last_seen', ''),
            'reporter':       info.get('reporter', ''),
            'origin':         info.get('origin_country', ''),
            'tags':           info.get('tags', []) or [],
            'signature':      info.get('signature', ''),
            'delivery_method':info.get('delivery_method', ''),
            'intelligence':   info.get('intelligence', {}),
            'vendor_intel':   info.get('vendor_intel', {}),
            'link':           f'https://bazaar.abuse.ch/sample/{info.get("sha256_hash","")}'
        }
    except requests.exceptions.Timeout:
        return {'source': 'MalwareBazaar', 'available': False, 'error': 'Timeout (>12s)'}
    except Exception as e:
        return {'source': 'MalwareBazaar', 'available': False, 'error': str(e)}


# ── ABUSEIPDB ─────────────────────────────────────────────────────────────────
def query_abuseipdb(value: str, ioc_type: str) -> dict:
    if ioc_type not in ('ip',):
        return {'source': 'AbuseIPDB', 'available': True, 'found': False,
                'message': 'AbuseIPDB solo analiza direcciones IP'}
    if not ABUSEIPDB_KEY:
        return {'source': 'AbuseIPDB', 'available': False,
                'error': 'API key no configurada (ABUSEIPDB_API_KEY)'}
    try:
        r = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers={'Key': ABUSEIPDB_KEY, 'Accept': 'application/json'},
            params={'ipAddress': value, 'maxAgeInDays': 90, 'verbose': True},
            timeout=TIMEOUT
        )
        r.raise_for_status()
        d = r.json().get('data', {})
        score = d.get('abuseConfidenceScore', 0)
        verdict = 'malicious' if score >= 75 else 'suspicious' if score >= 25 else 'clean'

        reports = d.get('reports', [])[:10]
        categories_map = {
            1:'DNS Compromise', 2:'DNS Poisoning', 3:'Fraud Orders', 4:'DDoS Attack',
            5:'FTP Brute-Force', 6:'Ping of Death', 7:'Phishing', 8:'Fraud VoIP',
            9:'Open Proxy', 10:'Web Spam', 11:'Email Spam', 12:'Blog Spam',
            13:'VPN IP', 14:'Port Scan', 15:'Hacking', 16:'SQL Injection',
            17:'Spoofing', 18:'Brute-Force', 19:'Bad Web Bot', 20:'Exploited Host',
            21:'Web App Attack', 22:'SSH', 23:'IoT Targeted'
        }
        # Categorías únicas de todos los reportes
        seen_cats = set()
        for rep in d.get('reports', []):
            for c in rep.get('categories', []):
                seen_cats.add(categories_map.get(c, f'Cat-{c}'))

        return {
            'source':             'AbuseIPDB',
            'available':          True,
            'found':              True,
            'verdict':            verdict,
            'abuse_score':        score,
            'country':            d.get('countryCode', ''),
            'usage_type':         d.get('usageType', ''),
            'isp':                d.get('isp', ''),
            'domain':             d.get('domain', ''),
            'is_tor':             d.get('isTor', False),
            'is_vpn':             d.get('isWhitelisted', False),
            'total_reports':      d.get('totalReports', 0),
            'distinct_users':     d.get('numDistinctUsers', 0),
            'last_reported':      d.get('lastReportedAt', ''),
            'categories':         list(seen_cats),
            'recent_reports':     [
                {
                    'reported_at': rep.get('reportedAt',''),
                    'comment':     (rep.get('comment','') or '')[:120],
                    'categories':  [categories_map.get(c, str(c)) for c in rep.get('categories',[])]
                } for rep in reports
            ],
            'link': f'https://www.abuseipdb.com/check/{value}'
        }
    except requests.exceptions.Timeout:
        return {'source': 'AbuseIPDB', 'available': False, 'error': 'Timeout (>12s)'}
    except Exception as e:
        return {'source': 'AbuseIPDB', 'available': False, 'error': str(e)}


# ── SHODAN ────────────────────────────────────────────────────────────────────
def query_shodan(value: str, ioc_type: str) -> dict:
    if ioc_type not in ('ip',):
        return {'source': 'Shodan', 'available': True, 'found': False,
                'message': 'Shodan solo analiza direcciones IP'}
    if not SHODAN_KEY:
        return {'source': 'Shodan', 'available': False,
                'error': 'API key no configurada (SHODAN_API_KEY)'}
    try:
        r = requests.get(
            f'https://api.shodan.io/shodan/host/{value}',
            params={'key': SHODAN_KEY},
            timeout=TIMEOUT
        )
        if r.status_code == 404:
            return {'source': 'Shodan', 'available': True, 'found': False,
                    'message': 'IP no encontrada en índice Shodan'}
        r.raise_for_status()
        d = r.json()

        ports   = d.get('ports', [])
        vulns   = list(d.get('vulns', {}).keys())
        hostnames = d.get('hostnames', [])

        # Extraer servicios de los banners
        services = []
        for item in d.get('data', [])[:10]:
            svc = {
                'port':      item.get('port'),
                'transport': item.get('transport','tcp'),
                'product':   item.get('product',''),
                'version':   item.get('version',''),
                'banner':    (item.get('data','') or '')[:150].strip()
            }
            if item.get('ssl'):
                svc['ssl'] = True
                cert = item.get('ssl',{}).get('cert',{})
                svc['cert_subject'] = str(cert.get('subject',{}))
            services.append(svc)

        return {
            'source':       'Shodan',
            'available':    True,
            'found':        True,
            'verdict':      'malicious' if vulns else 'unknown',
            'ip':           d.get('ip_str',''),
            'org':          d.get('org',''),
            'isp':          d.get('isp',''),
            'asn':          d.get('asn',''),
            'country':      d.get('country_name',''),
            'country_code': d.get('country_code',''),
            'city':         d.get('city',''),
            'os':           d.get('os',''),
            'hostnames':    hostnames[:5],
            'domains':      d.get('domains', [])[:5],
            'ports':        ports[:20],
            'services':     services,
            'vulns':        vulns[:10],
            'tags':         d.get('tags', []),
            'last_update':  d.get('last_update',''),
            'total_ports':  len(ports),
            'total_vulns':  len(vulns),
            'link':         f'https://www.shodan.io/host/{value}'
        }
    except requests.exceptions.Timeout:
        return {'source': 'Shodan', 'available': False, 'error': 'Timeout (>12s)'}
    except Exception as e:
        return {'source': 'Shodan', 'available': False, 'error': str(e)}


# ── MOTOR DE CORRELACIÓN ──────────────────────────────────────────────────────
def correlate_results(results: list, ioc_type: str, value: str) -> dict:
    """
    Cruza los resultados de todas las fuentes y genera:
    - Veredicto global consolidado
    - Score de confianza 0-100
    - Lista de hallazgos críticos
    - Tags únicos
    - Resumen ejecutivo
    """
    verdict_weight = {'malicious': 3, 'suspicious': 2, 'clean': 0, 'unknown': 0}
    total_weight   = 0
    max_weight     = 0
    sources_found  = 0
    all_tags       = set()
    findings       = []

    for r in results:
        if not r.get('available') or not r.get('found'):
            continue
        sources_found += 1
        v = r.get('verdict', 'unknown')
        w = verdict_weight.get(v, 0)
        total_weight += w
        max_weight   += 3  # máximo posible por fuente

        # Recopilar tags
        for tag in r.get('tags', []):
            if tag: all_tags.add(str(tag).lower())

        # Hallazgos específicos
        src = r['source']
        if src == 'VirusTotal' and r.get('malicious', 0) > 0:
            findings.append({
                'severity': 'critical',
                'source': src,
                'text': f"{r['malicious']}/{r.get('total',0)} motores antivirus detectaron amenaza",
                'detail': ', '.join(e['engine'] for e in r.get('engines_hit',[])[:5])
            })
        if src == 'MalwareBazaar' and r.get('found'):
            sig = r.get('signature','') or r.get('file_type','')
            findings.append({
                'severity': 'critical',
                'source': src,
                'text': f"Muestra de malware confirmada: {sig or 'familia desconocida'}",
                'detail': f"Reportado por: {r.get('reporter','')} · {r.get('first_seen','')}"
            })
        if src == 'AbuseIPDB':
            score = r.get('abuse_score', 0)
            if score > 0:
                sev = 'critical' if score >= 75 else 'high' if score >= 50 else 'medium'
                findings.append({
                    'severity': sev,
                    'source': src,
                    'text': f"IP reportada como abusiva — Score: {score}/100",
                    'detail': f"{r.get('total_reports',0)} reportes de {r.get('distinct_users',0)} usuarios · {', '.join(r.get('categories',[])[:3])}"
                })
        if src == 'Shodan':
            if r.get('vulns'):
                findings.append({
                    'severity': 'high',
                    'source': src,
                    'text': f"{len(r['vulns'])} CVE(s) detectados en host",
                    'detail': ', '.join(r['vulns'][:5])
                })
            if r.get('ports'):
                findings.append({
                    'severity': 'info',
                    'source': src,
                    'text': f"{r.get('total_ports',0)} puertos abiertos identificados",
                    'detail': ', '.join(str(p) for p in r.get('ports',[])[:8])
                })

    # Score de confianza
    confidence = round((total_weight / max_weight * 100) if max_weight > 0 else 0)

    # Veredicto global
    if total_weight >= max_weight * 0.6:
        global_verdict = 'malicious'
    elif total_weight >= max_weight * 0.25:
        global_verdict = 'suspicious'
    elif sources_found > 0 and total_weight == 0:
        global_verdict = 'clean'
    else:
        global_verdict = 'unknown'

    # Resumen ejecutivo
    def _summary():
        if global_verdict == 'malicious':
            return (f"El indicador '{value}' ha sido identificado como MALICIOSO con una confianza del "
                    f"{confidence}%. Múltiples fuentes de inteligencia confirman actividad maliciosa. "
                    f"Se recomienda bloquear inmediatamente y escalar al equipo de respuesta a incidentes.")
        elif global_verdict == 'suspicious':
            return (f"El indicador '{value}' presenta actividad SOSPECHOSA (confianza: {confidence}%). "
                    f"Al menos una fuente reporta comportamiento anómalo. "
                    f"Se recomienda investigación adicional antes de tomar acción.")
        elif global_verdict == 'clean':
            return (f"El indicador '{value}' no presenta evidencia de actividad maliciosa en las fuentes consultadas. "
                    f"Esto no garantiza que sea seguro; las fuentes tienen cobertura limitada.")
        else:
            return (f"No se encontró información suficiente sobre '{value}' en las fuentes consultadas. "
                    f"El indicador puede ser nuevo o desconocido para las bases de datos actuales.")

    return {
        'global_verdict':   global_verdict,
        'confidence':       confidence,
        'sources_consulted': len(results),
        'sources_found':    sources_found,
        'findings':         sorted(findings, key=lambda x: {'critical':0,'high':1,'medium':2,'info':3}.get(x['severity'],4)),
        'tags':             sorted(list(all_tags))[:20],
        'summary':          _summary(),
        'ioc_type':         ioc_type,
        'ioc_type_label':   hash_type_label(ioc_type),
        'timestamp':        datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    }


# ── RUTAS FLASK ───────────────────────────────────────────────────────────────
@investigate_bp.route('/investigate')
def investigate_page():
    """Página principal del módulo de investigación."""
    return render_template('investigate.html')


@investigate_bp.route('/api/investigate', methods=['POST'])
def api_investigate():
    """
    POST JSON: { "ioc": "8.8.8.8" }
    Consulta todas las fuentes en paralelo y devuelve resultados correlacionados.
    """
    body = request.get_json(silent=True) or {}
    ioc  = (body.get('ioc') or '').strip()

    if not ioc:
        return jsonify({'success': False, 'error': 'Debes proporcionar un indicador (IOC)'}), 400

    ioc_type = detect_ioc_type(ioc)
    if ioc_type == 'unknown':
        return jsonify({'success': False,
                        'error': 'Tipo de indicador no reconocido. Acepta: IPs, dominios, URLs, hashes MD5/SHA1/SHA256/SHA512'}), 400

    start_time = time.time()

    # Ejecutar consultas en paralelo
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

    results_list = list(source_results.values())
    correlation  = correlate_results(results_list, ioc_type, ioc)
    elapsed      = round(time.time() - start_time, 2)

    return jsonify({
        'success':     True,
        'ioc':         ioc,
        'ioc_type':    ioc_type,
        'elapsed':     elapsed,
        'correlation': correlation,
        'sources':     source_results
    })


@investigate_bp.route('/api/investigate/batch', methods=['POST'])
def api_investigate_batch():
    """
    POST JSON: { "iocs": ["8.8.8.8", "1.1.1.1", "abc123..."] }
    Procesa hasta 10 IOCs en secuencia (para no saturar las APIs).
    """
    body = request.get_json(silent=True) or {}
    iocs = body.get('iocs', [])
    if not iocs or not isinstance(iocs, list):
        return jsonify({'success': False, 'error': 'Proporciona una lista "iocs"'}), 400
    iocs = [str(i).strip() for i in iocs if str(i).strip()][:10]

    results = []
    for ioc in iocs:
        ioc_type = detect_ioc_type(ioc)
        if ioc_type == 'unknown':
            results.append({'ioc': ioc, 'error': 'Tipo no reconocido'})
            continue
        tasks = {
            'virustotal':    lambda i=ioc, t=ioc_type: query_virustotal(i, t),
            'malwarebazaar': lambda i=ioc, t=ioc_type: query_malwarebazaar(i, t),
            'abuseipdb':     lambda i=ioc, t=ioc_type: query_abuseipdb(i, t),
            'shodan':        lambda i=ioc, t=ioc_type: query_shodan(i, t),
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

        corr = correlate_results(list(source_results.values()), ioc_type, ioc)
        results.append({
            'ioc':         ioc,
            'ioc_type':    ioc_type,
            'correlation': corr,
            'sources':     source_results
        })
        time.sleep(0.5)  # respeto de rate limits

    return jsonify({'success': True, 'results': results, 'count': len(results)})