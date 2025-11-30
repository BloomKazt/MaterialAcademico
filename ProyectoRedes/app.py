#!/usr/bin/env python3
"""
Mini-CDN Educativo — versión ampliada
Mejoras incluidas:
 - Métricas Prometheus (/metrics)
 - Contadores y histograma de latencia
 - Logs estructurados en JSON (cdn.log) para Wazuh/Elastic
 - Endpoint /status con estado del cache y últimas entradas de log
 - Arranque opcional de captura pcap (tcpdump) para análisis en Wireshark
 - Zeek-style lightweight logging (http_zeek.log)
 - Escritura de archivo de reglas Suricata de ejemplo (suricata_rules.rules)
 - Prefetch, TTL, límite de cache, manifest remoto (como antes)
NOTA: instalar dependencias:
 pip install flask flask_compress requests prometheus_client python-json-logger flask-limiter
 tcpdump debe estar presente en el sistema para la captura pcap automática.
"""

import os
import time
import json
import requests
import logging
import subprocess
import signal
from threading import Thread
from flask import Flask, send_from_directory, jsonify, render_template_string, request, abort
from flask_compress import Compress

# Prometheus
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

# JSON logging
from pythonjsonlogger import jsonlogger

# ----------------------------
# CONFIGURACIÓN
# ----------------------------

CACHE_FOLDER = "cache"
REMOTE_SERVER = "https://raw.githubusercontent.com/BloomKazt/MaterialAcademico/main/ProyectoRedes/Material/"
MANIFEST_URL = REMOTE_SERVER + "manifest.json"

TTL_SECONDS = 60 * 60 * 24 * 7      # 7 días
CACHE_LIMIT_MB = 100                # 100 MB
PREFETCH_FILES = ["Taller1.pdf", "Imagen1.png"]

# Control pcap
ENABLE_PCAP_CAPTURE = True         # Cambia a False si no quieres capturar
PCAP_FILENAME = "cdn_traffic.pcap"
PCAP_INTERFACE = "any"             # "any" o interfaz específica
PCAP_FILTER = "port 5000"

# Suricata rules filename
SURICATA_RULES_FILE = "suricata_rules.rules"

# ----------------------------
# INICIALIZACIONES
# ----------------------------

app = Flask(__name__)
Compress(app)
os.makedirs(CACHE_FOLDER, exist_ok=True)

# -------------
# Logger JSON
# -------------
log_handler = logging.FileHandler("cdn.log")
log_formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(name)s %(message)s')
log_handler.setFormatter(log_formatter)

logger = logging.getLogger("mini_cdn")
logger.setLevel(logging.INFO)
# Evitar handlers duplicados si se ejecuta varias veces en entorno interactivo
if not logger.hasHandlers():
    logger.addHandler(log_handler)
# También loguear errores en stderr
stderr_handler = logging.StreamHandler()
stderr_handler.setFormatter(log_formatter)
logger.addHandler(stderr_handler)

# ----------------------------
# METRICAS PROMETHEUS
# ----------------------------
REQUEST_COUNT = Counter("cdn_requests_total", "Número de solicitudes recibidas", ["endpoint", "code"])
CACHE_HITS = Counter("cdn_cache_hits_total", "Archivos servidos desde cache")
CACHE_MISSES = Counter("cdn_cache_miss_total", "Archivos descargados desde servidor remoto")
REQUEST_LATENCY = Histogram("cdn_request_latency_seconds", "Latencia de respuesta", ["endpoint"])

# ----------------------------
# UTILIDADES
# ----------------------------

def get_cache_size_mb():
    total = 0
    for root, dirs, files in os.walk(CACHE_FOLDER):
        for f in files:
            total += os.path.getsize(os.path.join(root, f))
    return total / (1024 * 1024)


def enforce_cache_limit():
    """Borra archivos viejos si el cache supera el límite."""
    size = get_cache_size_mb()
    if size <= CACHE_LIMIT_MB:
        return

    files = []
    for f in os.listdir(CACHE_FOLDER):
        path = os.path.join(CACHE_FOLDER, f)
        if os.path.isfile(path):
            files.append((path, os.path.getmtime(path)))

    files.sort(key=lambda x: x[1])  # más viejo primero

    while get_cache_size_mb() > CACHE_LIMIT_MB and files:
        oldest = files.pop(0)[0]
        logger.info(json.dumps({
            "event": "cache_prune",
            "file": oldest,
            "reason": "cache_limit"
        }))
        try:
            os.remove(oldest)
        except Exception as e:
            logger.error(json.dumps({
                "event": "prune_error",
                "file": oldest,
                "error": str(e)
            }))


def download_manifest():
    try:
        r = requests.get(MANIFEST_URL, timeout=5)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        logger.warning(json.dumps({"event": "manifest_error", "error": str(e)}))
        return None
    return None


def is_expired(local_path):
    """Revisa si el archivo excede el TTL."""
    try:
        age = time.time() - os.path.getmtime(local_path)
        return age > TTL_SECONDS
    except Exception:
        return True


def download_file(filename):
    """Descarga un archivo del servidor remoto."""
    remote_url = REMOTE_SERVER + filename

    try:
        r = requests.get(remote_url, timeout=10, stream=True)
        if r.status_code != 200:
            logger.warning(json.dumps({"event": "remote_not_200", "file": filename, "status": r.status_code}))
            return None

        local_path = os.path.join(CACHE_FOLDER, filename)
        os.makedirs(os.path.dirname(local_path) or ".", exist_ok=True)
        with open(local_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)

        logger.info(json.dumps({"event": "downloaded", "file": filename, "from": remote_url}))
        enforce_cache_limit()
        return local_path

    except Exception as e:
        logger.error(json.dumps({"event": "download_error", "file": filename, "error": str(e)}))
        return None


def prefetch_files():
    for f in PREFETCH_FILES:
        if not os.path.exists(os.path.join(CACHE_FOLDER, f)):
            download_file(f)


# ----------------------------
# ZE E K-STYLE Y SURICATA
# ----------------------------

ZEEK_LOG = "http_zeek.log"

def zeek_style_log(method, uri, status, size=None):
    """
    Escribe un log simple estilo Zeek para correlacionar con capturas pcap.
    Formato: timestamp \t method \t uri \t status \t client_ip \t bytes
    """
    try:
        with open(ZEEK_LOG, "a") as z:
            line = f"{time.time()}\t{method}\t{uri}\t{status}\t{request.remote_addr}\t{size or '-'}\n"
            z.write(line)
    except Exception as e:
        logger.error(json.dumps({"event": "zeek_log_error", "error": str(e)}))


def write_suricata_rules():
    """Escribe un archivo de reglas de Suricata de ejemplo (educativo)."""
    rules = [
        'alert http any any -> any any (msg:"Descarga .exe detectada"; http_uri; pcre:"/\\.exe$/i"; sid:10001; rev:1;)',
        'alert http any any -> any any (msg:"Posible intento de path traversal"; http_uri; content:"../"; sid:10002; rev:1;)',
        'alert http any any -> any any (msg:"Alta tasa de solicitudes (ejemplo educativo)"; flow:to_server,established; detection_filter:track by_src, count 100, seconds 1; sid:10003; rev:1;)'
    ]
    try:
        with open(SURICATA_RULES_FILE, "w") as s:
            s.write("\n".join(rules) + "\n")
        logger.info(json.dumps({"event": "suricata_rules_written", "file": SURICATA_RULES_FILE}))
    except Exception as e:
        logger.error(json.dumps({"event": "suricata_write_error", "error": str(e)}))


# ----------------------------
# PCAP CAPTURE
# ----------------------------

pcap_process = None

def start_pcap_capture():
    """Intenta iniciar tcpdump en background. Requiere tcpdump instalado y permisos."""
    global pcap_process
    if not ENABLE_PCAP_CAPTURE:
        logger.info(json.dumps({"event": "pcap_disabled"}))
        return

    cmd = ["tcpdump", "-i", PCAP_INTERFACE, PCAP_FILTER, "-w", PCAP_FILENAME]
    try:
        # Spawn in a thread to avoid bloquear el arranque si tcpdump pide permisos
        def target():
            global pcap_process
            try:
                pcap_process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
                logger.info(json.dumps({"event": "pcap_started", "cmd": " ".join(cmd), "pid": pcap_process.pid}))
                pcap_process.wait()
            except FileNotFoundError:
                logger.error(json.dumps({"event": "tcpdump_missing", "error": "tcpdump no encontrado"}))
            except Exception as e:
                logger.error(json.dumps({"event": "pcap_error", "error": str(e)}))

        Thread(target=target, daemon=True).start()
    except Exception as e:
        logger.error(json.dumps({"event": "pcap_spawn_error", "error": str(e)}))


def stop_pcap_capture():
    """Intenta detener la captura pcap si está corriendo."""
    global pcap_process
    try:
        if pcap_process and pcap_process.poll() is None:
            os.killpg(os.getpgid(pcap_process.pid), signal.SIGTERM)
            logger.info(json.dumps({"event": "pcap_stopped", "pid": pcap_process.pid}))
    except Exception as e:
        logger.error(json.dumps({"event": "pcap_stop_error", "error": str(e)}))


# ----------------------------
# RUTAS WEB
# ----------------------------

@app.route("/")
def index():
    files = os.listdir(CACHE_FOLDER)

    html = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Mini-CDN Educativo</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f6f9; margin: 0; padding: 0; }
        header { background: #34495e; color: white; padding: 20px; text-align: center; font-size: 28px; font-weight: bold; }
        .container { width: 90%; max-width: 900px; margin: 30px auto; }
        .card { background: white; padding: 20px; border-radius: 12px; box-shadow: 0px 4px 12px rgba(0,0,0,0.1); margin-bottom: 25px; }
        h2 { color: #2c3e50; margin-bottom: 12px; }
        ul { list-style: none; padding-left: 0; }
        li { padding: 8px; margin-bottom: 5px; background: #ecf0f1; border-radius: 6px; transition: 0.2s; }
        li:hover { background: #dfe6e9; }
        a { text-decoration: none; color: #2980b9; font-weight: bold; }
        .input-box { margin-top: 15px; display: flex; gap: 10px; }
        input { flex: 1; padding: 10px; border-radius: 6px; border: 1px solid #bdc3c7; font-size: 14px; }
        button { background: #2980b9; border: none; padding: 10px 15px; color: white; border-radius: 6px; cursor: pointer; font-size: 14px; transition: .2s; }
        button:hover { background: #1f6391; }
        .small { font-size: 12px; color: #7f8c8d; }
    </style>
</head>
<body>

<header>Mini-CDN Educativo — (monitoreo & análisis de red)</header>

<div class="container">

    <div class="card">
        <h2>Archivos en caché</h2>
        <p class="small">Tamaño caché: {{ cache_size_mb }} MB — Archivos: {{ num_files }}</p>
        <ul>
            {% if files %}
                {% for f in files %}
                    <li><a href="/content/{{f}}">{{ f }}</a></li>
                {% endfor %}
            {% else %}
                <p>No hay archivos aún.</p>
            {% endif %}
        </ul>
    </div>

    <div class="card">
        <h2>Descargar archivo del repositorio</h2>
        <form action="/content" method="get">
            <div class="input-box">
                <input name="filename" placeholder="Ejemplo: Taller1.pdf" required>
                <button type="submit">Descargar</button>
            </div>
        </form>
    </div>

    <div class="card">
        <h2>Enlaces útiles</h2>
        <ul>
            <li><a href="/metrics">/metrics (Prometheus)</a></li>
            <li><a href="/status">/status (estado del servicio)</a></li>
            <li><a href="/logs/last">/logs/last (últimas 50 líneas de cdn.log)</a></li>
            <li><a href="/zeeklog">/zeeklog (http_zeek.log)</a></li>
        </ul>
    </div>

</div>

</body>
</html>
    """
    cache_size = round(get_cache_size_mb(), 2)
    num_files = len([f for f in os.listdir(CACHE_FOLDER) if os.path.isfile(os.path.join(CACHE_FOLDER, f))])
    return render_template_string(html, files=files, cache_size_mb=cache_size, num_files=num_files)


@app.route("/content", methods=["GET"])
def content_form():
    filename = request.args.get("filename")
    if not filename:
        return jsonify({"error": "Se requiere 'filename'"}), 400
    return get_content(filename)


@app.route("/content/<path:filename>", methods=["GET"])
def get_content(filename):
    """
    Punto central que sirve archivos desde cache o remoto.
    Incluye métricas y logging estructurado + zeek-style log.
    """
    start_time = time.time()
    endpoint = "/content"
    REQUEST_COUNT.labels(endpoint=endpoint, code="0").inc()  # código real actualizado al final

    manifest = download_manifest()
    local_path = os.path.join(CACHE_FOLDER, filename)

    # --- 1. Archivo en cache ---
    try:
        if os.path.exists(local_path):

            # Comparar versión con manifest
            if manifest and filename in manifest:
                version_file = local_path + ".version"
                current_version = None

                if os.path.exists(version_file):
                    with open(version_file, "r") as v:
                        current_version = v.read().strip()

                if current_version != manifest[filename]:
                    logger.info(json.dumps({"event": "version_mismatch", "file": filename, "remote_version": manifest[filename], "local_version": current_version}))
                    download_file(filename)
                    with open(version_file, "w") as v:
                        v.write(manifest[filename])

            # TTL expirado
            elif is_expired(local_path):
                logger.info(json.dumps({"event": "expired", "file": filename}))
                download_file(filename)

            CACHE_HITS.inc()
            REQUEST_COUNT.labels(endpoint=endpoint, code="200").inc()
            elapsed = time.time() - start_time
            REQUEST_LATENCY.labels(endpoint=endpoint).observe(elapsed)

            # Zeek-style log
            zeek_style_log(request.method, request.path, 200, os.path.getsize(local_path) if os.path.exists(local_path) else None)

            logger.info(json.dumps({
                "event": "served_from_cache",
                "file": filename,
                "client_ip": request.remote_addr,
                "size": os.path.getsize(local_path) if os.path.exists(local_path) else None,
                "latency_s": elapsed
            }))

            return send_from_directory(CACHE_FOLDER, filename)
    except Exception as e:
        logger.error(json.dumps({"event": "serve_cache_error", "file": filename, "error": str(e)}))

    # --- 2. Descargar si no está ---
    new_file = download_file(filename)
    if not new_file:
        REQUEST_COUNT.labels(endpoint=endpoint, code="404").inc()
        elapsed = time.time() - start_time
        REQUEST_LATENCY.labels(endpoint=endpoint).observe(elapsed)
        zeek_style_log(request.method, request.path, 404, 0)
        logger.warning(json.dumps({"event": "file_missing", "file": filename, "client_ip": request.remote_addr}))
        return jsonify({"error": "Archivo no disponible"}), 404

    # Guardar versión del manifest
    try:
        if manifest and filename in manifest:
            with open(new_file + ".version", "w") as v:
                v.write(manifest[filename])
    except Exception as e:
        logger.error(json.dumps({"event": "write_version_error", "file": filename, "error": str(e)}))

    CACHE_MISSES.inc()
    REQUEST_COUNT.labels(endpoint=endpoint, code="200").inc()
    elapsed = time.time() - start_time
    REQUEST_LATENCY.labels(endpoint=endpoint).observe(elapsed)
    zeek_style_log(request.method, request.path, 200, os.path.getsize(new_file) if os.path.exists(new_file) else None)

    logger.info(json.dumps({
        "event": "download_then_serve",
        "file": filename,
        "client_ip": request.remote_addr,
        "size": os.path.getsize(new_file) if os.path.exists(new_file) else None,
        "latency_s": elapsed
    }))

    return send_from_directory(CACHE_FOLDER, filename)


@app.route("/metrics")
def metrics():
    """Endpoint para Prometheus."""
    resp = generate_latest()
    return resp, 200, {"Content-Type": CONTENT_TYPE_LATEST}


@app.route("/status")
def status_page():
    """JSON con estado básico del servicio (útil para dashboards)."""
    cache_size = round(get_cache_size_mb(), 2)
    num_files = len([f for f in os.listdir(CACHE_FOLDER) if os.path.isfile(os.path.join(CACHE_FOLDER, f))])
    last_logs = get_last_log_entries(20)
    return jsonify({
        "cache_size_mb": cache_size,
        "cached_files": num_files,
        "pcap_enabled": ENABLE_PCAP_CAPTURE,
        "pcap_file": PCAP_FILENAME if ENABLE_PCAP_CAPTURE else None,
        "last_logs": last_logs
    })


@app.route("/logs/last")
def logs_last():
    """Devuelve últimas N líneas del cdn.log (puro texto)."""
    lines = get_last_log_entries(50)
    return jsonify({"last_lines": lines})


@app.route("/zeeklog")
def zeeklog():
    """Descarga el log estilo Zeek (http_zeek.log) si existe."""
    if os.path.exists(ZEEK_LOG):
        return send_from_directory(".", ZEEK_LOG)
    else:
        return jsonify({"error": "Zeek log no existe aún"}), 404


# ----------------------------
# UTIL: leer últimas líneas de un archivo (efficiente-ish)
# ----------------------------
def get_last_log_entries(n=50, logfile="cdn.log"):
    try:
        if not os.path.exists(logfile):
            return []
        with open(logfile, "rb") as f:
            # Leer desde el final en bloques
            f.seek(0, os.SEEK_END)
            filesize = f.tell()
            block_size = 1024
            blocks = []
            if filesize == 0:
                return []
            remaining = filesize
            while remaining > 0 and len(blocks) < n * 2:
                read_size = min(block_size, remaining)
                f.seek(remaining - read_size)
                block = f.read(read_size)
                blocks.append(block)
                remaining -= read_size
            content = b"".join(reversed(blocks)).decode(errors="ignore")
            lines = content.splitlines()
            return lines[-n:]
    except Exception as e:
        logger.error(json.dumps({"event": "read_log_error", "error": str(e)}))
        return []


# ----------------------------
# INICIO
# ----------------------------

if __name__ == "__main__":
    # Crear archivo de reglas de Suricata (ejemplo educativo)
    write_suricata_rules()

    # Prefetch inicial
    prefetch_files()

    # Arrancar captura pcap (si está habilitada)
    start_pcap_capture()

    try:
        # Ejecutar Flask
        app.run(host="0.0.0.0", port=5000)
    finally:
        # Intentar limpiar captura pcap al terminar
        stop_pcap_capture()
