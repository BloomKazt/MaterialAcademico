import os
import time
import json
import requests
import logging
from flask import Flask, send_from_directory, jsonify, render_template_string
from flask_compress import Compress

# ----------------------------
# CONFIGURACIÓN
# ----------------------------

CACHE_FOLDER = "cache"
REMOTE_SERVER = "https://raw.githubusercontent.com/educational-content/demo/main/"
MANIFEST_URL = REMOTE_SERVER + "manifest.json"
TTL_SECONDS = 60 * 60 * 24 * 7      # 7 días
CACHE_LIMIT_MB = 100               # 100 MB de cache
PREFETCH_FILES = ["Taller1.pdf", "Imagen1.png"]

# ----------------------------
# INICIALIZACIONES
# ----------------------------

app = Flask(__name__)
Compress(app)
os.makedirs(CACHE_FOLDER, exist_ok=True)

logging.basicConfig(filename="cdn.log", level=logging.INFO,
                    format="%(asctime)s - %(message)s")


# ----------------------------
# FUNCIONES DE UTILIDAD
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
        files.append((path, os.path.getmtime(path)))

    # Ordenar por archivo más viejo primero
    files.sort(key=lambda x: x[1])

    while get_cache_size_mb() > CACHE_LIMIT_MB:
        oldest = files.pop(0)[0]
        logging.info(f"Eliminando archivo por límite de cache: {oldest}")
        os.remove(oldest)


def download_manifest():
    try:
        r = requests.get(MANIFEST_URL, timeout=5)
        if r.status_code == 200:
            return r.json()
    except:
        return None
    return None


def is_expired(local_path):
    """Revisa si el archivo excede el TTL."""
    age = time.time() - os.path.getmtime(local_path)
    return age > TTL_SECONDS


def download_file(filename):
    """Descarga un archivo del servidor remoto."""
    remote_url = REMOTE_SERVER + filename

    try:
        r = requests.get(remote_url, timeout=5)
        if r.status_code != 200:
            return None

        local_path = os.path.join(CACHE_FOLDER, filename)
        with open(local_path, "wb") as f:
            f.write(r.content)

        logging.info(f"Descargado {filename} desde remoto")
        enforce_cache_limit()
        return local_path

    except Exception as e:
        logging.error(f"Error descargando {filename}: {e}")
        return None


def prefetch_files():
    """Descarga archivos importantes al iniciar."""
    for f in PREFETCH_FILES:
        if not os.path.exists(os.path.join(CACHE_FOLDER, f)):
            download_file(f)


# ----------------------------
# RUTAS
# ----------------------------

@app.route("/")
def index():
    files = os.listdir(CACHE_FOLDER)
    html = """
    <h1>Mini-CDN Educativo</h1>
    <p>Servidor funcionando correctamente.</p>
    
    <h2>Archivos en caché:</h2>
    <ul>
    {% for f in files %}
        <li><a href="/content/{{f}}">{{f}}</a></li>
    {% endfor %}
    </ul>

    <h2>Descargar archivo nuevo:</h2>
    <form action="/content" method="get">
        <input name="filename" placeholder="ej: guia1.pdf">
        <button type="submit">Descargar</button>
    </form>
    """

    return render_template_string(html, files=files)


@app.route("/content", methods=["GET"])
def content_form():
    from flask import request
    filename = request.args.get("filename")
    return get_content(filename)


@app.route("/content/<path:filename>")
def get_content(filename):
    manifest = download_manifest()
    local_path = os.path.join(CACHE_FOLDER, filename)

    # ----------------------------
    # 1. Si el archivo existe en cache
    # ----------------------------
    if os.path.exists(local_path):

        # Revisar versión con manifest
        if manifest and filename in manifest:
            version_file = local_path + ".version"
            current_version = None

            if os.path.exists(version_file):
                with open(version_file, "r") as v:
                    current_version = v.read().strip()

            if current_version != manifest[filename]:
                logging.info(f"Actualizando {filename} por cambio de versión")
                download_file(filename)
                with open(version_file, "w") as v:
                    v.write(manifest[filename])

        # Revisar expiración
        elif is_expired(local_path):
            logging.info(f"Archivo expirado: {filename}, actualizando")
            download_file(filename)

        logging.info(f"Servido desde cache: {filename}")
        return send_from_directory(CACHE_FOLDER, filename)

    # ----------------------------
    # 2. Si no existe, descargarlo
    # ----------------------------
    new_file = download_file(filename)
    if not new_file:
        return jsonify({"error": "Archivo no disponible"}), 404

    # Guardar versión
    if manifest and filename in manifest:
        with open(new_file + ".version", "w") as v:
            v.write(manifest[filename])

    return send_from_directory(CACHE_FOLDER, filename)


# ----------------------------
# INICIO DEL SERVIDOR
# ----------------------------

if __name__ == "__main__":
    prefetch_files()

    app.run(host="0.0.0.0", port=5000)
