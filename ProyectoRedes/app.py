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

# *** RUTA CORRECTA: ¡IMPORTANTE! ***
REMOTE_SERVER = "https://raw.githubusercontent.com/BloomKazt/MaterialAcademico/main/ProyectoRedes/Material/"  
MANIFEST_URL = REMOTE_SERVER + "manifest.json"

TTL_SECONDS = 60 * 60 * 24 * 7      # 7 días
CACHE_LIMIT_MB = 100               # 100 MB
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
        files.append((path, os.path.getmtime(path)))

    files.sort(key=lambda x: x[1])  # más viejo primero

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
    for f in PREFETCH_FILES:
        if not os.path.exists(os.path.join(CACHE_FOLDER, f)):
            download_file(f)


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
        body {
            font-family: Arial, sans-serif;
            background: #f4f6f9;
            margin: 0;
            padding: 0;
        }

        header {
            background: #34495e;
            color: white;
            padding: 20px;
            text-align: center;
            font-size: 28px;
            font-weight: bold;
        }

        .container {
            width: 90%;
            max-width: 900px;
            margin: 30px auto;
        }

        .card {
            background: white;
            padding: 20px;
            border-radius: 12px;
            box-shadow: 0px 4px 12px rgba(0,0,0,0.1);
            margin-bottom: 25px;
        }

        h2 {
            color: #2c3e50;
            margin-bottom: 12px;
        }

        ul {
            list-style: none;
            padding-left: 0;
        }

        li {
            padding: 8px;
            margin-bottom: 5px;
            background: #ecf0f1;
            border-radius: 6px;
            transition: 0.2s;
        }

        li:hover {
            background: #dfe6e9;
        }

        a {
            text-decoration: none;
            color: #2980b9;
            font-weight: bold;
        }

        .input-box {
            margin-top: 15px;
            display: flex;
            gap: 10px;
        }

        input {
            flex: 1;
            padding: 10px;
            border-radius: 6px;
            border: 1px solid #bdc3c7;
            font-size: 14px;
        }

        button {
            background: #2980b9;
            border: none;
            padding: 10px 15px;
            color: white;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            transition: .2s;
        }

        button:hover {
            background: #1f6391;
        }
    </style>
</head>
<body>

<header>Mini-CDN Educativo</header>

<div class="container">

    <div class="card">
        <h2>Archivos en caché</h2>
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

</div>

</body>
</html>
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

    # --- 1. Archivo en cache ---
    if os.path.exists(local_path):

        # Comparar versión con manifest
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

        # TTL expirado
        elif is_expired(local_path):
            logging.info(f"Archivo expirado: {filename}, actualizando")
            download_file(filename)

        logging.info(f"Servido desde cache: {filename}")
        return send_from_directory(CACHE_FOLDER, filename)

    # --- 2. Descargar si no está ---
    new_file = download_file(filename)
    if not new_file:
        return jsonify({"error": "Archivo no disponible"}), 404

    # Guardar versión del manifest
    if manifest and filename in manifest:
        with open(new_file + ".version", "w") as v:
            v.write(manifest[filename])

    return send_from_directory(CACHE_FOLDER, filename)


# ----------------------------
# INICIO
# ----------------------------

if __name__ == "__main__":
    prefetch_files()
    app.run(host="0.0.0.0", port=5000)


