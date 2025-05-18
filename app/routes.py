from flask import Blueprint, request, jsonify, render_template, send_file, redirect, session
from .ml_model import analizar_correo
from datetime import datetime
import csv
import os
import json


main = Blueprint('main', __name__)

@main.route("/", methods=["GET"])
def index():
    if "usuario" not in session:
        return redirect("/login")
    return redirect("/dashboard")

    historial_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'historial.csv'))
    ip_block_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'ips_bloqueadas.csv'))

    # Leer historial
    historial = []
    if os.path.exists(historial_path):
        with open(historial_path, mode="r", encoding='utf-8') as file:
            reader = csv.reader(file)
            historial = list(reader)[1:]

    # Leer IPs bloqueadas
    ips_bloqueadas = []
    if os.path.exists(ip_block_path):
        with open(ip_block_path, mode="r", encoding='utf-8') as file:
            reader = csv.reader(file)
            ips_bloqueadas = list(reader)[1:]

    return render_template("index.html", historial=historial, ips_bloqueadas=ips_bloqueadas)

@main.route("/analizar-correo", methods=["POST"])
def analizar_api():
    data = request.json
    texto = data.get("contenido", "")
    resultado = analizar_correo(texto)
    return jsonify({"veredicto": resultado})

@main.route("/analizar-web", methods=["POST"])
def analizar_web():
    if "usuario" not in session:
        return redirect("/login")

    texto = request.form.get("contenido", "")
    resultado = analizar_correo(texto)

    historial_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'historial.csv'))
    ip_block_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'ips_bloqueadas.csv'))

    # Guardar en historial
    guardar_encabezado = not os.path.exists(historial_path)
    with open(historial_path, mode="a", newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        if guardar_encabezado:
            writer.writerow(["fecha", "contenido", "resultado"])
        writer.writerow([datetime.now().isoformat(), texto, resultado])

    # Bloqueo automático de IPs
    palabras_sospechosas = ["clic", "suspendida", "urgente", "gratis", "bloqueada", "verifica"]
    bloqueo_activado = any(p in texto.lower() for p in palabras_sospechosas)
    ip_simulada = f"192.168.1.{len(texto) % 255}"

    if bloqueo_activado:
        encabezado_ips = not os.path.exists(ip_block_path)
        with open(ip_block_path, mode="a", newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            if encabezado_ips:
                writer.writerow(["fecha", "ip", "razon"])
            writer.writerow([datetime.now().isoformat(), ip_simulada, "Contenido sospechoso"])

    # Leer historial actualizado
    historial = []
    with open(historial_path, mode="r", encoding='utf-8') as file:
        reader = csv.reader(file)
        historial = list(reader)[1:]

    # Leer IPs bloqueadas
    ips_bloqueadas = []
    if os.path.exists(ip_block_path):
        with open(ip_block_path, mode="r", encoding='utf-8') as file:
            reader = csv.reader(file)
            ips_bloqueadas = list(reader)[1:]

    return render_template("index.html", resultado=resultado, historial=historial, ips_bloqueadas=ips_bloqueadas)

@main.route("/descargar-historial")
def descargar_historial():
    if "usuario" not in session:
        return redirect("/login")

    historial_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'historial.csv'))
    if not os.path.exists(historial_path):
        with open(historial_path, "w", encoding="utf-8") as f:
            f.write("fecha,contenido,resultado\n")
    return send_file(historial_path, as_attachment=True, download_name="historial.csv")

@main.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        user = request.form.get("usuario")
        password = request.form.get("contrasena")

        usuarios_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'usuarios.csv'))
        with open(usuarios_path, mode="r", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            for row in reader:
                if row["usuario"] == user and row["contrasena"] == password:
                    session["usuario"] = user
                    return redirect("/dashboard")
        error = "Credenciales inválidas. Intenta de nuevo."

    return render_template("login.html", error=error)

@main.route("/logout")
def logout():
    session.pop("usuario", None)
    return redirect("/login")

@main.route("/dashboard")
def dashboard():
    if "usuario" not in session:
        return redirect("/login")

    import psutil
    import os
    import csv
    from datetime import datetime

    # CPU y RAM
    cpu_percent = psutil.cpu_percent(interval=1)
    ram_usage = round(psutil.virtual_memory().used / (1024 * 1024), 2)  # MB

    # Actividad de red (bytes enviados + recibidos)
    net = psutil.net_io_counters()
    net_activity = round((net.bytes_sent + net.bytes_recv) / (1024 * 1024), 2)  # MB totales

    # Historial
    historial_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'historial.csv'))
    amenazas_detectadas = 0
    ultima_fecha = "N/A"

    if os.path.exists(historial_path):
        with open(historial_path, mode="r", encoding="utf-8") as file:
            reader = list(csv.reader(file))[1:]
            amenazas_detectadas = len(reader)
            if reader:
                ultima_fecha = reader[-1][0]

    return render_template("dashboard.html",
                           cpu=cpu_percent,
                           ram=ram_usage,
                           net=net_activity,
                           amenazas=amenazas_detectadas,
                           ultima_fecha=ultima_fecha,
                           dispositivos=4)  # valor fijo temporal



@main.route("/logs")
def logs():
    if "usuario" not in session:
        return redirect("/login")

    logs_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'logs.csv'))
    registros = []

    if os.path.exists(logs_path):
        with open(logs_path, mode="r", encoding="utf-8") as file:
            reader = csv.reader(file)
            next(reader)  # omitir encabezado
            for fila in reader:
                # [fecha, hora, origen, tipo_evento, detalle]
                registros.append({
                    "fecha": fila[0],
                    "hora": fila[1],
                    "origen": fila[2],
                    "tipo": fila[3],
                    "detalle": fila[4]
                })

    registros = registros[::-1]  # mostrar más reciente arriba
    return render_template("logs.html", registros=registros)


@main.route("/amenazas")
def amenazas():
    if "usuario" not in session:
        return redirect("/login")

    historial_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'historial.csv'))
    historial = []

    if os.path.exists(historial_path):
        with open(historial_path, mode="r", encoding="utf-8") as file:
            reader = csv.reader(file)
            historial = list(reader)[1:]  # omitir encabezado

    return render_template("amenazas.html", historial=historial)
@main.route("/analisis/<int:id>")
def analisis(id):
    if "usuario" not in session:
        return redirect("/login")

    historial_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'historial.csv'))
    correo = None

    if os.path.exists(historial_path):
        with open(historial_path, mode="r", encoding="utf-8") as file:
            reader = list(csv.reader(file))[1:]  # omitir encabezado
            if 1 <= id <= len(reader):
                correo = reader[id - 1]  # índice base 0

    return render_template("analisis.html", id=id, correo=correo)
@main.route("/api/amenazas")
def api_analizar_historial_ia():
    historial_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'historial.csv'))

    if not os.path.exists(historial_path):
        return jsonify({"error": "No existe historial.csv"}), 404

    correos = []
    with open(historial_path, mode="r", encoding="utf-8") as file:
        reader = list(csv.reader(file))
        encabezado = reader[0] if reader else []
        filas = reader[1:] if len(reader) > 1 else []

        for fila in filas:
            try:
                fecha, contenido, resultado_original = fila[:3]
                veredicto_ia = analizar_correo(contenido)
                correos.append({
                    "fecha": fecha,
                    "contenido": contenido,
                    "resultado_original": resultado_original,
                    "veredicto_ia": veredicto_ia
                })
            except Exception as e:
                continue  # ignora errores de filas mal formateadas

    return jsonify(correos)

@main.route("/api/metricas")
def api_metricas():
    import psutil
    import time

    # Usar un breve intervalo para mejor precisión
    cpu = psutil.cpu_percent(interval=0.5)
    ram = round(psutil.virtual_memory().used / (1024 * 1024), 2)
    net = psutil.net_io_counters()
    net_total = round((net.bytes_sent + net.bytes_recv) / (1024 * 1024), 2)

    return jsonify({
        "cpu": cpu,
        "ram": ram,
        "net": net_total,
        "timestamp": int(time.time())
    })



@main.route("/reglas", methods=["GET", "POST"])
def reglas():
    if "usuario" not in session:
        return redirect("/login")

    reglas_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'reglas.json'))

    # Cargar reglas existentes
    reglas = []
    if os.path.exists(reglas_path):
        with open(reglas_path, "r", encoding="utf-8") as file:
            reglas = json.load(file)

    # POST: agregar nueva regla (desde formulario oculto por ahora)
    if request.method == "POST":
        nombre = request.form.get("nombre")
        tipo = request.form.get("tipo")
        if nombre and tipo:
            nueva_regla = {
                "id": (max([r["id"] for r in reglas]) + 1) if reglas else 1,
                "nombre": nombre,
                "tipo": tipo,
                "estado": True,
                "fecha_modificacion": datetime.now().strftime("%Y-%m-%d")
            }
            reglas.append(nueva_regla)
            with open(reglas_path, "w", encoding="utf-8") as file:
                json.dump(reglas, file, indent=2)

        return redirect("/reglas")

    # Renderizar reglas.html
    return render_template("reglas.html", reglas=reglas)


@main.route("/analizar-emails")
def analizar_emails():
    if "usuario" not in session:
        return redirect("/login")

    try:
        # Ejecuta el script imap_monitor.py como proceso externo
        subprocess.run(["python", "imap_monitor.py"], check=True)
        registrar_log(session["usuario"], "Análisis (correo)", "Análisis manual de bandeja IMAP ejecutado")
    except Exception as e:
        registrar_log(session["usuario"], "Error", f"Fallo al ejecutar análisis IMAP: {str(e)}")

    return redirect("/dashboard")


