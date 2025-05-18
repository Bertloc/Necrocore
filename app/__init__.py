import os
from flask import Flask

def create_app():
    # Ruta absoluta a la carpeta 'templates'
    template_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'templates'))

    # Crear la app con la carpeta de templates correctamente especificada
    app = Flask(__name__, template_folder=template_path)

    app.secret_key = "clave_secreta_necrocore_2025"

    # Importar y registrar las rutas
    from .routes import main
    app.register_blueprint(main)

    return app
