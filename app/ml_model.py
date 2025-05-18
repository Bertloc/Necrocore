import pandas as pd
import re
import joblib
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
import json
import os   

modelo_path = "modelo_naive.pkl"
vectorizer_path = "vectorizer.pkl"

def entrenar_modelo():
    df = pd.read_csv("correos_entrenamiento.csv")
    df.dropna(inplace=True)
    
    # Preprocesar texto
    df["contenido"] = df["contenido"].apply(limpiar_texto)
    
    vectorizer = CountVectorizer()
    X = vectorizer.fit_transform(df["contenido"])
    y = df["veredicto"]
    
    modelo = MultinomialNB()
    modelo.fit(X, y)
    
    # Guardar modelo y vectorizador
    joblib.dump(modelo, modelo_path)
    joblib.dump(vectorizer, vectorizer_path)
    print("✅ Modelo y vectorizador guardados")

def cargar_modelo_y_vectorizer():
    modelo = joblib.load(modelo_path)
    vectorizer = joblib.load(vectorizer_path)
    return modelo, vectorizer

def limpiar_texto(texto):
    texto = texto.lower()
    texto = re.sub(r'https?://\S+', '', texto)
    texto = re.sub(r'\W+', ' ', texto)
    return texto.strip()


def analizar_correo(texto):
    modelo, vectorizer = cargar_modelo_y_vectorizer()
    texto_limpio = limpiar_texto(texto)
    X_new = vectorizer.transform([texto_limpio])
    veredicto_ia = modelo.predict(X_new)[0]

    # Reglas
    reglas_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'reglas.json'))
    if os.path.exists(reglas_path):
        with open(reglas_path, "r", encoding="utf-8") as file:
            reglas = json.load(file)
            for regla in reglas:
                if regla["estado"] and regla["tipo"].lower() == "contenido":
                    palabra = regla["nombre"].lower()
                    if palabra in texto_limpio:
                        return "Sospechoso (por regla)"

    return veredicto_ia
