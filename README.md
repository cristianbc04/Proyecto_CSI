# Proyecto_CSI

API para operadores de mutación y análisis de tráfico

Este proyecto implementa una **API en FastAPI** que permite ejecutar y analizar distintos operadores relacionados con **ataques de red** tales como:

* **DoS (Denial of Service)**
* **DDoS (Distributed Denial of Service)**
* **ARP Spoofing**
* **Port Scanning**
* **Analizador de tráfico**

El objetivo es ofrecer un entorno organizado, modular y fácil de desplegar para pruebas, análisis y aprendizaje.

---

## 🪧 Características principales

* Arquitectura modular usando **routers** de FastAPI.
* Plantillas HTML para visualización (`templates/`).
* Archivos estáticos CSS para interfaz (`static/`).
* Endpoints específicos para cada operador/ataque.
* Compatible con Python **3.11** (recomendado).

---

## 📁 Estructura del Proyecto

```
Proyecto_CSI/
 ├── app/
 │   ├── routers/         # Endpoints (GET/POST) de cada operador
 │   ├── templates/       # HTML de la interfaz
 │   ├── static/          # CSS / imágenes
 │   ├── main.py          # Punto de entrada de la API
 │   └── __init__.py
 └── README.md
```

---

## 🛠 Instalación

### 1️⃣ Requisitos

* **Python 3.11**
  *(Versiones superiores pueden causar incompatibilidades con FastAPI)*

---

### 2️⃣ Crear entorno virtual

#### En Windows (PowerShell):

```
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

#### En Linux / WSL:

```
bash
python3.11 -m venv .venv
source .venv/bin/activate
```

---

### 3️⃣ Actualizar pip (recomendado)

```
python -m pip install --upgrade pip
```

---

### 4️⃣ Instalar dependencias

```
pip install "fastapi[standard]"

pip install scapy

pip install pyfiglet 
```

Si necesitas levantar el servidor local:

```
pip install uvicorn
```

---


## ▶️ Ejecución del Proyecto

Una vez activado el entorno virtual y dentro de la carpeta `Proyecto_CSI`:

```
uvicorn app.main:app --reload
```

La API estará disponible en:

👉 **[http://127.0.0.1:8000](http://127.0.0.1:8000)**

Documentación interactiva (Swagger UI):

👉 **[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)**

---

## ⚙️ Uso de la API

Cada operador tiene su propio router. Ejemplos:

* `/op_ddos`
* `/op_dos`
* `/op_portscan`
* `/op_analizador`

Las rutas ofrecen formularios HTML para interacción o respuestas JSON según el endpoint.

---

## 📌 Notas adicionales

* El directorio `__pycache__` **no debe añadirse al repositorio**.
* Se recomienda usar un archivo `.gitignore` como:

```
__pycache__/
*.pyc
*.pyo
*.pyd
.env
```

---

