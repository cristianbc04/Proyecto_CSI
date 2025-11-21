# Proyecto_CSI
API para operadores de mutacion

Esta API sirve para poder usar diferentes operadores de mutacion como lo son: Ataques de Denegacion de Servicios (DoS), Operador de Denegacion de Servicio Distribuido (DDoS)... 

- Instalacion: Simplemente se debe de descargar el repositorio y disponer de un entorno en python para tranajar con el.
  - Instalacion de entorno en Python:
  1) Disponer de python 3.11: Esto es porque versiones superiores dan problemas a la hora de trabajar con la biblioteca fastapi
  2) Comando para levantar un entorno: py 3.11 -m venv <nombre_entorno>
  3) Activar el entorno:
    - Linux: soruce <nombre_entorno>\Scripts\Activate.ps1
    - Windows: .\<nombre_entorno>\Scripts\Activate.ps1
  4) *Recomendacion: actualizar pip (python -m pip install --upgrade pip)*
  5) Instalacion de fastapi: pip install "fastapi[standard]"
