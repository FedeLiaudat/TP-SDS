"""
MiniRed - TPI Seguridad en el Desarrollo de Software (UTN FRC - 4K2)

Aplicación web DELIBERADAMENTE VULNERABLE para fines académicos.
NO desplegar en Internet. Correr solo en localhost.

Cubre:
  Propuesta A -> XSS persistente, CSRF, IDOR  (con interruptor VULNERABLE / SEGURO)
  Propuesta B -> SQL Injection en 3 versiones (v1 concatenación, v2 filtros, v3 parametrizada)

Cada punto vulnerable está marcado en el código con  [VULN-XSS], [VULN-CSRF], [VULN-IDOR], [VULN-SQLI]
y su corrección con  [FIX-XSS], [FIX-CSRF], [FIX-IDOR], [FIX-SQLI].
"""
import os
import re
import secrets
import sqlite3
from functools import wraps
from pathlib import Path

from flask import (Flask, abort, g, jsonify, redirect, render_template,
                   request, session, url_for, flash)
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "minired.db"

app = Flask(__name__)
app.config["SECRET_KEY"] = "clave-fija-solo-para-la-demo"
# Recargar plantillas al vuelo (comodo durante el desarrollo de la demo)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.jinja_env.auto_reload = True
# Modo global de la demo. Arranca VULNERABLE salvo que se pase MODO_SEGURO=1
app.config["MODO_SEGURO"] = os.environ.get("MODO_SEGURO") == "1"


def modo_seguro() -> bool:
    return app.config["MODO_SEGURO"]


def aplicar_config_cookies():
    """Las banderas de la cookie de sesión dependen del modo."""
    if modo_seguro():
        # [FIX-XSS] HttpOnly: JavaScript no puede leer la cookie -> un XSS no la puede robar
        app.config["SESSION_COOKIE_HTTPONLY"] = True
        # [FIX-CSRF] SameSite=Strict: defensa en profundidad (ver guía: localhost:5001 es "same-site")
        app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
    else:
        # [VULN-XSS] Sin HttpOnly: document.cookie expone la sesión
        app.config["SESSION_COOKIE_HTTPONLY"] = False
        app.config["SESSION_COOKIE_SAMESITE"] = None


aplicar_config_cookies()


# ---------------------------------------------------------------------------
# Base de datos
# ---------------------------------------------------------------------------
USUARIOS_SEMILLA = [
    # username, password, display_name, bio, email, telefono, dni, is_admin
    ("admin", "admin123", "Administrador", "Cuenta de administración.", "admin@minired.local", "351-000-0000", "20111222", 1),
    ("alice", "alice123", "Alice", "Me gusta la seguridad informática.", "alice@gmail.com", "351-555-1111", "40123456", 0),
    ("bob", "bob123", "Bob", "Estudiante de Sistemas.", "bob@hotmail.com", "351-555-2222", "41987654", 0),
    ("mallory", "mallory123", "Mallory", "Usuaria común (la atacante de la demo).", "mallory@mail.com", "351-555-6666", "39000111", 0),
]


def conectar(readonly: bool = False) -> sqlite3.Connection:
    if readonly:
        # [FIX-SQLI] Mínimo privilegio: conexión de SOLO LECTURA para el endpoint de búsqueda
        conn = sqlite3.connect(f"{DB_PATH.as_uri()}?mode=ro", uri=True)
    else:
        conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = conectar()
    return g.db


@app.teardown_appcontext
def cerrar_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(forzar: bool = False):
    if forzar and DB_PATH.exists():
        DB_PATH.unlink()
    if DB_PATH.exists():
        return
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT NOT NULL,
            bio TEXT DEFAULT '',
            email TEXT,
            telefono TEXT,
            dni TEXT,
            is_admin INTEGER DEFAULT 0
        );
        CREATE TABLE posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            content TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
        """
    )
    for u, pw, dn, bio, email, tel, dni, adm in USUARIOS_SEMILLA:
        conn.execute(
            "INSERT INTO users (username, password_hash, display_name, bio, email, telefono, dni, is_admin)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (u, generate_password_hash(pw), dn, bio, email, tel, dni, adm),
        )
    conn.execute("INSERT INTO posts (user_id, content) VALUES (2, '¡Hola a todos! Primer post en MiniRed.')")
    conn.execute("INSERT INTO posts (user_id, content) VALUES (3, 'Alguien tiene los apuntes de Seguridad?')")
    # Cebo para la demo de CSRF: Mallory publica un enlace a la página trampa del atacante.
    conn.execute(
        "INSERT INTO posts (user_id, content) VALUES (4, ?)",
        ("¡Ganaste un premio! Sos uno de los ganadores del sorteo de MiniRed. "
         "Reclamalo acá: http://localhost:5001/premio",),
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Sesión, autenticación y utilidades
# ---------------------------------------------------------------------------
def usuario_actual():
    uid = session.get("user_id")
    if uid is None:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()


def login_requerido(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if usuario_actual() is None:
            if request.path.startswith("/api/"):
                return jsonify(error="No autenticado"), 401
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapper


def csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


URL_SUELTA = re.compile(r"(^|\s)(https?://[^\s<>\"']+)")


@app.template_filter("enlazar")
def enlazar(texto):
    """Convierte las URLs sueltas de una publicación en enlaces clicables.

    Solo toma URLs al inicio o después de un espacio, para no tocar las que estén
    dentro de atributos HTML. En modo seguro recibe el texto YA escapado, así que
    no puede abrir HTML nuevo; solo agrega el <a>.
    """
    return Markup(URL_SUELTA.sub(r'\1<a href="\2" class="post-link">\2</a>', str(texto)))


@app.context_processor
def inyectar_globales():
    return {"seguro": modo_seguro(), "yo": usuario_actual(), "csrf_token": csrf_token}


# Endpoints de control de la demo (no forman parte de la "aplicación" analizada)
ENDPOINTS_EXENTOS_CSRF = {"cambiar_modo", "reset_db", "static"}


@app.before_request
def verificar_csrf():
    """[FIX-CSRF] Patrón Synchronizer Token.

    En modo seguro, toda petición que cambia estado debe traer el token secreto
    que solo la propia aplicación conoce (campo oculto del form o header X-CSRF-Token).
    Un sitio externo NO puede leer ese token (Same-Origin Policy), así que no puede falsificarlo.
    En modo vulnerable esta verificación no se hace -> [VULN-CSRF].
    """
    if not modo_seguro():
        return
    if request.method in ("POST", "PUT", "PATCH", "DELETE") and request.endpoint not in ENDPOINTS_EXENTOS_CSRF:
        enviado = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or ""
        esperado = session.get("csrf_token", "")
        if not esperado or not secrets.compare_digest(enviado, esperado):
            abort(403, description="Token CSRF ausente o inválido. Petición rechazada.")


@app.after_request
def cabeceras_seguridad(resp):
    if modo_seguro():
        # [FIX-XSS] Content-Security-Policy: aunque se colara HTML, el navegador
        # no ejecuta scripts inline (onerror=, <script>...) ni carga recursos de otros orígenes.
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
            "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        )
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
    return resp


# ---------------------------------------------------------------------------
# Control de la demo
# ---------------------------------------------------------------------------
@app.post("/modo")
def cambiar_modo():
    app.config["MODO_SEGURO"] = not modo_seguro()
    aplicar_config_cookies()
    flash(f"Modo cambiado a {'SEGURO' if modo_seguro() else 'VULNERABLE'}")
    return redirect(request.referrer or url_for("muro"))


@app.post("/reset")
def reset_db():
    cerrar_db(None)
    init_db(forzar=True)
    session.clear()
    flash("Base de datos reiniciada. Volvé a iniciar sesión.")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Autenticación
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (request.form.get("username", ""),)
        ).fetchone()
        if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
            session.clear()  # evita fijación de sesión
            session["user_id"] = user["id"]
            session.permanent = True
            nxt = request.args.get("next", "")
            return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("muro"))
        flash("Usuario o contraseña incorrectos")
    return render_template("login.html", usuarios=USUARIOS_SEMILLA)


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# 1) XSS PERSISTENTE - Muro de comentarios
# ---------------------------------------------------------------------------
@app.route("/")
@login_requerido
def muro():
    posts = get_db().execute(
        "SELECT p.id, p.content, p.created_at, u.display_name, u.id AS autor_id "
        "FROM posts p JOIN users u ON u.id = p.user_id ORDER BY p.id DESC"
    ).fetchall()
    # La diferencia vulnerable/segura está en templates/muro.html:
    #   [VULN-XSS] {{ p.content|safe }}  -> se inserta el HTML tal cual
    #   [FIX-XSS]  {{ p.content }}       -> Jinja escapa < > " ' &  (output encoding)
    return render_template("muro.html", posts=posts)


@app.post("/publicar")
@login_requerido
def publicar():
    contenido = request.form.get("content", "").strip()
    if not contenido:
        flash("El comentario está vacío")
        return redirect(url_for("muro"))
    if modo_seguro() and len(contenido) > 500:
        # [FIX-XSS] Validación de entrada (complementaria, la defensa principal es el escapado)
        flash("Máximo 500 caracteres")
        return redirect(url_for("muro"))
    # En ambos modos se guarda el texto tal cual: la defensa contra XSS se aplica
    # al MOSTRARLO (codificación de salida según contexto), no "limpiando" la entrada.
    get_db().execute("INSERT INTO posts (user_id, content) VALUES (?, ?)", (session["user_id"], contenido))
    get_db().commit()
    return redirect(url_for("muro"))


# ---------------------------------------------------------------------------
# 2) CSRF - Edición de perfil por formulario clásico
# ---------------------------------------------------------------------------
@app.route("/perfil/editar", methods=["GET", "POST"])
@login_requerido
def editar_perfil():
    yo = usuario_actual()
    if request.method == "POST":
        # [VULN-CSRF] En modo vulnerable esta acción se ejecuta para CUALQUIER POST que
        # traiga la cookie de sesión, aunque venga de un formulario de otro sitio.
        # [FIX-CSRF] En modo seguro, verificar_csrf() (before_request) ya rechazó el
        # POST si no traía el token correcto.
        display_name = request.form.get("display_name", yo["display_name"])
        email = request.form.get("email", yo["email"])
        bio = request.form.get("bio", yo["bio"])
        get_db().execute(
            "UPDATE users SET display_name = ?, email = ?, bio = ? WHERE id = ?",
            (display_name, email, bio, yo["id"]),
        )
        get_db().commit()
        flash("Perfil actualizado")
        return redirect(url_for("editar_perfil"))
    return render_template("editar_perfil.html")


# ---------------------------------------------------------------------------
# 3) IDOR - API de perfiles por ID
# ---------------------------------------------------------------------------
CAMPOS_PUBLICOS = ("id", "username", "display_name", "bio")
CAMPOS_PRIVADOS = ("email", "telefono", "dni", "is_admin")
CAMPOS_EDITABLES = ("display_name", "bio", "email", "telefono")


@app.route("/usuarios")
@login_requerido
def usuarios():
    lista = get_db().execute("SELECT id, username, display_name FROM users ORDER BY id").fetchall()
    return render_template("usuarios.html", lista=lista)


@app.route("/perfil")
@login_requerido
def ver_perfil():
    # La página toma ?id= de la URL y consulta /api/users/<id> (ver static/app.js)
    uid = request.args.get("id", type=int) or session["user_id"]
    return render_template("perfil.html", uid=uid)


@app.get("/api/users/<int:uid>")
@login_requerido
def api_get_usuario(uid):
    user = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if user is None:
        return jsonify(error="Usuario inexistente"), 404

    es_dueno = uid == session["user_id"]
    if modo_seguro() and not es_dueno:
        # [FIX-IDOR] Control de acceso a nivel de objeto: si el recurso no es tuyo,
        # solo ves los datos públicos.
        return jsonify({k: user[k] for k in CAMPOS_PUBLICOS})

    # [VULN-IDOR] Solo se verifica que estés autenticado, NO que el recurso te pertenezca.
    # Cambiando el id en la URL se obtienen los datos privados de cualquier usuario.
    return jsonify({k: user[k] for k in CAMPOS_PUBLICOS + CAMPOS_PRIVADOS})


@app.put("/api/users/<int:uid>")
@login_requerido
def api_put_usuario(uid):
    user = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if user is None:
        return jsonify(error="Usuario inexistente"), 404

    if modo_seguro() and uid != session["user_id"]:
        # [FIX-IDOR] Autorización: solo el dueño puede modificar su perfil.
        return jsonify(error="Prohibido: el recurso no te pertenece"), 403

    # [VULN-IDOR] En modo vulnerable cualquiera modifica el perfil de cualquiera.
    datos = request.get_json(silent=True) or {}
    cambios = {k: str(v) for k, v in datos.items() if k in CAMPOS_EDITABLES}  # lista blanca de campos
    if not cambios:
        return jsonify(error="Nada para actualizar"), 400
    set_sql = ", ".join(f"{k} = ?" for k in cambios)  # nombres de columna de la lista blanca, no del usuario
    get_db().execute(f"UPDATE users SET {set_sql} WHERE id = ?", (*cambios.values(), uid))
    get_db().commit()
    return jsonify(ok=True, actualizado=uid, campos=list(cambios))


# ---------------------------------------------------------------------------
# 4) SQL INJECTION - Propuesta B: mismo endpoint en 3 versiones
#    (independiente del interruptor de modo: las 3 versiones están siempre disponibles)
# ---------------------------------------------------------------------------
@app.route("/sqli")
@login_requerido
def sqli_lab():
    return render_template("sqli.html")


def _filas(cursor_rows):
    return [dict(r) for r in cursor_rows]


@app.get("/api/sqli/v1/buscar")
def sqli_v1():
    """[VULN-SQLI] v1: concatenación directa del input en la consulta."""
    q = request.args.get("q", "")
    sql = f"SELECT id, username, display_name, bio FROM users WHERE username LIKE '%{q}%'"
    try:
        filas = _filas(get_db().execute(sql).fetchall())
        return jsonify(version="v1 - concatenación", query=sql, resultados=filas)
    except sqlite3.Error as e:
        # Además expone el error interno de la BD (ayuda al atacante a ajustar el payload)
        return jsonify(version="v1 - concatenación", query=sql, error=str(e)), 500


# Lista negra "ingenua" típica
LISTA_NEGRA = ["--", " or ", " and ", "union select", ";", "drop ", "sleep("]


@app.get("/api/sqli/v2/buscar")
def sqli_v2():
    """[VULN-SQLI] v2: filtros manuales / lista negra. Sigue concatenando -> se puede evadir."""
    q = request.args.get("q", "")
    q_min = q.lower()
    for patron in LISTA_NEGRA:
        if patron in q_min:
            return jsonify(version="v2 - lista negra", bloqueado=True,
                           motivo=f"Patrón prohibido detectado: {patron!r}"), 400
    # También "escapa" un caso puntual... que no alcanza
    q = q.replace("'='", "")
    sql = f"SELECT id, username, display_name, bio FROM users WHERE username LIKE '%{q}%'"
    try:
        filas = _filas(get_db().execute(sql).fetchall())
        return jsonify(version="v2 - lista negra", query=sql, resultados=filas)
    except sqlite3.Error as e:
        return jsonify(version="v2 - lista negra", query=sql, error=str(e)), 500


@app.get("/api/sqli/v3/buscar")
def sqli_v3():
    """[FIX-SQLI] v3: consulta parametrizada + validación + conexión de solo lectura."""
    q = request.args.get("q", "")
    if len(q) > 50:
        return jsonify(version="v3 - parametrizada", error="Búsqueda demasiado larga (máx. 50)"), 400
    sql = "SELECT id, username, display_name, bio FROM users WHERE username LIKE ?"
    param = f"%{q}%"
    conn = conectar(readonly=True)
    try:
        filas = _filas(conn.execute(sql, (param,)).fetchall())
        return jsonify(version="v3 - parametrizada", query=sql, parametros=[param], resultados=filas)
    except sqlite3.Error:
        # Mensaje genérico: no se filtran detalles internos
        return jsonify(version="v3 - parametrizada", error="Error al procesar la búsqueda"), 500
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
    print("\n  MiniRed corriendo en  http://localhost:5000")
    print(f"  Modo inicial: {'SEGURO' if modo_seguro() else 'VULNERABLE'}\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
