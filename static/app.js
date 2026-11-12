// JS de MiniRed. Va en un archivo aparte (no inline) para que funcione con la CSP del modo seguro.
// Todo lo que viene del servidor se inserta con textContent (nunca innerHTML).

const CSRF = document.querySelector('meta[name="csrf-token"]')?.content || "";

function el(tag, texto) {
  const e = document.createElement(tag);
  if (texto !== undefined) e.textContent = texto;
  return e;
}

// ---------------------------------------------------------------- Perfil (IDOR)
const perfil = document.getElementById("perfil-api");
if (perfil) {
  const uid = perfil.dataset.uid;
  const salida = document.getElementById("perfil-json");
  const form = document.getElementById("form-api");

  async function cargar() {
    const r = await fetch(`/api/users/${uid}`);
    const datos = await r.json();
    salida.textContent = `GET /api/users/${uid}  ->  HTTP ${r.status}\n\n` + JSON.stringify(datos, null, 2);
    for (const campo of ["display_name", "bio", "email", "telefono"]) {
      form.elements[campo].value = datos[campo] ?? "";
    }
  }

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const cuerpo = {};
    for (const campo of ["display_name", "bio", "email", "telefono"]) {
      if (form.elements[campo].value !== "") cuerpo[campo] = form.elements[campo].value;
    }
    const r = await fetch(`/api/users/${uid}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": CSRF },
      body: JSON.stringify(cuerpo),
    });
    const res = await r.json();
    document.getElementById("put-resultado").textContent =
      `PUT /api/users/${uid}  ->  HTTP ${r.status}\n\n` + JSON.stringify(res, null, 2);
    cargar();
  });

  document.getElementById("ir-a-id").addEventListener("submit", (ev) => {
    ev.preventDefault();
    location.href = `/perfil?id=${encodeURIComponent(document.getElementById("otro-id").value)}`;
  });

  cargar();
}

// ---------------------------------------------------------------- Lab SQLi
const lab = document.getElementById("sqli-lab");
if (lab) {
  const input = document.getElementById("sqli-q");
  const salida = document.getElementById("sqli-salida");

  async function probar(version) {
    const r = await fetch(`/api/sqli/${version}/buscar?q=${encodeURIComponent(input.value)}`);
    const d = await r.json();

    const caja = el("section");
    caja.className = "resultado " + (r.ok ? "ok" : "error");
    caja.append(el("h3", `${d.version || version}  ·  HTTP ${r.status}`));
    if (d.query) {
      caja.append(el("div", "Consulta ejecutada:"));
      caja.append(el("pre", d.query + (d.parametros ? `\nparámetros: ${JSON.stringify(d.parametros)}` : "")));
    }
    if (d.bloqueado) caja.append(el("p", "BLOQUEADO por el filtro: " + d.motivo));
    if (d.error) caja.append(el("p", "Error: " + d.error));
    if (d.resultados) {
      caja.append(el("p", `${d.resultados.length} fila(s)`));
      if (d.resultados.length) {
        const t = el("table");
        const cols = Object.keys(d.resultados[0]);
        const head = el("tr");
        cols.forEach((c) => head.append(el("th", c)));
        t.append(head);
        d.resultados.forEach((fila) => {
          const tr = el("tr");
          cols.forEach((c) => tr.append(el("td", String(fila[c]))));
          t.append(tr);
        });
        caja.append(t);
      }
    }
    return caja;
  }

  lab.querySelectorAll("button[data-version]").forEach((b) =>
    b.addEventListener("click", async () => {
      const versiones = b.dataset.version === "todas" ? ["v1", "v2", "v3"] : [b.dataset.version];
      salida.replaceChildren();
      for (const v of versiones) salida.append(await probar(v));
    })
  );

  lab.querySelectorAll("button.payload").forEach((b) =>
    b.addEventListener("click", () => { input.value = b.dataset.p; input.focus(); })
  );
}
