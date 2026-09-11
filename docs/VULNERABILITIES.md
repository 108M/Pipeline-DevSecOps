# Vulnerabilidades intencionadas y cómo corregirlas

Este repositorio incluye **3 vulnerabilidades sencillas, deliberadas y documentadas**
en la Fleet Compliance API, precisamente para que el pipeline DevSecOps tenga
algo real que detectar. No son exploits ni malware: son errores comunes y
didácticos que cualquier equipo comete alguna vez.

**Estado esperado en la primera ejecución del pipeline: en rojo.** Eso es
intencionado — demuestra que las puertas de seguridad (*security gates*)
funcionan de verdad. El objetivo de este documento es que apliques cada fix
en **un commit independiente** (`fix: ...`) y veas el pipeline pasar a verde
paso a paso. Esa secuencia de commits es en sí misma una pieza de portafolio:
demuestra que sabes interpretar hallazgos de seguridad y corregirlos, no solo
generar informes.

---

## Vulnerabilidad 1 — Dependencia desactualizada con CVE conocida

| | |
|---|---|
| **Dónde** | `app/requirements.txt` |
| **Qué** | `PyYAML==5.3.1` |
| **CVE** | [CVE-2020-14343](https://nvd.nist.gov/vuln/detail/CVE-2020-14343) |
| **Severidad (NVD)** | Crítica (9.8 CVSS v3) |
| **Detectada por** | Job `03 · SCA — dependencies (Trivy)` y `05 · Container image scan (Trivy)` |
| **CWE** | CWE-20 (Improper Input Validation) → permite ejecución de código arbitrario |

### Descripción

PyYAML ≤ 5.3.1 permite ejecución de código arbitrario si se usa
`yaml.load()`/`yaml.full_load()` con las clases `FullLoader` o `UnsafeLoader`
sobre una entrada no confiable, porque el deserializador puede reconstruir
objetos Python arbitrarios (`!!python/object/apply:...`) durante el parseo.

Este proyecto usa `yaml.safe_load()` (ver `app/feature_flags.py`), que **no**
es vulnerable a este CVE concreto. Es un matiz importante y a propósito: un
escáner de composición de software (SCA) como Trivy marca la **versión** de
la librería instalada, no si tu código la usa de forma segura o insegura.
Eso es correcto — un SBOM y un escaneo de dependencias existen para dar
visibilidad de *qué* hay en tu cadena de suministro, no para juzgar caso por
caso si hoy es explotable. Mañana alguien puede añadir un `yaml.load()` sin
`Loader=SafeLoader` en otro módulo y la vulnerabilidad pasa a ser real de
inmediato, sin que nadie lo note si no hay SCA en el pipeline.

### Cómo reproducirlo

```bash
cd app
pip install -r requirements.txt
pip show pyyaml   # Version: 5.3.1
```

### Fix

Actualizar el pin a una versión parcheada (≥ 5.4) y fijar además la última
estable conocida en el momento de escribir esto:

```diff
- PyYAML==5.3.1
+ PyYAML==6.0.1
```

Después:

```bash
cd app
pip install -r requirements.txt
pytest ../  # los tests no dependen de PyYAML, deben seguir en verde
```

Commit sugerido:

```
fix(deps): bump PyYAML 5.3.1 -> 6.0.1 (CVE-2020-14343)
```

### Lo que pasó de verdad al aplicarlo (la parte que no sale en los tutoriales)

Subir el pin de PyYAML fue un único commit. Pero el job `05 · Container
image scan (Trivy)` — que analiza la imagen final, no solo el código
fuente — siguió en rojo varios commits más después de eso, por motivos que
no tenían nada que ver con PyYAML. Se documentan aquí porque son exactamente
el tipo de fricción real que un pipeline de este tipo saca a la luz, y que
un caso de laboratorio "limpio" nunca enseña:

1. **Otras dependencias también estaban desactualizadas de verdad.**
   El propio escaneo de imagen encontró CVEs con parche disponible en
   `PyJWT`, `python-multipart` y `starlette` (dependencia transitiva de
   FastAPI) — ninguna de las tres era la "vulnerabilidad intencionada", eran
   simplemente pines que habían quedado desactualizados entre que se escribió
   el código y que se ejecutó el pipeline por primera vez. Se corrigieron
   subiendo cada una a su última versión estable real (comprobada contra
   PyPI, no de memoria).
2. **`pip` también tenía CVEs con parche disponible** — y arreglarlo reveló
   un fallo de diseño del propio `Dockerfile`: el build es multi-stage
   (`builder` + `runtime`), y cada `FROM python:3.12-slim` arranca una copia
   **independiente** de la imagen base con su propio `pip` de fábrica.
   Actualizar `pip` en el stage `builder` no tiene ningún efecto en el stage
   `runtime`, que es el que realmente se escanea y se despliega — hubo que
   actualizarlo en los dos sitios por separado.
3. **Un filtro de severidad demasiado amplio hace que el job nunca pueda
   ponerse verde.** La imagen base (`python:3.12-slim`, Debian) trae de
   fábrica decenas de CVEs en paquetes del sistema operativo (`perl-base`,
   `bash`, `coreutils`...) que **todavía no tienen parche publicado**. Con
   el filtro original (`CRITICAL,HIGH,MEDIUM` sin más) el job jamás iba a
   pasar, sin importar qué se arreglara en el código — se añadió
   `ignore-unfixed: true` para bloquear solo por lo que sí se puede
   arreglar hoy.
4. **Un "false lead" real: la SBOM de Docker Buildx.** Trivy avisaba con
   `Third-party SBOM may lead to inaccurate vulnerability detection` — Docker
   moderno adjunta automáticamente una attestation de procedencia/SBOM a la
   imagen durante el build, y en teoría eso puede hacer que Trivy prefiera
   esa SBOM en vez de analizar el sistema de ficheros real. Se probó a
   desactivarlo (`docker build --provenance=false --sbom=false`) — no
   cambió nada, así que no era la causa real, pero se dejó el flag puesto
   porque sigue siendo una buena práctica independiente de este problema.
5. **La causa real de un hallazgo persistente (`msgpack`, `setuptools`
   siempre en la misma versión, pasara lo que pasara).** Ningún cambio en
   `requirements.txt` ni ninguna actualización de `pip`/`setuptools`
   cambiaba nunca la versión que Trivy reportaba — la misma, exacta,
   commit tras commit, aunque los logs de build probaban que la instalación
   real había ido bien. La explicación más plausible: `pip` lleva sus
   propias dependencias empaquetadas internamente para su propio uso
   interno, independientes de lo que el proyecto instala. La solución no
   fue seguir persiguiendo versiones — fue darse cuenta de que **la imagen
   final no necesita `pip` para nada** (todo lo que se ejecuta en runtime ya
   viene pre-instalado desde el stage de build) y eliminarlo del todo del
   stage `runtime`. Elimina la categoría de hallazgo entera en vez de
   perseguirla número a número.

Ninguno de estos cinco pasos estaba planeado — cada uno salió de leer el log
o la SARIF real de una ejecución fallida, no de anticipar el problema de
antemano. Esa es, honestamente, la mecánica real de resolver hallazgos de un
pipeline de seguridad: iterar contra evidencia real, no contra lo que "se
supone" que debería pasar.

---

## Vulnerabilidad 2 — Secretos y credenciales por defecto embebidos en el código

| | |
|---|---|
| **Dónde** | `app/config.py` |
| **Qué** | `SECRET_KEY` (firma de JWT) y `ADMIN_PASSWORD` (credencial de la cuenta operadora sembrada al arrancar) hardcodeados en el fuente |
| **Detectada por** | Job `02 · Secrets (Gitleaks)` |
| **CWE** | CWE-798 (Use of Hard-coded Credentials) |
| **Relación con CRA** | Ver [`CRA_MAPPING.md`](../CRA_MAPPING.md) — Annex I, Parte I, punto 2(b): *"por defecto, entregarse con una configuración segura"* |

### Descripción

Dos problemas relacionados, del mismo origen (gestión de secretos), con
impacto distinto:

1. **`SECRET_KEY`** firma todos los JWT emitidos por `POST /auth/token`. Al
   estar en el código fuente (y por tanto en el historial de git si se
   llega a subir), cualquiera con acceso al repositorio puede **forjar
   tokens válidos para cualquier usuario**, sin conocer ninguna contraseña.
2. **`ADMIN_PASSWORD`** es la contraseña de la cuenta operadora sembrada la
   primera vez que arranca la aplicación. Es una credencial por defecto,
   igual para todo el mundo que despliegue este software sin cambiarla —
   justo lo que la CRA llama "secure by default".

Gitleaks detecta el primer caso de forma automática (cadena de alta entropía
asignada a una variable con nombre `*_KEY`/`*_SECRET*`, patrón `generic-api-key`
de su ruleset por defecto). El segundo caso (contraseña por defecto débil
pero de aspecto "normal") normalmente **no** lo detecta un escáner de
secretos — hace falta revisión humana o una política explícita
("todo despliegue debe forzar cambio de credencial en el primer login").
Ese es justamente el aprendizaje: la automatización coge lo obvio, pero el
threat modeling sigue haciendo falta para lo que no tiene una firma clara.

### Fix

Mover ambos valores a variables de entorno, sin valor por defecto embebido
para el secreto de firma (que falle explícitamente si no se configura), y
generar la contraseña inicial de forma aleatoria si no se proporciona:

```diff
--- a/app/config.py
+++ b/app/config.py
@@
 import os
+import secrets
 
-# --- VULNERABLE: a realistic-looking, high-entropy secret hardcoded in source.
-SECRET_KEY = "<redacted-high-entropy-string>"  # the real value is in the git history, not repeated here
+SECRET_KEY = os.environ["FLEET_SECRET_KEY"]  # no default: fail fast if unset
 ALGORITHM = "HS256"
 ACCESS_TOKEN_EXPIRE_MINUTES = 30
 
-ADMIN_USERNAME = "admin"
-ADMIN_PASSWORD = "Admin123!"
+ADMIN_USERNAME = os.getenv("FLEET_ADMIN_USERNAME", "admin")
+ADMIN_PASSWORD = os.getenv("FLEET_ADMIN_PASSWORD") or secrets.token_urlsafe(16)
+if "FLEET_ADMIN_PASSWORD" not in os.environ:
+    print(f"[startup] No FLEET_ADMIN_PASSWORD set — generated one-time password: {ADMIN_PASSWORD}")
```

Y en despliegue (local o CI), usar `.env.example` como plantilla:

```bash
cp .env.example .env
# editar .env con valores reales
export $(grep -v '^#' .env | xargs)  # o usa --env-file con docker/docker compose
```

Genera un secreto fuerte con:

```bash
openssl rand -hex 32
```

Commit sugerido (idealmente en dos commits separados, uno por cada
credencial, para que el historial sea legible):

```
fix(secrets): load JWT signing key from environment, fail fast if unset
fix(secrets): remove hardcoded default admin password, generate at first boot
```

> 🔗 **Efecto colateral que este fix ya resuelve:** el job `07 · DAST`
> arranca el contenedor de verdad (`docker run`) para que ZAP lo ataque, y
> `app/config.py` ahora exige `FLEET_SECRET_KEY` sin valor por defecto —
> así que el contenedor ya no arrancaría sin él. El workflow ya incluye un
> paso ("Generate ephemeral secrets for this run") que genera un
> `FLEET_SECRET_KEY` y un `FLEET_ADMIN_PASSWORD` aleatorios **solo para esa
> ejecución**, los pasa al `docker run` con `-e`, y usa el mismo
> `FLEET_ADMIN_PASSWORD` en el login que hace ZAP justo después — sin
> necesidad de crear ningún secret de repositorio ni de fijar ninguna
> contraseña real en el YAML. Es intencionado: para un contenedor efímero
> que vive solo durante el escaneo, generar el secreto en el momento es más
> seguro que gestionar uno persistente.

> ⚠️ **Esto pasó de verdad en este mismo repositorio, no es solo teoría.**
> Cambiar el código en `db1f022` **no fue suficiente**: el job `02 ·
> Secrets (Gitleaks)` siguió en rojo después del fix, porque el secreto
> original sigue en el historial de git, en el commit `3b544bf` (donde se
> introdujo a propósito). Con las opciones reales sobre la mesa:
>
> 1. **Reescribir el historial** (`git filter-repo` + force-push) — lo más
>    "limpio" en teoría, pero destructivo y poco realista en cuanto el
>    repositorio se comparte con alguien más (reescribe SHAs, rompe forks,
>    PRs abiertos, referencias externas).
> 2. **Rotar el secreto donde se use** — la respuesta correcta si fuera un
>    secreto real de un servicio real. Aquí no aplica: nunca fue una
>    credencial de verdad, no hay nada que rotar.
> 3. **Allowlist explícito por commit, después del fix, no en su lugar** —
>    lo que se hizo aquí. `.gitleaks.toml` ignora ese *commit concreto* por
>    SHA exacto (no por patrón), con un comentario explicando el porqué.
>    Cualquier secreto nuevo — incluso en esa misma línea de código, en un
>    commit futuro — se sigue detectando con normalidad.
>
> La opción 3 es la que casi siempre se usa en la práctica al encontrar
> un secreto legacy en un repo compartido: no puedes deshacer que estuvo
> ahí, pero puedes dejar constancia de que se investigó, se confirmó inerte
> y se documentó — que es justo lo que exige el Anexo I, Parte II, punto 4
> de la CRA sobre divulgación de vulnerabilidades corregidas.

---

## Vulnerabilidad 3 — Inyección SQL

| | |
|---|---|
| **Dónde** | `app/database.py`, función `search_devices()` |
| **Endpoint afectado** | `GET /devices/search?q=...` |
| **Detectada por** | Job `01 · SAST (Semgrep)` (regla propia `.semgrep/custom-rules.yml` + reglas públicas `p/python`) |
| **CWE** | CWE-89 (SQL Injection) |
| **OWASP Top 10 2021** | A03:2021 — Injection |

### Descripción

```python
sql = (
    f"SELECT * FROM devices WHERE owner = '{owner}' "
    f"AND (asset_tag LIKE '%{query}%' OR device_type LIKE '%{query}%')"
)
return conn.execute(sql).fetchall()
```

El parámetro `q` de la query string se concatena directamente en el SQL. Un
payload como:

```
GET /devices/search?q=nonexistent' OR '1'='1') --%20
```

rompe la cláusula `LIKE` prevista, cierra el paréntesis que la envuelve,
añade una condición siempre verdadera y comenta el resto de la consulta —
convirtiendo el filtro de búsqueda en un "devuélvemelo todo" (nótese que hay
que cerrar el paréntesis y comentar con `--` explícitamente: el código
vulnerable añade un `%'` justo después de `{query}`, así que un payload
ingenuo `' OR '1'='1` no basta, porque ese `%` final rompe la tautología
antes de que llegue a evaluarse). Verificado directamente contra `sqlite3`
al escribir `app/tests/test_vulnerabilities.py`.

Con más esfuerzo, la misma técnica permite exfiltrar datos de **otra
tabla** con una inyección `UNION SELECT`, por ejemplo para leer los hashes
de contraseña de `users` (la tabla `devices` tiene 7 columnas, así que la
`UNION SELECT` debe aportar 7 valores):

```
GET /devices/search?q=x') UNION SELECT id, username, hashed_password, 'x','x','x','x' FROM users --%20
```

también verificado directamente contra `sqlite3` (no incluido como test
automatizado para no acoplar el test a la forma exacta de la tabla, pero
reproducible copiando la query anterior).

El test `app/tests/test_vulnerabilities.py::test_search_endpoint_is_sql_injectable`
reproduce el fallo de forma automatizada y sirve de test de regresión una
vez aplicado el fix.

### Fix

Sustituir la interpolación por una consulta parametrizada:

```diff
--- a/app/database.py
+++ b/app/database.py
@@
     with get_connection() as conn:
-        sql = (
-            f"SELECT * FROM devices WHERE owner = '{owner}' "
-            f"AND (asset_tag LIKE '%{query}%' OR device_type LIKE '%{query}%')"
-        )  # intentionally NOT parameterized — left in for the SAST job to find
-        return conn.execute(sql).fetchall()
+        like_pattern = f"%{query}%"
+        sql = (
+            "SELECT * FROM devices WHERE owner = ? "
+            "AND (asset_tag LIKE ? OR device_type LIKE ?)"
+        )
+        return conn.execute(sql, (owner, like_pattern, like_pattern)).fetchall()
```

Y actualizar el test de regresión para reflejar el comportamiento correcto
(ya no debe devolver resultados con un payload de inyección):

```diff
--- a/app/tests/test_vulnerabilities.py
+++ b/app/tests/test_vulnerabilities.py
@@
-    tags = [d["asset_tag"] for d in resp.json()]
-    assert "SENSOR-100" in tags
-    assert "POS-200" in tags
+    # FIXED behavior: the payload is treated as a literal search string,
+    # matches nothing, and no injection occurs.
+    assert resp.json() == []
```

Commit sugerido:

```
fix(security): parameterize search_devices() query to prevent SQL injection
```

---

## Checklist para tu propia secuencia de commits

1. `fix(deps): bump PyYAML 5.3.1 -> 6.0.1 (CVE-2020-14343)`
2. `fix(secrets): load JWT signing key from environment, fail fast if unset`
3. `fix(secrets): remove hardcoded default admin password, generate at first boot`
4. `fix(security): parameterize search_devices() query to prevent SQL injection`

Después de cada commit, relanza el workflow (`workflow_dispatch` o un push)
y observa qué job pasa de rojo a verde. Guarda una captura de cada
transición — son exactamente las capturas "antes/después" que pide el
README para la sección de resultados.

## Sobre los hallazgos de OWASP ZAP (DAST)

A diferencia de las tres vulnerabilidades anteriores, los hallazgos de ZAP
(cabeceras de seguridad ausentes: `Content-Security-Policy`,
`X-Content-Type-Options`, `Strict-Transport-Security`, ...) no se han
introducido "a propósito" en el sentido de una línea de código concreta:
son el estado por defecto de cualquier API FastAPI a la que no se le ha
añadido un middleware de cabeceras. Se documentan aquí porque son un
ejemplo perfecto de por qué el DAST es complementario al SAST: ningún
análisis estático del código Python iba a decirte que faltan cabeceras
HTTP en las respuestas reales.

**Fix — aplicado.** Este fue deliberadamente el último ejercicio del
proyecto, dejado fuera del código base hasta cerrar el resto del pipeline.
Un run real de `07 · DAST — OWASP ZAP (OpenAPI scan)` contra la API viva en
el runner confirmó, con hallazgos reales (no simulados), que faltaban
exactamente `X-Content-Type-Options` y `Cross-Origin-Resource-Policy` — el
resto de cabeceras de abajo se añadieron por buena práctica adicional para
una API JSON pura sin frontend renderizado en navegador.

El fix es un middleware en `app/main.py` (justo después de instanciar
`FastAPI(...)`) que fija cabeceras de seguridad en cada respuesta:

```python
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    # No browser-rendered frontend ships from this origin, so a maximally
    # restrictive CSP is correct here rather than a permissive default.
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    response.headers["Strict-Transport-Security"] = (
        "max-age=63072000; includeSubDomains"
    )
    return response
```

Verificado localmente antes de subirlo: suite de tests (11/11) sigue en
verde, y un servidor uvicorn real contra `GET /health` devuelve las 5
cabeceras en la respuesta:

```
$ curl -sI http://127.0.0.1:8123/health
HTTP/1.1 200 OK
x-content-type-options: nosniff
x-frame-options: DENY
cross-origin-resource-policy: same-origin
content-security-policy: default-src 'none'
strict-transport-security: max-age=63072000; includeSubDomains
```

Commit:

```
fix(security): add hardening HTTP response headers (OWASP ZAP findings)
```
