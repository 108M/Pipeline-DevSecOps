# Mapeo del pipeline con la Cyber Resilience Act (CRA)

> **Regulación de referencia:** Reglamento (UE) 2024/2847 del Parlamento
> Europeo y del Consejo, de 23 de octubre de 2024, sobre requisitos de
> ciberseguridad horizontales para productos con elementos digitales
> ("Cyber Resilience Act"), DO L, 2024/2847, 20.11.2024.
>
> **Aviso de alcance:** este documento es una pieza de portafolio educativa,
> no un dictamen legal ni una evaluación de conformidad. El mapeo está hecho
> de buena fe sobre el texto público de la CRA, pero para cualquier uso real
> de cumplimiento normativo debe verificarse contra el texto oficial en
> [EUR-Lex](https://eur-lex.europa.eu/eli/reg/2024/2847/oj) y, en su caso,
> con asesoría legal especializada. El objetivo aquí es demostrar que sé
> **leer un marco regulatorio de seguridad y traducirlo a controles técnicos
> concretos** — la habilidad que un equipo de GRC/AppSec necesita.

## ¿Por qué importa esto para una API como esta?

La CRA aplica a "productos con elementos digitales", una categoría que
incluye tanto software como hardware conectado. La Fleet Compliance API de
este repositorio no es casualidad: es un ejemplo de exactamente el tipo de
sistema que una organización necesita para cumplir la CRA en la práctica —
llevar inventario de los dispositivos que fabrica u opera y de la versión de
firmware que corre en cada uno. El pipeline de este repositorio, a su vez,
es cómo se construye *ese mismo software* cumpliendo la CRA.

## Calendario de aplicación (contexto)

| Fecha | Qué entra en vigor |
|---|---|
| 11 dic 2024 | Entrada en vigor del reglamento |
| 11 sept 2026 | Obligaciones de notificación de incidentes/vulnerabilidades activamente explotadas (Art. 14) |
| 11 dic 2027 | Aplicación plena de todos los requisitos, incluidos los esenciales del Anexo I |

---

## 1. Mapa por etapa del pipeline

| # | Job del pipeline | Herramienta | Qué detecta en esta app | Requisito CRA | Referencia |
|---|---|---|---|---|---|
| 1 | `01 · SAST (Semgrep)` | Semgrep | Inyección SQL en `search_devices()` (Vulnerabilidad 3) | Productos "sin vulnerabilidades explotables conocidas" en el momento de la comercialización; diseño para minimizar superficies de ataque | Anexo I, Parte I, punto 2(a) y 2(i) |
| 2 | `02 · Secrets (Gitleaks)` | Gitleaks | Secreto de firma JWT y contraseña por defecto hardcodeados (Vulnerabilidad 2) | Configuración segura por defecto; control de acceso mediante mecanismos de autenticación adecuados | Anexo I, Parte I, punto 2(b) y 2(c) |
| 3 | `03 · SCA — dependencies (Trivy)` | Trivy (filesystem) | Dependencia desactualizada con CVE pública (PyYAML, Vulnerabilidad 1) | Identificación y documentación de vulnerabilidades en componentes de terceros; remediación sin demora indebida | Anexo I, Parte II, puntos 1 y 2 |
| 4 | `05 · Container image scan (Trivy)` | Trivy (image) | Vulnerabilidades en paquetes del SO base y en la imagen final que realmente se despliega | Igual que el anterior, aplicado al artefacto de despliegue real, no solo al código fuente | Anexo I, Parte II, puntos 1 y 2 |
| 5 | `06 · SBOM (Syft)` | Syft (CycloneDX) | Inventario completo y máquina-legible de todos los componentes (directos y transitivos) de la imagen | **Obligación explícita de generar un SBOM** en un formato estándar y de uso común | Anexo I, Parte II, punto 1; Art. 13 |
| 6 | `07 · DAST (OWASP ZAP)` | OWASP ZAP (baseline) | Cabeceras de seguridad ausentes, problemas de configuración observables solo en runtime | Aplicación de pruebas y revisiones de seguridad efectivas y periódicas sobre el producto en ejecución | Anexo I, Parte II, punto 3 |
| 7 | `08 · Publish security reports` | (agregación) | Consolida SARIF/JSON/SBOM como artifacts + resumen en cada ejecución | Documentación técnica y trazabilidad de la gestión de vulnerabilidades a lo largo del ciclo de vida | Art. 13; Anexo VII (documentación técnica) |
| 8 | Ejecución programada semanal (`schedule: cron`) | Todo lo anterior | Vulnerabilidades nuevas en dependencias/imagen ya publicadas, sin necesidad de un cambio de código | Direccionar vulnerabilidades **sin demora indebida durante todo el periodo de soporte**, no solo en el momento del release | Anexo I, Parte II, punto 2 |
| 9 | `SECURITY.md` (política CVD) | — | Canal privado de reporte, plazos de respuesta, divulgación coordinada tras el fix | Política de divulgación coordinada de vulnerabilidades | Anexo I, Parte II, punto 5 |
| 10 | `docs/VULNERABILITIES.md` (fixes documentados) | — | Descripción pública de cada vulnerabilidad, su severidad y su corrección | Divulgar públicamente información sobre vulnerabilidades corregidas una vez hay una actualización disponible | Anexo I, Parte II, punto 4 |

---

## 2. Mapa por requisito esencial (Anexo I, Parte I)

El Anexo I, Parte I enumera las propiedades de ciberseguridad que debe tener
todo producto con elementos digitales. Esta tabla es más honesta: algunos
puntos los cubre directamente el pipeline/la app, y otros son
organizativos — se documenta explícitamente cuando este proyecto **no** los
resuelve por sí solo, porque fingir cobertura total sería justo el tipo de
"security theater" que un revisor técnico detecta a la primera.

| Punto | Requisito (resumen) | Cobertura en este proyecto |
|---|---|---|
| 2(a) | Sin vulnerabilidades explotables conocidas al comercializarse | ✅ Parcial — SAST + SCA + escaneo de imagen antes de cada release; no elimina el riesgo de día 0 |
| 2(b) | Configuración segura por defecto | ⚠️ Documentado como gap intencionado (Vulnerabilidad 2) + fix propuesto en `docs/VULNERABILITIES.md` |
| 2(c) | Protección frente a acceso no autorizado (auth/identidad) | ✅ JWT + hashing bcrypt de contraseñas; ⚠️ gestión del secreto de firma es el propio hallazgo 2 |
| 2(d) | Confidencialidad de datos almacenados/transmitidos | ❌ Fuera de alcance de este demo — no hay TLS terminado en la app (se delegaría a un reverse proxy/ingress en producción); mencionado como trabajo futuro en el README |
| 2(e) | Integridad de datos, comandos, programas y configuración | ✅ Parcial — consultas parametrizadas salvo el hallazgo 3; validación de entrada vía Pydantic |
| 2(f) | Minimización de datos procesados | ✅ El modelo de datos (`devices`, `users`) solo guarda lo estrictamente necesario para el caso de uso |
| 2(g) | Disponibilidad de funciones esenciales, resiliencia ante DoS | ❌ No implementado (rate limiting, timeouts) — trabajo futuro |
| 2(h) | No degradar la disponibilidad de otros servicios/dispositivos | N/A para este demo (no hay integraciones salientes) |
| 2(i) | Minimizar superficies de ataque, incluidas interfaces externas | ✅ Imagen mínima (`python:3.12-slim`), usuario no-root, solo el puerto 8000 expuesto |
| 2(j) | Mecanismos de mitigación de explotación | ⚠️ No hay WAF/mitigaciones en runtime en este demo; el hardening de cabeceras queda como ejercicio (ver `docs/VULNERABILITIES.md`) |
| 2(k) | Registro de actividad relevante para la seguridad (logging) | ❌ No implementado — trabajo futuro (ver README, "Qué añadiría con más tiempo") |
| 2(l) | Posibilidad de actualizaciones de seguridad | ✅ El propio pipeline (imagen versionada por commit SHA + reconstrucción automática) es el mecanismo de entrega de parches |

---

## 3. Obligaciones del fabricante (Art. 10-14) y su equivalente aquí

| Obligación CRA | Artículo | Cómo se demuestra en este repositorio |
|---|---|---|
| Evaluación de riesgos de ciberseguridad antes de comercializar | Art. 10(2) | El propio pipeline actúa como puerta de salida (*gate*) antes de cualquier despliegue: no hay forma de "comercializar" (mergear a `main`) sin pasar los 8 jobs |
| Diligencia debida sobre componentes de terceros integrados | Art. 10(4) | SBOM (Syft) + escaneo de dependencias (Trivy) documentan exactamente qué se integra y con qué vulnerabilidades conocidas |
| Documentación técnica | Art. 10(7), Anexo VII | Este mismo documento + `docs/VULNERABILITIES.md` + los reports SARIF/JSON/SBOM publicados como artifacts en cada ejecución |
| Gestión de vulnerabilidades durante el periodo de soporte | Art. 13(8)-(10) | Ejecución programada semanal del pipeline (`cron`), independiente de nuevos commits |
| Notificación de vulnerabilidades activamente explotadas a ENISA en 24h | Art. 14(1)-(2) | Fuera de alcance técnico de un repo de portafolio (requiere integración con CSIRT/ENISA); el proceso equivalente a nivel de proyecto es `SECURITY.md` |
| Política de divulgación coordinada de vulnerabilidades | Anexo I, Parte II, punto 5 | `SECURITY.md` |
| SBOM en formato estándar máquina-legible | Anexo I, Parte II, punto 1 | Job `06 · SBOM (Syft)`, formato CycloneDX JSON |

---

## 4. Por qué CycloneDX y no SPDX

La CRA no impone un formato concreto de SBOM, solo exige que sea "en un
formato de uso común y legible por máquina, que cubra como mínimo las
dependencias de primer nivel" (Anexo I, Parte II, punto 1). Este proyecto
usa **CycloneDX** (generado con Syft) por tres motivos prácticos:

1. Es el formato nativo de OWASP y el más extendido en tooling de seguridad
   de aplicaciones (frente a SPDX, más orientado a cumplimiento de licencias).
2. Integra directamente con escáneres de vulnerabilidades de segunda etapa
   (Grype, Dependency-Track) sin conversión.
3. Su especificación incluye campos pensados explícitamente para
   vulnerabilidades (`vulnerabilities` field, VEX), lo que encaja mejor con
   el caso de uso de esta pipeline que un formato centrado en licencias.

## 5. Limitaciones honestas de este mapeo

- Este proyecto demuestra los **controles técnicos** de la CRA (SBOM,
  gestión de vulnerabilidades, pruebas de seguridad). No cubre las
  obligaciones puramente administrativas: marcado CE, declaración UE de
  conformidad, designación de un organismo notificado para productos
  críticos, o el registro ante autoridades de vigilancia de mercado.
- La CRA distingue entre productos "importantes" (Clase I/II) y "críticos",
  con requisitos de evaluación de conformidad distintos (autoevaluación vs.
  evaluación por tercero). Este demo no clasifica la Fleet Compliance API
  en ninguna categoría — es un ejercicio educativo, no un producto real
  sujeto a comercialización.
- Ninguna herramienta de este pipeline certifica cumplimiento normativo por
  sí sola. Son controles técnicos que **sustentan** la evidencia que luego
  necesitaría un proceso de conformidad real.
