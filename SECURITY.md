# Política de seguridad y divulgación coordinada de vulnerabilidades

Este documento es la política de *Coordinated Vulnerability Disclosure* (CVD)
de este repositorio. Existe porque la Cyber Resilience Act exige explícitamente
que un fabricante de software tenga una (Anexo I, Parte II, punto 5) — ver
[`CRA_MAPPING.md`](CRA_MAPPING.md). Es una pieza de portafolio: el repositorio
es un proyecto educativo, pero el proceso descrito aquí es el mismo que se
esperaría de un producto real.

## Alcance

Aplica a la Fleet Compliance API (`app/`), a los workflows de CI/CD
(`.github/workflows/`) y a la configuración de las herramientas de seguridad
incluidas en este repositorio.

**Fuera de alcance:** las 3 vulnerabilidades documentadas intencionadamente en
[`docs/VULNERABILITIES.md`](docs/VULNERABILITIES.md) — ya son conocidas,
están documentadas públicamente y su corrección es parte del ejercicio del
proyecto. No hace falta reportarlas.

## Cómo reportar una vulnerabilidad

1. **No abras un issue público.** Usa la pestaña
   [**Security → Report a vulnerability**](../../security/advisories/new)
   de GitHub (Security Advisories), que crea un espacio privado de discusión.
2. Si por algún motivo esa vía no está disponible, contacta directamente con
   el mantenedor indicado en el perfil del repositorio.
3. Incluye, si es posible:
   - Descripción del problema y su impacto potencial.
   - Pasos para reproducirlo (endpoint, payload, precondiciones).
   - Versión/commit afectado.

## Qué puedes esperar

| Hito | Plazo objetivo |
|---|---|
| Confirmación de recepción | 3 días hábiles |
| Evaluación inicial de severidad (CVSS) | 7 días hábiles |
| Corrección o plan de mitigación | Según severidad (crítica/alta: prioridad inmediata) |
| Divulgación pública tras el fix | Coordinada con quien reporta, nunca antes de que exista una corrección disponible |

Este es un proyecto personal de portafolio, no un producto con SLA
contractual — los plazos anteriores son el compromiso razonable que se
aplicaría en un contexto profesional, y reflejan el espíritu del Anexo I,
Parte II, punto 2 de la CRA ("abordar y remediar las vulnerabilidades sin
demora indebida").

## Divulgación pública de vulnerabilidades corregidas

Una vez publicada una corrección, se documentará en el historial de commits
(`fix: ...`) y, para hallazgos relevantes, en las
[GitHub Security Advisories](../../security/advisories) del repositorio,
incluyendo: descripción, severidad, versiones/commits afectados, y la
corrección aplicada — en línea con el Anexo I, Parte II, punto 4 de la CRA.

## Gestión de dependencias de terceros

Las vulnerabilidades en dependencias de terceros (por ejemplo, una futura
CVE en FastAPI o en la imagen base de Docker) se gestionan igual que las
propias: el job semanal programado del pipeline (`schedule: cron`) las
detecta automáticamente sin necesidad de un nuevo commit, y se corrigen
actualizando el pin de versión correspondiente.
