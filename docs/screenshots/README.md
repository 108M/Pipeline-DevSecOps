# Capturas pendientes

Esta carpeta está preparada para recibir capturas reales una vez el
pipeline se ejecute en GitHub Actions (no se han generado en este commit
porque el proyecto se ha construido sin hacer push al repositorio remoto).

Cuando hagas push y lo ejecutes, añade aquí, con estos nombres exactos
(el `README.md` principal ya enlaza a ellos):

| Archivo | Qué capturar |
|---|---|
| `01-pipeline-red.png` | La primera ejecución del workflow, en rojo, mostrando los jobs `01`, `02` y `03` fallando por las 3 vulnerabilidades intencionadas |
| `02-pipeline-green.png` | Una ejecución posterior a aplicar los 4 fixes de `docs/VULNERABILITIES.md`, con los 8 jobs en verde |
| `03-security-tab.png` | La pestaña **Security → Code scanning** del repositorio, mostrando las alertas SARIF de Semgrep, Gitleaks y Trivy agregadas por GitHub |
| `04-artifacts.png` | La lista de artifacts de una ejecución (`report-semgrep`, `report-gitleaks`, `report-trivy-dependencies`, `report-trivy-image`, `report-sbom`, `report-zap`, `security-reports-<sha>`) |
| `05-sbom-preview.png` | Un fragmento del SBOM CycloneDX generado (por ejemplo abierto con `jq` o en un visor CycloneDX) mostrando la dependencia `PyYAML` |
| `06-zap-report.png` | El informe HTML de OWASP ZAP mostrando los hallazgos de cabeceras de seguridad ausentes |

Formato recomendado: PNG, recorte a la zona relevante (no full-screen), sin
información sensible visible (tokens, nombres de organización privados, etc.).
