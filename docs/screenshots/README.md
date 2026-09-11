# Capturas

Capturas reales de ejecuciones de este pipeline en GitHub Actions,
enlazadas desde el `README.md` principal:

| Archivo | Qué muestra |
|---|---|
| `01-pipeline-red.png` | La primera ejecución del workflow, en rojo, mostrando los jobs `01`, `02` y `03` fallando por las 3 vulnerabilidades intencionadas |
| `02-pipeline-green.png` | La ejecución posterior a aplicar los 4 fixes de `docs/VULNERABILITIES.md` (incluido el middleware de cabeceras), con los 9 jobs en verde |
| `03-security-tab.png` | La pestaña **Security → Code scanning** del repositorio, mostrando las alertas SARIF de Semgrep, Gitleaks y Trivy agregadas por GitHub |
| `04-artifacts.png` | La lista de artifacts de una ejecución (`report-semgrep`, `report-gitleaks`, `report-trivy-dependencies`, `report-trivy-image`, `report-sbom`, `report-zap`, `security-reports-<sha>`) |
| `05-sbom-preview.png` | Un fragmento del SBOM CycloneDX generado (por ejemplo abierto con `jq` o en un visor CycloneDX) mostrando la dependencia `PyYAML` |
| `06-zap-report.png` | El informe HTML de OWASP ZAP mostrando los hallazgos de cabeceras de seguridad ausentes |

Todas en PNG, recortadas a la zona relevante y revisadas para no exponer
tokens ni datos sensibles.
