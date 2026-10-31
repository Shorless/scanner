# ⚡ Shorless — Post-Quantum (PQC) DevSecOps Scanner & CycloneDX 1.6 CBOM Generator

[![PyPI version](https://img.shields.io/badge/pypi-v0.9.4-10B981.svg)](https://pypi.org/project/shorless/)
[![GitHub Release](https://img.shields.io/badge/release-v0.9.4-06B6D4.svg)](https://github.com/Shorless/scanner/releases/tag/v0.9.4)
[![License](https://img.shields.io/badge/license-Apache%202.0-3B82F6.svg)](https://opensource.org/licenses/Apache-2.0)
[![CycloneDX 1.6](https://img.shields.io/badge/CBOM-CycloneDX%201.6-A855F7.svg)](https://cyclonedx.org/capabilities/cbom/)

**Shorless** (`shorless`) est un scanner statique (AST Python), d'infrastructure (Nginx, Dockerfile, Traefik, Kubernetes Ingress, Terraform), réseau (`--check-tls`) et d'auto-remédiation (`--fix`) Open Source conçu pour aider les équipes DevSecOps de PME et d'ETI à cartographier leur dette cryptographique et préparer leur transition vers la cryptographie post-quantique (**ANSSI** / **NIST FIPS 203 ML-KEM** & **FIPS 204 ML-DSA**).

🔗 **Site officiel & Sandbox interactif :** [https://shorless.io](https://shorless.io)
📘 **Documentation complète CLI & GitHub Action :** [https://shorless.io/scanner-documentation.html](https://shorless.io/scanner-documentation.html)

---

## 🆕 Nouveautés de la version v0.9.4 (Support Multi-Langages Backend (C# .NET))

- Ajout du scan statique pour  C# .NET (.cs)
- Validation unitaire automatisée sur 11 cibles (6 langages + 5 formats IaC) dans le CBOM CycloneDX 1.6 et le rapport exécutif HTML/PDF

---

## 🚀 Installation Rapide (PyPI / pipx)

```bash
# Exécution instantanée sans installation permanente via pipx
pipx run shorless . --cbom cbom.json

# Ou installation / mise à jour globale via PyPI
pip install -U shorless
```

---

## 💻 Référence complète des Commandes & Options CLI

```bash
# 1. Audit complet Code (Python AST) + Multi-IaC + Rapport Exécutif HTML/PDF
shorless ./mon_projet --cbom cbom.json --report-html pqc-report.html

# 2. Inspection en direct d'un endpoint TLS distant (TLS 1.3, KEM hybride X25519MLKEM768 & certificat X.509)
shorless . --check-tls https://shorless.io --cbom cbom-live.json

# 3. Simulation d'auto-remédiation IaC sans modifier les fichiers sur le disque (--dry-run)
shorless ./mon_projet --fix --dry-run

# 4. Application automatique des correctifs PQC sur Nginx, Dockerfile, Traefik, K8s Ingress et Terraform (--fix)
shorless ./mon_projet --fix

# 5. Mode bloqueur CI/CD (renvoie exit code 1 si au moins 1 risque CRITIQUE face à Shor est détecté)
shorless . --check-tls https://api.entreprise.fr --cbom cbom.json --ci
```

| Argument / Option | Type | Défaut | Description |
| :--- | :--- | :--- | :--- |
| `TARGET_DIR` | Argument | `.` | Chemin du dossier projet ou dépôt Git à analyser récursivement (`.py`, `.conf`, `Dockerfile*`, `.yml/.yaml`, `.tf`). |
| `--cbom TEXT` | Option | `cbom.json` | Chemin du fichier JSON généré au standard officiel **OWASP CycloneDX 1.6**. |
| `--report-html TEXT` | Option | `None` | Génère un **Rapport d'Audit Exécutif HTML/PDF** autonome (Score PQC /100, NIS 2, DORA, ANSSI) pour RSSI & CTO. |
| `--check-tls TEXT` | Option | `None` | URL ou `domaine:port` à inspecter en direct (handshake TLS 1.3, groupe hybride `X25519MLKEM768`, certificat X.509). |
| `--fix` | Flag | `False` | Corrige automatiquement les fichiers IaC (Nginx, Dockerfile, Traefik, K8s Ingress, Terraform) vers TLS 1.3 & ML-KEM. |
| `--dry-run` | Flag | `False` | Simule l'option `--fix` et affiche les correctifs prévus dans le terminal sans modifier aucun fichier sur le disque. |
| `--ci` | Flag | `False` | Interrompt le pipeline CI/CD (`exit code 1`) si au moins une vulnérabilité `CRITIQUE` est détectée. |
| `--help` | Flag | - | Affiche l'aide interactive et la liste complète des options dans le terminal. |

---

## 🤖 Intégration GitHub Action Officielle (`Shorless/scanner@v0.9.4`)

Ajoutez ce workflow dans `.github/workflows/shorless-pqc.yml` pour auditer chaque Pull Request et archiver automatiquement le CBOM CycloneDX 1.6 :

```yaml
name: Post-Quantum Readiness & CBOM Audit
on: [push, pull_request]

jobs:
  shorless-pqc-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Run Shorless PQC & CBOM Scanner
        uses: Shorless/scanner@v0.9.4
        with:
          target-dir: "."
          output-cbom: "cbom-cyclonedx.json"
          check-tls: "https://shorless.io"
          auto-fix: "false"
          dry-run: "true"
          fail-on-critical: "true"
          upload-artifact: "true"
```

### Paramètres (`inputs`) de la GitHub Action

| Input | Requis | Défaut | Option CLI associée & Description |
| :--- | :--- | :--- | :--- |
| `target-dir` | Non | `"."` | Répertoire projet à analyser (`TARGET_DIR`). |
| `output-cbom` | Non | `"cbom.json"` | Chemin du fichier CBOM CycloneDX 1.6 généré (`--cbom`). |
| `report-html` | Non | `"pqc-report.html"` | Chemin du rapport d'audit exécutif HTML/PDF généré (`--report-html`). |
| `check-tls` | Non | `""` | Endpoint TLS distant à auditer en direct (`--check-tls`). |
| `auto-fix` | Non | `"false"` | Applique automatiquement les correctifs PQC sur les fichiers IaC (`--fix`). |
| `dry-run` | Non | `"false"` | Prévisualise les patchs IaC dans les logs sans modifier les fichiers (`--dry-run`). |
| `fail-on-critical` | Non | `"true"` | Bloque la Pull Request (`exit code 1`) si un risque critique est trouvé (`--ci`). |
| `upload-artifact` | Non | `"true"` | Téléverse automatiquement le fichier `cbom.json` en artefact de build GitHub Actions. |

---

## 📄 Licence

Distribué sous licence **Apache 2.0**. © 2026 Shorless Security.
