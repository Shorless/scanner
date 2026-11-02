# ⚡ Shorless — Post-Quantum (PQC) DevSecOps Scanner, Auto-PR & CycloneDX 1.6 CBOM Generator

[![PyPI version](https://img.shields.io/badge/pypi-v1.0.0-10B981.svg)](https://pypi.org/project/shorless/)
[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-Shorless%20PQC%20Action-2088FF.svg?logo=github-actions&logoColor=white)](https://github.com/marketplace/actions/shorless-pqc-cyclonedx-1-6-cbom-scanner)
[![GitHub Release](https://img.shields.io/badge/release-v1.0.0-06B6D4.svg)](https://github.com/Shorless/scanner/releases/tag/v1.0.0)
[![License](https://img.shields.io/badge/license-Apache%202.0-3B82F6.svg)](https://opensource.org/licenses/Apache-2.0)
[![CycloneDX 1.6](https://img.shields.io/badge/CBOM-CycloneDX%201.6-A855F7.svg)](https://cyclonedx.org/capabilities/cbom/)
[![PQC Score](https://shorless.io/api_badge.php?project=Shorless/scanner)](https://shorless.io/dashboard.html)

**Shorless** (`shorless`) est un scanner statique multi-langages (**Python AST, Java, Go, Node.js, TypeScript, C# .NET**), d'infrastructure (**Nginx, Dockerfile, Traefik, Kubernetes Ingress, Terraform**), réseau (`--check-tls`) et d'auto-remédiation (`--fix` / `--auto-pr`) conçu pour aider les équipes DevSecOps, RSSI et CTO à cartographier leur dette cryptographique et automatiser leur migration vers la cryptographie post-quantique (**ANSSI** / **NIST FIPS 203 ML-KEM** & **FIPS 204 ML-DSA**).

🔗 **Site officiel & Sandbox interactif :** [https://shorless.io](https://shorless.io)
☁️ **Console SaaS CBOM & Télémétrie CI/CD :** [https://shorless.io/dashboard.html](https://shorless.io/dashboard.html)
📘 **Documentation complète CLI & GitHub Action :** [https://shorless.io/scanner-documentation.html](https://shorless.io/scanner-documentation.html)

---

## 🆕 Nouveautés de la version v1.0.0 (Version Majeure 1.0.0 — Simulateur MTU, Envoy/Istio/SSH, Audit JWT/OIDC, Diff PQC & Attestation NIS 2 / DORA)

- Simulateur d'impact réseau MTU (1 500 octets) et fragmentation TCP/TLS (--simulate-mtu) comparant X25519MLKEM768, ML-DSA-65 et les Merkle Tree Certificates (MTC)
- Inspection et auto-remédiation des proxys Cloud-Native (Envoy Proxy, Istio, HAProxy) et d'OpenSSH (sshd_config, ssh_config avec KexAlgorithms mlkem768x25519-sha256)
- Détection des signatures JWT/OIDC asymétriques (RS256, ES256, PS256) sur les 6 langages Backend et inspection X.509 approfondie (algorithme, taille de clé, date d'expiration)
- Console SaaS v1.0.0 : Comparateur temporel Diff PQC (+X pts / risques éliminés), générateur d'Attestation de Conformité NIS 2 / DORA en 1 clic et Monitoring Externe des Endpoints TLS (api_tls_monitor.php).

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
# 1. Audit complet Code (6 langages) + Infra (5 formats IaC) + Rapport Exécutif HTML/PDF
shorless ./mon_projet --cbom cbom.json --report-html pqc-report.html

# 2. Inspection en direct d'un endpoint TLS distant (TLS 1.3, KEM hybride X25519MLKEM768 & certificat X.509)
shorless . --check-tls https://shorless.io --cbom cbom-live.json

# 3. Simulation d'auto-remédiation sur les 11 technologies sans modifier les fichiers (--dry-run)
shorless ./mon_projet --fix --dry-run

# 4. Application automatique des correctifs PQC sur le code et l'IaC (--fix)
shorless ./mon_projet --fix

# 5. Synchronisation Cloud SaaS + Auto-Remédiation + Ouverture automatique d'une Pull Request GitHub (--auto-pr)
shorless ./mon_projet --api-key VOTRE_CLE_SAAS --fix --auto-pr --pr-base main

# 6. Mode bloqueur CI/CD (renvoie exit code 1 si au moins 1 risque CRITIQUE face à Shor est détecté)
shorless . --check-tls https://api.entreprise.fr --cbom cbom.json --ci
```

| Argument / Option | Type | Défaut | Description |
| :--- | :--- | :--- | :--- |
| `TARGET_DIR` | Argument | `.` | Dossier projet analysé récursivement (`.py`, `.java`, `.go`, `.js`, `.ts`, `.cs`, `.conf`, `Dockerfile*`, `.yml/.yaml`, `.tf`). |
| `--cbom TEXT` | Option | `cbom.json` | Chemin du fichier JSON généré au standard officiel **OWASP CycloneDX 1.6**. |
| `--sarif TEXT` | Option | `None` | Génère un rapport **OASIS SARIF 2.1.0** pour annoter les Pull Requests dans GitHub Code Scanning. |
| `--project TEXT` | Option | `Auto` | Nom du projet/dépôt Git pour segmenter la télémétrie dans la Console SaaS et générer le badge SVG. |
| `--webhook-url TEXT` | Option | `None` | URL de Webhook **Slack / Microsoft Teams / Discord** pour recevoir une alerte de score PQC. |
| `--report-html TEXT` | Option | `None` | Génère un **Rapport d'Audit Exécutif HTML/PDF** autonome (Score PQC /100, NIS 2, DORA, ANSSI) pour RSSI & CTO. |
| `--check-tls TEXT` | Option | `None` | URL ou `domaine:port` à inspecter en direct (handshake TLS 1.3, groupe hybride `X25519MLKEM768`, certificat X.509). |
| `--fix` | Flag | `False` | Corrige automatiquement les 11 technologies (6 langages Backend + 5 formats IaC) vers TLS 1.3 & ML-KEM (FIPS 203). |
| `--dry-run` | Flag | `False` | Simule l'option `--fix` et affiche les correctifs prévus dans le terminal sans modifier aucun fichier sur le disque. |
| `--api-key TEXT` | Option | `None` | Clé d'API Shorless SaaS pour synchroniser le Score PQC avec la Console Cloud (`https://shorless.io/dashboard.html`). |
| `--auto-pr` | Flag | `False` | Crée une branche Git `shorless-pqc-fix-...`, commit les patchs `--fix` et ouvre automatiquement une Pull Request GitHub. |
| `--pr-base TEXT` | Option | `main` | Branche cible pour la Pull Request automatique ouverte par `--auto-pr`. |
| `--verbose` / `-v` | Flag | `False` | Affiche la liste des fichiers analysés, leur type détecté et la probabilité (%) qu'ils contiennent des références cryptographiques. |
| `--ci` | Flag | `False` | Interrompt le pipeline CI/CD (`exit code 1`) si au moins une vulnérabilité `CRITIQUE` est détectée. |
| `--help` | Flag | - | Affiche l'aide interactive et la liste complète des options dans le terminal. |

---

## 🤖 Intégration GitHub Action Officielle (`Shorless/scanner@v0` / `@v1.0.0`)

Disponible sur le **[GitHub Marketplace](https://github.com/marketplace/actions/shorless-pqc-cyclonedx-1-6-cbom-scanner)**. Ajoutez ce workflow dans `.github/workflows/shorless-pqc.yml` :

```yaml
name: Post-Quantum Readiness, Auto-PR & CBOM Audit
on:
  push:
    branches: [ main ]
  pull_request:

permissions:
  contents: write
  pull-requests: write

jobs:
  shorless-pqc-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Run Shorless PQC Scanner & Auto-PR
        uses: Shorless/scanner@v0
        with:
          target-dir: "."
          output-cbom: "cbom-cyclonedx.json"
          report-html: "pqc-report.html"
          check-tls: "https://shorless.io"
          api-key: ${{ secrets.SHORLESS_API_KEY }}
          auto-fix: "true"
          auto-pr: "true"
          pr-base: "main"
          dry-run: "false"
          fail-on-critical: "false"
          upload-artifact: "true"
```

### Paramètres (`inputs`) de la GitHub Action

| Input | Requis | Défaut | Option CLI associée & Description |
| :--- | :--- | :--- | :--- |
| `target-dir` | Non | `"."` | Répertoire projet à analyser (`TARGET_DIR`). |
| `output-cbom` | Non | `"cbom.json"` | Chemin du fichier CBOM CycloneDX 1.6 généré (`--cbom`). |
| `report-html` | Non | `"pqc-report.html"` | Chemin du rapport d'audit exécutif HTML/PDF généré (`--report-html`). |
| `check-tls` | Non | `""` | Endpoint TLS distant à auditer en direct (`--check-tls`). |
| `api-key` | Non | `""` | Clé d'API Shorless SaaS pour activer la télémétrie Cloud et l'ouverture de Pull Requests (`--api-key`). |
| `auto-fix` | Non | `"false"` | Applique automatiquement les correctifs PQC sur les 11 technologies Code & IaC (`--fix`). |
| `auto-pr` | Non | `"false"` | Pousse une branche dédiée et ouvre automatiquement une Pull Request GitHub (`--auto-pr`). |
| `pr-base` | Non | `"main"` | Branche de base cible pour la Pull Request automatique (`--pr-base`). |
| `dry-run` | Non | `"false"` | Prévisualise les patchs dans les logs sans modifier les fichiers (`--dry-run`). |
| `verbose` | Non | `"false"` | Affiche l'inventaire des fichiers analysés, leur type et leur probabilité crypto (`--verbose`). |
| `fail-on-critical` | Non | `"true"` | Bloque la Pull Request (`exit code 1`) si un risque critique est trouvé (`--ci`). |
| `upload-artifact` | Non | `"true"` | Téléverse automatiquement les rapports `cbom.json` et `pqc-report.html` en artefacts GitHub Actions. |

---

## 📊 Score de Maturité PQC & Console SaaS CBOM

Le score de maturité Post-Quantique (0 à 100) est calculé selon une courbe d'amortissement pondérée prenant en compte les vulnérabilités résiduelles (recalculée automatiquement après `--fix`) :

```text
Score PQC = round( 100 * (100 / (100 + 12 * N_critiques + 4 * N_autres)) )
```

- **100/100 (Grade A)** : Zéro vulnérabilité quantique détectée (conforme aux recommandations ANSSI / NIST FIPS 203).
- **Console Cloud SaaS** : Consultez l'historique de vos audits CI/CD et inspectez vos rapports CBOM sur **[https://shorless.io/dashboard.html](https://shorless.io/dashboard.html)**.

---

## 📄 Licence

Distribué sous licence **Apache 2.0**. © 2026 Shorless Security.
