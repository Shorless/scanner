# ⚡ Shorless — Post-Quantum (PQC) DevSecOps Scanner & CycloneDX 1.6 CBOM Generator

[![PyPI version](https://img.shields.io/badge/pypi-v0.8.6-10B981.svg)](https://pypi.org/project/shorless/)
[![License](https://img.shields.io/badge/license-Apache%202.0-06B6D4.svg)](https://opensource.org/licenses/Apache-2.0)
[![CycloneDX 1.6](https://img.shields.io/badge/CBOM-CycloneDX%201.6-A855F7.svg)](https://cyclonedx.org/capabilities/cbom/)

**Shorless** (`shorless`) est un scanner statique (AST), d'infrastructure (Nginx, Docker) et réseau (`--check-tls`) Open Source conçu pour aider les équipes DevSecOps de PME et d'ETI à cartographier leur dette cryptographique (RSA, ECDSA, SHA-1, OpenSSL < 3.2, TLS non hybridé) et à préparer leur transition vers la cryptographie post-quantique (**ANSSI** / **NIST FIPS 203 ML-KEM** & **FIPS 204 ML-DSA**).

🔗 **Site officiel & Sandbox interactif :** [https://shorless.io](https://shorless.io)
📘 **Documentation complète du scanner :** [https://shorless.io/scanner-documentation.html](https://shorless.io/scanner-documentation.html)

---

## 🆕 Nouveautés de la version v0.8.6 (Support Dockerfile & Inspection TLS Live (--check-tls))

- Ajout du scan des Dockerfiles et détection OpenSSL < 3.2
- Ajout de l'option --check-tls pour auditer un serveur TLS en direct
- Export unifié Code + Infra + Réseau dans le CBOM CycloneDX 1.6

---

## 🚀 Installation & Utilisation Rapide (PyPI / pipx)

```bash
# 1. Audit complet Code (AST) + Infra (Nginx / Dockerfile) + Export CBOM CycloneDX 1.6
pipx run shorless . --cbom cbom.json

# 2. Audit incluant l'inspection en direct d'un serveur TLS en production
shorless . --check-tls https://shorless.io --cbom cbom.json

# 3. Mode bloqueur CI/CD (renvoie exit code 1 si un risque critique face à Shor est trouvé)
shorless . --cbom cbom.json --ci
```

---

## 📄 Licence

Distribué sous licence **Apache 2.0**. © 2026 Shorless Security.
