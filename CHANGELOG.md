# Changelog — Shorless PQC & CBOM Scanner

## [v0.9.5] — 2026-10-31 : Authentification SaaS (--api-key) & Pull Requests Automatiques (--auto-pr)
- Ajout de l'authentification SaaS (--api-key / SHORLESS_API_KEY) reliée à l'endpoint api_verify.php
- Ajout de l'option --auto-pr pour créer une branche Git dédiée et ouvrir automatiquement les Pull Requests de remédiation PQC
- Mise à jour de la GitHub Action officielle (action.yml) avec injection automatique de GITHUB_TOKEN
- Ajout des auto-remdiations de code multi-language

## [v0.9.4] — 2026-10-31 : Support Multi-Langages Backend (C# .NET)
- Ajout du scan statique pour  C# .NET (.cs)
- Validation unitaire automatisée sur 11 cibles (6 langages + 5 formats IaC) dans le CBOM CycloneDX 1.6 et le rapport exécutif HTML/PDF

## [v0.9.3] — 2026-10-31 : Support Multi-Langages Backend (Java, Go, Node.js / TypeScript)
- Ajout du scan Java, Go et Node.js/TS
- Ajout des tests unitaires automatisés multi-langages

## [v0.9.2] — 2026-10-31 : Générateur de Rapport d'Audit Exécutif HTML/PDF (--report-html)
- Ajout de l'option --report-html générant un rapport exécutif HTML/PDF autonome avec Score de Maturité PQC (/100)
- Synthèse de conformité réglementaire ANSSI, NIST FIPS 203/204, NIS 2 et DORA prête pour les RSSI et CTO
- Mise à jour de la documentation CLI, de la GitHub Action et des tests automatisés

## [v0.9.1] — 2026-10-31 : Documentation CLI Complète, GitHub Action Officielle & Auto-Fix Multi-IaC
- Documentation complète de toutes les options CLI (--check-tls, --fix, --dry-run, --cbom, --ci)
- Ajout de la GitHub Action officielle (action.yml) avec upload automatique de l'artefact CBOM
- Support complet et auto-remédiation IaC pour Nginx, Dockerfile, Traefik, Kubernetes Ingress et Terraform

## [v0.9.0] — 2026-10-31 : Auto-Remédiation (--fix) & Support Multi-IaC (Traefik, K8s Ingress, Terraform)
- Ajout du mode d'auto-remédiation --fix et simulation --dry-run pour corriger automatiquement les fichiers IaC
- Extension du scanner aux configurations Traefik, manifestes Kubernetes Ingress (.yml/.yaml) et fichiers Terraform (.tf)
- Synchronisation automatisée de la documentation et du site vers l'hébergement OVH

## [v0.8.7] — 2026-10-31 : Support Multi-Fichiers IaC : Traefik, Kubernetes Ingress & Terraform
- Ajout du scan des configurations Traefik (minVersion TLS 1.3 & curvePreferences X25519MLKEM768)
- Inspection des manifestes Kubernetes Ingress & Cert-Manager (.yaml/.yml)
- Analyse des fichiers Terraform (.tf) pour détecter les clés RSA/ECDSA et politiques Cloud TLS < 1.3

## [v0.8.6] — 2026-10-31 : Support Dockerfile & Inspection TLS Live (--check-tls)
- Ajout du scan des Dockerfiles et détection OpenSSL < 3.2
- Ajout de l'option --check-tls pour auditer un serveur TLS en direct
- Export unifié Code + Infra + Réseau dans le CBOM CycloneDX 1.6

## [v0.8.5] — 2026-10-31 : Support Dockerfile & détection OpenSSL
- Ajout du scan des Dockerfiles
- Détection des versions OpenSSL < 3.2
- Correction automatique du nommage test_env

## [v0.8.4] — 2026-10-31 : Support CycloneDX 1.6 CBOM, détection AST & règles Nginx X25519MLKEM768
- Analyse statique AST Python sans faux positifs (`generate_private_key`, `SECP256R1`, `SHA1`, `MD5`).
- Inspection des configurations TLS Nginx (`ssl_protocols TLSv1.3` et courbe hybride `X25519MLKEM768`).
- Export natif au format standard OWASP CycloneDX 1.6 (`cbom.json`).
- Ajout du drapeau bloqueur `--ci` (`exit code 1`) pour GitHub Actions et GitLab CI.
