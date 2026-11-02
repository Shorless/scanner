# Changelog — Shorless PQC & CBOM Scanner

## [v1.0.0] — 2026-11-02 : Version Majeure 1.0.0 — Simulateur MTU, Envoy/Istio/SSH, Audit JWT/OIDC, Diff PQC & Attestation NIS 2 / DORA
- Simulateur d'impact réseau MTU (1 500 octets) et fragmentation TCP/TLS (--simulate-mtu) comparant X25519MLKEM768, ML-DSA-65 et les Merkle Tree Certificates (MTC)
- Inspection et auto-remédiation des proxys Cloud-Native (Envoy Proxy, Istio, HAProxy) et d'OpenSSH (sshd_config, ssh_config avec KexAlgorithms mlkem768x25519-sha256)
- Détection des signatures JWT/OIDC asymétriques (RS256, ES256, PS256) sur les 6 langages Backend et inspection X.509 approfondie (algorithme, taille de clé, date d'expiration)
- Console SaaS v1.0.0 : Comparateur temporel Diff PQC (+X pts / risques éliminés), générateur d'Attestation de Conformité NIS 2 / DORA en 1 clic et Monitoring Externe des Endpoints TLS (api_tls_monitor.php).

## [v0.9.8] — 2026-11-02 : SCA Tous Langages, Héritages IaC, SARIF 2.1.0 & Multi-Projets
- Test complet v0.9.8

## [v0.9.7] — 2026-11-02 : Mode Inventaire Verbeux (--verbose) & Probabilité d'Exposition Crypto
- Ajout de l'option CLI --verbose (-v) affichant la liste détaillée des fichiers analysés, leur technologie détectée et la probabilité heuristique (%) de présence cryptographique
- Ajout de l'input verbose dans la GitHub Action officielle (action.yml) et mise à jour de l'alias @v0
- Mise à jour complète de la documentation utilisateur (scanner-documentation.html et README.md).

## [v0.9.6] — 2026-10-31 : Auto-PR Multi-Langages (11 cibles), Console SaaS CBOM & GitHub Marketplace
- Extension de l'auto-remédiation (--fix et --auto-pr) aux 11 technologies (6 langages Backend + 5 formats IaC).
- Fiabilisation de la création automatique de branches Git (shorless-pqc-fix-...) et ouverture de Pull Requests GitHub.
- Déploiement de la Console SaaS CBOM (dashboard.html) avec courbe de Score PQC amortie et licences Pro Entreprise illimitées.
- Publication officielle sur le GitHub Marketplace avec support du tag majeur flottant @v0.

## [v0.9.5] — 2026-10-31 : Authentification SaaS (--api-key) & Pull Requests Automatiques (--auto-pr)
- Ajout des options CLI --api-key, --auto-pr et --pr-base pour synchroniser les audits CI/CD avec Shorless SaaS.
- Mise à jour de la GitHub Action officielle (action.yml) avec prise en charge automatique de GITHUB_TOKEN.
- Support des clés d'essai (14 jours) et des clés Pro Entreprise illimitées.

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
