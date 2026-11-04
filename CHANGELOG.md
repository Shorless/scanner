# Changelog — Shorless PQC & CBOM Scanner

## [v1.0.2] — 2026-11-04 : Formulaire Contact (contact@shorless.io), Tchat Bot IA Gemini Flash 3.8 & Décrochage Conseiller Humain
- Ajout du formulaire de contact commercial et support technique (api_contact.php) envoyant directement les demandes à contact@shorless.io avec accusé de réception client et journalisation Zero-PII.
- Intégration du Tchat Bot IA propulsé par Gemini Flash 3.8 (api_chatbot.php + shorless-assistant-widget.js) entraîné sur l'ensemble des fonctionnalités Shorless.
- Ajout du mode décrochage en 1 clic vers un conseiller humain dans le tchat avec transfert instantané de l'historique de conversation à contact@shorless.io.
- Compatibilité Python 3.14 (installation automatique de setuptools/wheel et gestion tolérante de twine upload --skip-existing).

## [v1.0.1] — 2026-11-04 : Support Bilingue FR/EN (--lang), Barème de Crédits Unifié (500 Crédits Offerts), Conformité CGV/CGU & Suppression RGPD
- Ajout de l'option CLI --lang (-l fr|en) et de la variable d'environnement SHORLESS_LANG=en pour exécuter le scanner, les tableaux Rich et la télémétrie SaaS en Français ou en Anglais.
- Ajout de l'input lang ('fr' ou 'en') dans la GitHub Action officielle (action.yml) et support bilingue complet dans la Console SaaS (dashboard.html) et la documentation.
- Alignement sur le modèle par crédits (500 crédits offerts à l'essai, 5 crédits/scan CI/CD, 15 crédits avec --auto-pr, 1 crédit/sonde TLS) détaillé dans les CGV.
- Ajout du workflow RGPD de suppression définitive de compte et des données associées avec double confirmation (case d'impact + lien sécurisé par email).

## [v0.8.4] — 2026-10-30 : Version initiale Open Source (Apache 2.0)
- Analyse statique AST Python pour détecter les clés RSA-2048, ECDSA P-256, SHA-1 et MD5.
- Inspection des configurations Nginx (`ssl_protocols`, `ssl_ecdh_curve X25519MLKEM768`).
- Génération native de l'inventaire cryptographique au standard OWASP CycloneDX 1.6 (`cbom.json`).
- Mode bloqueur CI/CD (`--ci` / Exit Code 1) pour GitHub Actions et GitLab CI.
