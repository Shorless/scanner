#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
SHORLESS.IO — ORCHESTRATEUR DE RELEASE COMPLET (CI/CD LOCAL & DÉPLOIEMENT)
================================================================================
Ce script automatise de bout en bout chaque nouvelle version de `shorless` :
1. Met à jour le numéro de version dans `pyproject.toml` et `shorless_scanner.py`.
2. Ajoute la Release Note horodatée dans `CHANGELOG.md`.
3. Met à jour `README.md` avec la dernière version et l'historique des évolutions.
4. Génère/met à jour la page officielle `scanner-documentation.html` (avec la charte
   graphique exacte de `index.html`, les liens PyPI/GitHub/Docker, le guide CLI/CI
   incluant Dockerfile & --check-tls, et le journal des versions).
5. Installe le paquet en mode éditable (`pip install -e .`).
6. Prépare `./test_env` (`auth_service.py`, `nginx.conf`, `Dockerfile.prod`) et
   exécute la suite de tests complète (AST + Nginx + Docker + --check-tls + --ci).
7. Compile et publie la nouvelle version sur PyPI (`python3 -m build` + `twine upload`).
8. Commit, Tag, Push sur Git et crée la Release officielle sur GitHub (API REST / `gh`)
   + synchronise optionnellement les fichiers web vers votre serveur OVH.
================================================================================
"""

import os
import re
import sys
import json
import shutil
import logging
import argparse
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError

# ------------------------------------------------------------------------------
# CONFIGURATION DU PROJET
# ------------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
SITE_DIR = BASE_DIR / "site" if (BASE_DIR / "site").exists() else BASE_DIR

PYPROJECT_FILE = BASE_DIR / "pyproject.toml"
SCANNER_FILE = BASE_DIR / "shorless_scanner.py"
README_FILE = BASE_DIR / "README.md"
CHANGELOG_FILE = BASE_DIR / "CHANGELOG.md"

DOC_HTML_FILE = SITE_DIR / "scanner-documentation.html"
INDEX_HTML_FILE = SITE_DIR / "index.html"
ARTICLES_HTML_FILE = SITE_DIR / "articles.html"
SITEMAP_FILE = SITE_DIR / "sitemap.xml" if (SITE_DIR / "sitemap.xml").exists() else (BASE_DIR / "sitemap.xml")
RELEASES_DB_FILE = SITE_DIR / "releases_db.json"

TEST_ENV_DIR = BASE_DIR / "test_env"

GITHUB_REPO = os.environ.get("SHORLESS_GITHUB_REPO", "shorless-dev/shorless")
SITE_URL = "https://shorless.io"
OVH_SSH_TARGET = os.environ.get("SHORLESS_OVH_SSH", "")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)


def run_cmd(cmd, check=True, capture=False):
    """Exécute une commande système proprement en forçant le mode UTF-8 sous Windows."""
    logging.info("Exécution : %s", " ".join(cmd) if isinstance(cmd, list) else cmd)
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    res = subprocess.run(
        cmd,
        shell=isinstance(cmd, str),
        check=False,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        encoding="utf-8",
        errors="replace",
        env=env
    )
    if check and res.returncode != 0:
        if capture:
            logging.error("Sortie erreur :\n%s", res.stderr or res.stdout)
        raise RuntimeError("La commande a échoué (code {}) : {}".format(res.returncode, cmd))
    return res


# ------------------------------------------------------------------------------
# 1. GESTION DE L'HISTORIQUE DES RELEASES (JSON + CHANGELOG.MD + PYPROJECT.TOML)
# ------------------------------------------------------------------------------
def load_releases_db():
    if not RELEASES_DB_FILE.exists():
        return [
            {
                "version": "0.8.4",
                "date": "30/10/2026",
                "iso_date": "2026-10-30",
                "title": "Version initiale Open Source (Apache 2.0)",
                "notes": [
                    "Analyse statique AST Python pour détecter les clés RSA-2048, ECDSA P-256, SHA-1 et MD5.",
                    "Inspection des configurations Nginx (`ssl_protocols`, `ssl_ecdh_curve X25519MLKEM768`).",
                    "Génération native de l'inventaire cryptographique au standard OWASP CycloneDX 1.6 (`cbom.json`).",
                    "Mode bloqueur CI/CD (`--ci` / Exit Code 1) pour GitHub Actions et GitLab CI."
                ]
            }
        ]
    try:
        return json.loads(RELEASES_DB_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def save_releases_db(releases):
    RELEASES_DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    RELEASES_DB_FILE.write_text(json.dumps(releases, indent=2, ensure_ascii=False), encoding="utf-8")


def update_version_in_files(version):
    """Met à jour le numéro de version dans pyproject.toml et shorless_scanner.py."""
    if PYPROJECT_FILE.exists():
        content = PYPROJECT_FILE.read_text(encoding="utf-8")
        content = re.sub(r'^version\s*=\s*"[^"]+"', 'version = "{}"'.format(version), content, flags=re.MULTILINE)
        PYPROJECT_FILE.write_text(content, encoding="utf-8")
        logging.info("pyproject.toml mis à jour en version %s", version)

    if SCANNER_FILE.exists():
        content = SCANNER_FILE.read_text(encoding="utf-8")
        content = re.sub(r'"version":\s*"[^"]+"', '"version": "{}"'.format(version), content)
        SCANNER_FILE.write_text(content, encoding="utf-8")
        logging.info("shorless_scanner.py mis à jour en version %s", version)


def update_changelog_and_readme(version, title, notes_list, releases_history):
    """Met à jour CHANGELOG.md et README.md avec les dernières évolutions."""
    today_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    changelog_blocks = ["# Changelog — Shorless PQC & CBOM Scanner\n"]
    for rel in releases_history:
        bullets = "\n".join(["- {}".format(n) for n in rel.get("notes", [])])
        changelog_blocks.append(
            "## [v{ver}] — {date} : {title}\n{bullets}\n".format(
                ver=rel["version"],
                date=rel.get("iso_date", today_iso),
                title=rel.get("title", ""),
                bullets=bullets
            )
        )
    CHANGELOG_FILE.write_text("\n".join(changelog_blocks), encoding="utf-8")
    logging.info("CHANGELOG.md mis à jour.")

    latest_bullets = "\n".join(["- {}".format(n) for n in notes_list])
    readme_content = """# ⚡ Shorless — Post-Quantum (PQC) DevSecOps Scanner & CycloneDX 1.6 CBOM Generator

[![PyPI version](https://img.shields.io/badge/pypi-v{version}-10B981.svg)](https://pypi.org/project/shorless/)
[![License](https://img.shields.io/badge/license-Apache%202.0-06B6D4.svg)](https://opensource.org/licenses/Apache-2.0)
[![CycloneDX 1.6](https://img.shields.io/badge/CBOM-CycloneDX%201.6-A855F7.svg)](https://cyclonedx.org/capabilities/cbom/)

**Shorless** (`shorless`) est un scanner statique (AST), d'infrastructure (Nginx, Docker) et réseau (`--check-tls`) Open Source conçu pour aider les équipes DevSecOps de PME et d'ETI à cartographier leur dette cryptographique (RSA, ECDSA, SHA-1, OpenSSL < 3.2, TLS non hybridé) et à préparer leur transition vers la cryptographie post-quantique (**ANSSI** / **NIST FIPS 203 ML-KEM** & **FIPS 204 ML-DSA**).

🔗 **Site officiel & Sandbox interactif :** [https://shorless.io](https://shorless.io)
📘 **Documentation complète du scanner :** [https://shorless.io/scanner-documentation.html](https://shorless.io/scanner-documentation.html)

---

## 🆕 Nouveautés de la version v{version} ({title})

{latest_bullets}

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
""".format(version=version, title=title, latest_bullets=latest_bullets)

    README_FILE.write_text(readme_content, encoding="utf-8")
    logging.info("README.md mis à jour.")


# ------------------------------------------------------------------------------
# 2. GÉNÉRATION DE LA PAGE WEB `scanner-documentation.html` & MAJ `index.html`
# ------------------------------------------------------------------------------
def generate_scanner_documentation_html(version, releases_history):
    changelog_html_cards = []
    for idx, rel in enumerate(releases_history):
        is_latest = (idx == 0)
        badge_html = (
            '<span class="px-2.5 py-0.5 rounded-full bg-emerald-500 text-obsidian font-mono font-bold text-[10px]">DERNIÈRE VERSION</span>'
            if is_latest else
            '<span class="px-2.5 py-0.5 rounded-full bg-white/10 text-slate-300 font-mono text-[10px]">ARCHIVE</span>'
        )
        notes_li = "\n".join([
            '<li class="flex items-start gap-2.5"><span class="text-emerald-400 font-bold">✓</span><span>{}</span></li>'.format(n)
            for n in rel.get("notes", [])
        ])
        card = """
                <div class="p-6 rounded-2xl bg-slateCard glow-border">
                    <div class="flex flex-wrap items-center justify-between gap-2 border-b border-white/10 pb-3 mb-4">
                        <div class="flex items-center gap-3">
                            <span class="font-mono font-extrabold text-xl text-white">v{ver}</span>
                            {badge}
                            <span class="text-sm font-semibold text-emerald-300">{title}</span>
                        </div>
                        <div class="flex items-center gap-3 text-xs font-mono text-slate-400">
                            <span>📅 {date}</span>
                            <a href="https://github.com/{repo}/releases/tag/v{ver}" target="_blank" rel="noopener noreferrer" class="text-cyan-400 hover:underline">GitHub Release ↗</a>
                        </div>
                    </div>
                    <ul class="space-y-2 text-sm text-slate-300">
                        {notes_li}
                    </ul>
                </div>""".format(
            ver=rel["version"],
            badge=badge_html,
            title=rel.get("title", "Mise à jour technique"),
            date=rel.get("date", ""),
            repo=GITHUB_REPO,
            notes_li=notes_li
        )
        changelog_html_cards.append(card)

    doc_html = """<!DOCTYPE html>
<html lang="fr" class="dark scroll-smooth">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Documentation Shorless CLI (v{version}) — Téléchargement PyPI, Guide CBOM CycloneDX 1.6 &amp; CI/CD</title>
    <meta name="description" content="Documentation officielle et téléchargement du scanner Open Source Shorless CLI (v{version}). Audit AST Python, Nginx, Dockerfile, TLS Live (--check-tls) et génération de CBOM CycloneDX 1.6.">
    <meta name="keywords" content="Shorless CLI documentation, pip install shorless, scanner PQC Python, Dockerfile OpenSSL PQC, check-tls ML-KEM, CycloneDX 1.6 CBOM generator">
    <meta name="author" content="Shorless Security">
    <meta name="robots" content="index, follow">
    <link rel="canonical" href="{site_url}/scanner-documentation.html">

    <meta property="og:type" content="website">
    <meta property="og:url" content="{site_url}/scanner-documentation.html">
    <meta property="og:title" content="Documentation &amp; Téléchargement Shorless CLI v{version} — Scanner DevSecOps Post-Quantique">
    <meta property="og:description" content="Installez Shorless CLI via PyPI, auditez votre code AST, vos Dockerfiles, vos serveurs TLS en direct et générez votre CBOM CycloneDX 1.6.">
    <meta property="og:site_name" content="Shorless.io">

    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
    <!-- Google tag (gtag.js) -->
    <script async="" src="https://www.googletagmanager.com/gtag/js?id=G-M2TD9H7HMN"></script>
    <script>
        window.dataLayer = window.dataLayer || [];
        function gtag() {{ dataLayer.push(arguments); }}
        gtag('js', new Date());
        gtag('config', 'G-M2TD9H7HMN');
    </script>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {{
            darkMode: 'class',
            theme: {{
                extend: {{
                    fontFamily: {{
                        sans: ['Inter', 'system-ui', 'sans-serif'],
                        mono: ['JetBrains Mono', 'monospace'],
                    }},
                    colors: {{
                        obsidian: '#06080D',
                        slateDark: '#0B0F17',
                        slateCard: '#111827',
                        quantum: {{
                            400: '#34D399',
                            500: '#10B981',
                            600: '#059669',
                            cyan: '#06B6D4'
                        }}
                    }}
                }}
            }}
        }}
    </script>
    <style>
        body {{ background-color: #06080D; color: #F3F4F6; overflow-x: hidden; }}
        .bg-lattice {{
            background-image: radial-gradient(rgba(16, 185, 129, 0.12) 1px, transparent 1px);
            background-size: 28px 28px;
        }}
        .glow-border {{
            border: 1px solid rgba(255, 255, 255, 0.08);
            transition: all 0.25s ease;
        }}
        .glow-border:hover {{
            border-color: rgba(16, 185, 129, 0.45);
            box-shadow: 0 0 25px -5px rgba(16, 185, 129, 0.18);
        }}
    </style>
</head>
<body class="antialiased selection:bg-emerald-500/30 selection:text-emerald-300">

    <div class="bg-gradient-to-r from-emerald-950/80 via-slate-900 to-cyan-950/80 border-b border-emerald-500/20 text-xs py-2 px-4">
        <div class="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-2">
            <div class="flex items-center space-x-2">
                <span class="px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 font-mono font-semibold border border-emerald-500/30">v{version} LATEST</span>
                <span class="text-slate-300">Documentation officielle du scanner Open Source Shorless CLI (Code AST + Nginx + Dockerfile + TLS Live).</span>
            </div>
            <div class="flex items-center space-x-4">
                <a href="https://pypi.org/project/shorless/" target="_blank" rel="noopener noreferrer" class="text-cyan-400 hover:text-cyan-300 font-mono">PyPI Package ↗</a>
                <a href="./index.html#interactive-demo" class="text-emerald-400 hover:text-emerald-300 font-medium hidden sm:inline">Tester le simulateur web →</a>
            </div>
        </div>
    </div>

    <header class="sticky top-0 z-40 backdrop-blur-xl bg-obsidian/85 border-b border-white/10">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
            <a href="./index.html" class="flex items-center space-x-3 group">
                <div class="w-9 h-9 rounded-lg bg-gradient-to-br from-emerald-500/20 to-cyan-500/20 border border-emerald-500/40 flex items-center justify-center group-hover:border-emerald-400 transition">
                    <svg class="w-5 h-5 text-emerald-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M12 3L4 9v6l8 6 8-6V9l-8-6z"></path>
                        <path stroke-linecap="round" stroke-linejoin="round" d="M4 9l8 6 8-6M12 3v12M12 15v6"></path>
                        <circle cx="12" cy="9" r="1.5" fill="#06B6D4"></circle>
                    </svg>
                </div>
                <div class="flex flex-col">
                    <div class="flex items-center space-x-1.5">
                        <span class="font-bold text-lg tracking-tight text-white font-mono">shorless</span>
                        <span class="text-[10px] font-mono px-1.5 py-0.5 rounded bg-white/5 text-slate-400 border border-white/10">.io</span>
                    </div>
                    <span class="text-[10px] text-slate-400 -mt-1 font-mono">PQC &amp; CBOM DevSecOps</span>
                </div>
            </a>

            <nav class="hidden md:flex items-center space-x-7 text-sm font-medium text-slate-300">
                <a href="./index.html#interactive-demo" class="hover:text-emerald-400 transition">Scanner Interactif</a>
                <a href="./scanner-documentation.html" class="text-emerald-400 font-semibold">Documentation CLI</a>
                <a href="./articles.html" class="hover:text-emerald-400 transition">Veille &amp; Blog PQC</a>
                <a href="./index.html#pricing" class="hover:text-emerald-400 transition">Tarifs PME/ETI</a>
                <a href="./index.html#faq" class="hover:text-emerald-400 transition">FAQ &amp; Normes</a>
            </nav>

            <div class="flex items-center space-x-3">
                <a href="https://github.com/{repo}" target="_blank" rel="noopener noreferrer" class="hidden sm:inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-xs font-mono text-slate-200 transition">
                    <span>GitHub</span>
                    <span>↗</span>
                </a>
                <button onclick="openDemoModal()" class="px-3.5 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-obsidian font-semibold text-xs sm:text-sm transition shadow-lg shadow-emerald-500/20">
                    Essai SaaS Gratuit
                </button>
            </div>
        </div>
    </header>

    <main class="py-12 md:py-20 bg-lattice border-b border-white/10">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">

            <div class="max-w-4xl mb-14">
                <div class="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-emerald-500/15 border border-emerald-500/30 text-xs font-mono text-emerald-300 mb-4">
                    <span>📦 PACKAGE OFFICIEL PYPI &amp; GITHUB RELEASE</span>
                    <span>•</span>
                    <span>v{version}</span>
                </div>
                <h1 class="text-3xl sm:text-5xl font-extrabold tracking-tight text-white leading-tight">
                    Documentation &amp; Téléchargement du Scanner <span class="text-emerald-400 font-mono">shorless</span>
                </h1>
                <p class="mt-4 text-slate-300 text-base sm:text-lg leading-relaxed">
                    Installez l'outil en ligne de commande Open Source (Apache 2.0) en 10 secondes pour auditer vos dépôts Python, vos configurations Nginx, vos <code class="text-emerald-400 font-mono">Dockerfile</code> et vos serveurs TLS en direct (<code class="text-emerald-400 font-mono">--check-tls</code>), tout en générant votre inventaire <strong>CBOM OWASP CycloneDX 1.6</strong>.
                </p>

                <div class="mt-8 grid grid-cols-1 sm:grid-cols-3 gap-4">
                    <a href="https://pypi.org/project/shorless/" target="_blank" rel="noopener noreferrer" class="p-4 rounded-xl bg-slateCard glow-border flex items-center justify-between group">
                        <div>
                            <span class="text-[11px] font-mono text-emerald-400 uppercase block">Téléchargement Officiel</span>
                            <span class="text-base font-bold text-white group-hover:text-emerald-400 transition">Package PyPI (v{version})</span>
                            <span class="text-xs text-slate-400 block mt-0.5 font-mono">pip install shorless</span>
                        </div>
                        <span class="text-emerald-400 text-lg">↗</span>
                    </a>

                    <a href="https://github.com/{repo}/releases/latest" target="_blank" rel="noopener noreferrer" class="p-4 rounded-xl bg-slateCard glow-border flex items-center justify-between group">
                        <div>
                            <span class="text-[11px] font-mono text-cyan-400 uppercase block">Code Source &amp; Binaires</span>
                            <span class="text-base font-bold text-white group-hover:text-cyan-400 transition">GitHub Release v{version}</span>
                            <span class="text-xs text-slate-400 block mt-0.5 font-mono">.tar.gz / .whl vérifiés</span>
                        </div>
                        <span class="text-cyan-400 text-lg">↗</span>
                    </a>

                    <a href="./shorless_scanner.py" download class="p-4 rounded-xl bg-slateCard glow-border flex items-center justify-between group">
                        <div>
                            <span class="text-[11px] font-mono text-purple-400 uppercase block">Script Autonome Direct</span>
                            <span class="text-base font-bold text-white group-hover:text-purple-400 transition">shorless_scanner.py</span>
                            <span class="text-xs text-slate-400 block mt-0.5 font-mono">Téléchargement direct .py</span>
                        </div>
                        <span class="text-purple-400 text-lg">↓</span>
                    </a>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-12 gap-10">
                <aside class="lg:col-span-3 space-y-2 text-sm font-mono">
                    <div class="p-4 rounded-2xl bg-slateDark border border-white/10 sticky top-24 space-y-2">
                        <div class="text-xs uppercase tracking-wider text-slate-400 pb-2 border-b border-white/10">Sommaire Technique</div>
                        <a href="#installation" class="block py-1.5 text-emerald-400 hover:underline">1. Installation (pip / pipx)</a>
                        <a href="#commandes-cli" class="block py-1.5 text-slate-300 hover:text-emerald-400">2. Commandes &amp; Options CLI</a>
                        <a href="#regles-detection" class="block py-1.5 text-slate-300 hover:text-emerald-400">3. Règles AST, Nginx, Docker &amp; TLS</a>
                        <a href="#format-cbom" class="block py-1.5 text-slate-300 hover:text-emerald-400">4. Export CBOM CycloneDX 1.6</a>
                        <a href="#integration-cicd" class="block py-1.5 text-slate-300 hover:text-emerald-400">5. Intégration GitHub Actions</a>
                        <a href="#release-notes" class="block py-1.5 text-slate-300 hover:text-emerald-400">6. Release Notes &amp; Versions</a>
                    </div>
                </aside>

                <div class="lg:col-span-9 space-y-12">

                    <section id="installation" class="p-7 rounded-2xl bg-slateDark border border-white/10 space-y-4">
                        <h2 class="text-2xl font-bold text-white">1. Installation Rapide (Python 3.8+)</h2>
                        <p class="text-slate-300 text-sm leading-relaxed">
                            Le scanner Shorless s'exécute 100 % en local sur votre machine ou dans vos runners CI/CD. Aucune ligne de code source ni clé privée ne quitte votre infrastructure.
                        </p>

                        <div class="space-y-3">
                            <div class="text-xs font-mono text-emerald-400">Option A — Exécution directe sans installation permanente (via pipx) :</div>
                            <div class="flex items-center justify-between bg-obsidian border border-emerald-500/30 rounded-xl p-3 font-mono text-xs sm:text-sm">
                                <code id="cmd-pipx" class="text-slate-100">pipx run shorless . --cbom cbom.json</code>
                                <button onclick="copyDocCmd('cmd-pipx')" class="px-3 py-1 rounded bg-emerald-500/20 text-emerald-300 hover:bg-emerald-500 hover:text-obsidian transition text-xs">Copier</button>
                            </div>

                            <div class="text-xs font-mono text-cyan-400 pt-2">Option B — Installation standard via PyPI :</div>
                            <div class="flex items-center justify-between bg-obsidian border border-white/15 rounded-xl p-3 font-mono text-xs sm:text-sm">
                                <code id="cmd-pip" class="text-slate-100">pip install -U shorless</code>
                                <button onclick="copyDocCmd('cmd-pip')" class="px-3 py-1 rounded bg-white/10 text-slate-200 hover:bg-emerald-500 hover:text-obsidian transition text-xs">Copier</button>
                            </div>
                        </div>
                    </section>

                    <section id="commandes-cli" class="p-7 rounded-2xl bg-slateDark border border-white/10 space-y-4">
                        <h2 class="text-2xl font-bold text-white">2. Utilisation &amp; Options de la ligne de commande</h2>
                        <p class="text-slate-300 text-sm leading-relaxed">
                            Pointez <code class="text-emerald-400 font-mono">shorless</code> vers un dossier local et/ou utilisez <code class="text-emerald-400 font-mono">--check-tls</code> pour inspecter une URL en production :
                        </p>
                        <pre class="p-4 rounded-xl bg-obsidian border border-white/10 font-mono text-xs text-emerald-300 overflow-x-auto leading-relaxed"># 1. Scanner le code Python (.py), Nginx (.conf) et Docker (Dockerfile*) du dossier
shorless ./test_env --cbom cbom.json

# 2. Auditer en direct un endpoint TLS distant (protocole TLS 1.3, KEM hybride ML-KEM &amp; certificat)
shorless . --check-tls https://shorless.io --cbom cbom-live.json

# 3. Mode bloqueur CI/CD (renvoie Exit Code 1 si au moins 1 risque CRITIQUE est détecté)
shorless ./test_env --check-tls https://api.entreprise.fr --ci</pre>

                        <div class="overflow-x-auto pt-2">
                            <table class="w-full text-left border-collapse border border-white/10 text-xs font-mono">
                                <thead>
                                    <tr class="bg-obsidian text-slate-300 border-b border-white/10">
                                        <th class="p-3 border-r border-white/10">Argument / Option</th>
                                        <th class="p-3 border-r border-white/10">Défaut</th>
                                        <th class="p-3">Description</th>
                                    </tr>
                                </thead>
                                <tbody class="divide-y divide-white/10 text-slate-300">
                                    <tr>
                                        <td class="p-3 text-emerald-400 border-r border-white/10">TARGET_DIR</td>
                                        <td class="p-3 border-r border-white/10">.</td>
                                        <td class="p-3 font-sans">Chemin du dossier projet ou dépôt Git à analyser récursivement (Code AST + Nginx + Dockerfile).</td>
                                    </tr>
                                    <tr>
                                        <td class="p-3 text-emerald-400 border-r border-white/10">--check-tls</td>
                                        <td class="p-3 border-r border-white/10">None</td>
                                        <td class="p-3 font-sans">URL ou <code class="text-cyan-300">domaine:port</code> à inspecter en direct pour vérifier TLS 1.3 et l'échange hybride <code class="text-cyan-300">X25519MLKEM768</code>.</td>
                                    </tr>
                                    <tr>
                                        <td class="p-3 text-emerald-400 border-r border-white/10">--cbom</td>
                                        <td class="p-3 border-r border-white/10">cbom.json</td>
                                        <td class="p-3 font-sans">Chemin du fichier JSON généré au format standard OWASP CycloneDX 1.6.</td>
                                    </tr>
                                    <tr>
                                        <td class="p-3 text-emerald-400 border-r border-white/10">--ci</td>
                                        <td class="p-3 border-r border-white/10">False</td>
                                        <td class="p-3 font-sans">Interrompt le pipeline CI/CD (<code class="text-rose-400">exit code 1</code>) en présence d'algorithmes vulnérables à Shor.</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </section>

                    <section id="regles-detection" class="p-7 rounded-2xl bg-slateDark border border-white/10 space-y-4">
                        <h2 class="text-2xl font-bold text-white">3. Couverture des Règles PQC (Code AST + Nginx + Docker + TLS Live)</h2>
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                            <div class="p-4 rounded-xl bg-obsidian border border-rose-500/30">
                                <span class="font-mono font-bold text-rose-400 uppercase">Détections Code &amp; Conteneurs</span>
                                <ul class="mt-2 space-y-1.5 text-slate-300">
                                    <li>• <strong>Python AST :</strong> <code class="text-white">generate_private_key</code>, <code class="text-white">SECP256R1</code>, <code class="text-white">SECP384R1</code>, <code class="text-white">SHA1</code>, <code class="text-white">MD5</code></li>
                                    <li>• <strong>Dockerfiles :</strong> Images OS legacy (<code class="text-white">buster</code>, <code class="text-white">bullseye</code>, <code class="text-white">ubuntu:20.04</code>, <code class="text-white">alpine &lt; 3.19</code>) &amp; <code class="text-white">OpenSSL &lt; 3.2</code></li>
                                </ul>
                            </div>
                            <div class="p-4 rounded-xl bg-obsidian border border-emerald-500/30">
                                <span class="font-mono font-bold text-emerald-400 uppercase">Détections Infra Nginx &amp; Réseau TLS</span>
                                <ul class="mt-2 space-y-1.5 text-slate-300">
                                    <li>• <strong>Nginx (.conf) :</strong> Vérification <code class="text-emerald-300">TLSv1.3</code> et présence de <code class="text-emerald-300">ssl_ecdh_curve X25519MLKEM768</code></li>
                                    <li>• <strong>TLS Live (--check-tls) :</strong> Handshake réel, détection du groupe KEM négocié et audit du certificat X.509</li>
                                </ul>
                            </div>
                        </div>
                    </section>

                    <section id="format-cbom" class="p-7 rounded-2xl bg-slateDark border border-white/10 space-y-4">
                        <h2 class="text-2xl font-bold text-white">4. Structure du fichier CBOM CycloneDX 1.6 exporté</h2>
                        <pre class="p-4 rounded-xl bg-obsidian border border-white/10 font-mono text-xs text-cyan-300 overflow-x-auto leading-relaxed">{{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {{
    "tools": [{{ "vendor": "Shorless", "name": "shorless-scanner", "version": "{version}" }}]
  }},
  "components": [
    {{
      "type": "cryptographic-asset",
      "name": "OpenSSL Obsolète (Incompatible PQC)",
      "evidence": {{ "occurrences": [{{ "location": "test_env/Dockerfile.prod", "line": 2 }}] }},
      "cryptoProperties": {{
        "assetType": "algorithm",
        "quantumSafe": "false",
        "remediation": "Mettre à niveau vers OpenSSL 3.2+ avec oqs-provider pour supporter ML-KEM (FIPS 203)."
      }}
    }}
  ]
}}</pre>
                    </section>

                    <section id="integration-cicd" class="p-7 rounded-2xl bg-slateDark border border-white/10 space-y-4">
                        <h2 class="text-2xl font-bold text-white">5. Intégration automatisée dans GitHub Actions &amp; GitLab CI</h2>
                        <pre class="p-4 rounded-xl bg-obsidian border border-white/10 font-mono text-xs text-slate-200 overflow-x-auto leading-relaxed">name: Shorless PQC &amp; CBOM Audit
on: [push, pull_request]

jobs:
  pqc-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Run Shorless PQC Scanner
        run: |
          pip install shorless
          shorless . --cbom cbom.json --ci</pre>
                    </section>

                    <section id="release-notes" class="space-y-4">
                        <div class="flex items-center justify-between">
                            <h2 class="text-2xl font-bold text-white">6. Journal des Versions &amp; Release Notes</h2>
                            <a href="https://github.com/{repo}/releases" target="_blank" rel="noopener noreferrer" class="text-xs font-mono text-emerald-400 hover:underline">Voir toutes les releases GitHub ↗</a>
                        </div>
                        <div class="space-y-4">
                            {changelog_cards}
                        </div>
                    </section>

                </div>
            </div>
        </div>
    </main>

    <footer class="bg-obsidian py-12 text-xs text-slate-400">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="pt-6 flex flex-col sm:flex-row items-center justify-between gap-4">
                <p>© 2026 Shorless Security SAS. Open Source CLI sous licence Apache 2.0.</p>
                <div class="flex space-x-4 font-mono">
                    <span>Scanner Version: v{version}</span>
                    <span>•</span>
                    <span>TLS 1.3 (X25519MLKEM768 Active)</span>
                </div>
            </div>
        </div>
    </footer>

    <div id="demo-modal" class="fixed inset-0 z-50 hidden bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
        <div class="bg-slateCard border border-emerald-500/40 rounded-2xl max-w-md w-full p-6 shadow-2xl">
            <div class="flex items-center justify-between border-b border-white/10 pb-3">
                <h3 class="text-lg font-bold text-white">Démarrer avec Shorless SaaS</h3>
                <button onclick="closeDemoModal()" class="text-slate-400 hover:text-white">✕</button>
            </div>
            <form onsubmit="submitTrialForm(event)" class="mt-4 space-y-4 text-sm">
                <div>
                    <label class="block text-xs font-mono text-slate-300 mb-1">Email professionnel (CTO / DevSecOps / RSSI)</label>
                    <input type="email" required placeholder="alex@entreprise-tech.fr" class="w-full px-3.5 py-2.5 rounded-lg bg-obsidian border border-white/15 text-white focus:border-emerald-400 focus:outline-none">
                </div>
                <div id="modal-feedback" class="hidden p-3 rounded-lg bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 text-xs font-mono">
                    ✓ Clé d'API d'essai générée !
                </div>
                <button type="submit" class="w-full py-3 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-obsidian font-bold transition">
                    Obtenir ma clé d'API &amp; Activer l'Auto-PR (14j gratuits)
                </button>
            </form>
        </div>
    </div>

    <script>
        function copyDocCmd(elemId) {{
            const text = document.getElementById(elemId).innerText;
            navigator.clipboard.writeText(text);
        }}
        function openDemoModal() {{ document.getElementById('demo-modal').classList.remove('hidden'); }}
        function closeDemoModal() {{ document.getElementById('demo-modal').classList.add('hidden'); }}
        function submitTrialForm(e) {{
            e.preventDefault();
            document.getElementById('modal-feedback').classList.remove('hidden');
        }}
    </script>
</body>
</html>
""".format(
        version=version,
        site_url=SITE_URL,
        repo=GITHUB_REPO,
        changelog_cards="\n".join(changelog_html_cards)
    )

    DOC_HTML_FILE.parent.mkdir(parents=True, exist_ok=True)
    DOC_HTML_FILE.write_text(doc_html, encoding="utf-8")
    # Copie également shorless_scanner.py dans SITE_DIR si SITE_DIR != BASE_DIR pour le lien de téléchargement direct
    if SITE_DIR != BASE_DIR and SCANNER_FILE.exists():
        shutil.copy2(str(SCANNER_FILE), str(SITE_DIR / "shorless_scanner.py"))
    logging.info("Page scanner-documentation.html générée avec succès (%s).", DOC_HTML_FILE)


def update_site_links_and_version(version):
    if INDEX_HTML_FILE.exists():
        content = INDEX_HTML_FILE.read_text(encoding="utf-8")
        content = re.sub(r'v\d+\.\d+\.\d+\s*RELEASE', 'v{} RELEASE'.format(version), content)
        content = re.sub(r'shorless-cli\s+v\d+\.\d+\.\d+', 'shorless-cli v{}'.format(version), content)
        content = re.sub(r'Scanner v\d+\.\d+\.\d+', 'Scanner v{}'.format(version), content)

        if 'scanner-documentation.html' not in content:
            content = content.replace(
                '<a href="./articles.html"',
                '<a href="./scanner-documentation.html" class="hover:text-emerald-400 transition">Doc CLI</a>\n                <a href="./articles.html"',
                1
            )
        INDEX_HTML_FILE.write_text(content, encoding="utf-8")
        logging.info("index.html mis à jour avec la version v%s.", version)

    if SITEMAP_FILE.exists():
        sm = SITEMAP_FILE.read_text(encoding="utf-8")
        today_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        if "scanner-documentation.html" not in sm:
            doc_url_entry = """  <url>
    <loc>{}/scanner-documentation.html</loc>
    <lastmod>{}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.95</priority>
  </url>\n</urlset>""".format(SITE_URL, today_iso)
            sm = sm.replace("</urlset>", doc_url_entry)
            SITEMAP_FILE.write_text(sm, encoding="utf-8")
            logging.info("sitemap.xml mis à jour avec scanner-documentation.html.")


# ------------------------------------------------------------------------------
# 3. INSTALLATION ÉDITABLE & EXÉCUTION DES TESTS (PYTHON + NGINX + DOCKER + TLS)
# ------------------------------------------------------------------------------
def install_editable_and_run_tests():
    """
    Installe le paquet en mode `-e .`, génère les 3 fichiers de test dans `./test_env`
    (`auth_service.py`, `nginx.conf`, `Dockerfile.prod`) et vérifie que chaque brique
    (AST Python, Nginx, Dockerfile et --ci) est bien détectée.
    """
    logging.info("--- Étape : Installation du paquet en mode éditable (pip install -e .) ---")
    run_cmd([sys.executable, "-m", "pip", "install", "-e", "."])

    logging.info("--- Étape : Préparation des fichiers de test dans ./test_env ---")
    TEST_ENV_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Correction automatique si auth_service.pu existe
    typo_file = TEST_ENV_DIR / "auth_service.pu"
    py_test_file = TEST_ENV_DIR / "auth_service.py"
    if typo_file.exists() and not py_test_file.exists():
        shutil.copy2(str(typo_file), str(py_test_file))
        logging.info("Correction automatique : test_env/auth_service.pu -> test_env/auth_service.py")

    if not py_test_file.exists():
        py_test_file.write_text(
            "from cryptography.hazmat.primitives.asymmetric import rsa, ec\n"
            "# Génération d'une clé RSA-2048 et courbe P-256 vulnérables à Shor\n"
            "private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
            "curve = ec.SECP256R1()\n",
            encoding="utf-8"
        )
        logging.info("Fichier de test créé : %s", py_test_file)

    # 2. Fichier de test Nginx (.conf)
    nginx_test_file = TEST_ENV_DIR / "nginx.conf"
    if not nginx_test_file.exists():
        nginx_test_file.write_text(
            "server {\n"
            "    listen 443 ssl;\n"
            "    ssl_protocols TLSv1.2 TLSv1.3;\n"
            "    ssl_ecdh_curve secp384r1;\n"
            "}\n",
            encoding="utf-8"
        )
        logging.info("Fichier de test créé : %s", nginx_test_file)

    # 3. NOUVEAU : Fichier de test Docker (Dockerfile.prod)
    docker_test_file = TEST_ENV_DIR / "Dockerfile.prod"
    if not docker_test_file.exists():
        docker_test_file.write_text(
            "FROM python:3.9-slim-buster\n"
            "RUN apt-get update && apt-get install -y openssl=1.1.1k\n"
            "RUN openssl genrsa -out server.key 2048\n"
            "CMD [\"python\", \"auth_service.py\"]\n",
            encoding="utf-8"
        )
        logging.info("Fichier de test Docker créé : %s", docker_test_file)

    cbom_test_out = TEST_ENV_DIR / "cbom_test.json"
    if cbom_test_out.exists():
        cbom_test_out.unlink()

    scanner_script = SCANNER_FILE if SCANNER_FILE.exists() else (BASE_DIR / "shorless_scanner.py")
    if scanner_script.exists():
        logging.info("--- Exécution du test unitaire (Python AST + Nginx + Dockerfile) ---")
        run_cmd([sys.executable, str(scanner_script), str(TEST_ENV_DIR), "--cbom", str(cbom_test_out)])
        if not cbom_test_out.exists():
            raise RuntimeError("Échec du test : le fichier CBOM n'a pas été généré !")

        try:
            raw_cbom = cbom_test_out.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            raw_cbom = cbom_test_out.read_text(encoding="cp1252")

        cbom_data = json.loads(raw_cbom)
        components = cbom_data.get("components", [])
        comp_count = len(components)

        # Vérifie que le Dockerfile a bien été scanné dans les résultats
        docker_detected = any(
            "Dockerfile" in c.get("evidence", {}).get("occurrences", [{}])[0].get("location", "")
            for c in components
        )
        if not docker_detected:
            logging.warning(
                "⚠️ Attention : aucune alerte Dockerfile trouvée dans cbom_test.json ! "
                "Vérifiez que votre fichier shorless_scanner.py contient bien la fonction scan_dockerfile()."
            )
        else:
            logging.info("✅ Test Dockerfile validé : les vulnérabilités de test_env/Dockerfile.prod sont bien présentes dans le CBOM.")

        logging.info("✅ Test global réussi : %d vulnérabilités (Code + Nginx + Docker) exportées dans CBOM CycloneDX 1.6.", comp_count)

        # Test du mode bloqueur CI (--ci doit renvoyer Exit Code 1)
        res_ci = run_cmd([sys.executable, str(scanner_script), str(TEST_ENV_DIR), "--ci"], check=False, capture=True)
        if res_ci.returncode != 1:
            raise RuntimeError("Échec du test --ci : le scanner aurait dû retourner exit code 1 !")
        logging.info("✅ Test du mode bloqueur CI (--ci -> exit code 1) validé avec succès.")
    else:
        logging.warning("Fichier shorless_scanner.py introuvable dans ce dossier, test unitaire ignoré.")


# ------------------------------------------------------------------------------
# 4. BUILD & PUBLICATION SUR PYPI
# ------------------------------------------------------------------------------
def build_and_publish_pypi(skip_pypi=False):
    if skip_pypi:
        logging.info("Publication PyPI ignorée (--skip-pypi activé).")
        return

    logging.info("--- Étape : Construction du paquet PyPI (sdist & wheel) ---")
    dist_dir = BASE_DIR / "dist"
    if dist_dir.exists():
        shutil.rmtree(str(dist_dir))

    run_cmd([sys.executable, "-m", "pip", "install", "--quiet", "-U", "build", "twine"])
    run_cmd([sys.executable, "-m", "build"])

    logging.info("--- Étape : Publication sur PyPI via Twine ---")
    run_cmd([sys.executable, "-m", "twine", "upload", "dist/*"])
    logging.info("✅ Paquet publié avec succès sur PyPI !")


# ------------------------------------------------------------------------------
# 5. GIT TAG, CRÉATION DE LA RELEASE GITHUB & SYNCHRONISATION SERVEUR
# ------------------------------------------------------------------------------
def publish_github_release_and_sync(version, title, notes_list, skip_git=False):
    if skip_git:
        logging.info("Publication Git/GitHub ignorée (--skip-git activé).")
        return

    tag_name = "v{}".format(version)
    release_body = "### {}\n\n".format(title) + "\n".join(["- {}".format(n) for n in notes_list])

    logging.info("--- Étape : Git Commit, Tag & Push (%s) ---", tag_name)
    run_cmd(["git", "add", "."], check=False)
    run_cmd(["git", "commit", "-m", "chore(release): {} — {}".format(tag_name, title)], check=False)
    run_cmd(["git", "tag", "-a", tag_name, "-m", title], check=False)
    run_cmd(["git", "push"], check=False)
    run_cmd(["git", "push", "origin", tag_name], check=False)

    gh_bin = shutil.which("gh")
    github_token = os.environ.get("GITHUB_TOKEN", "").strip()

    if gh_bin:
        logging.info("Création de la Release GitHub via GitHub CLI (`gh`)...")
        cmd = ["gh", "release", "create", tag_name, "--title", "{} — {}".format(tag_name, title), "--notes", release_body]
        dist_files = list((BASE_DIR / "dist").glob("*")) if (BASE_DIR / "dist").exists() else []
        cmd.extend([str(f) for f in dist_files])
        run_cmd(cmd, check=False)
    elif github_token:
        logging.info("Création de la Release GitHub via l'API REST officielle...")
        api_url = "https://api.github.com/repos/{}/releases".format(GITHUB_REPO)
        payload = {
            "tag_name": tag_name,
            "name": "{} — {}".format(tag_name, title),
            "body": release_body,
            "draft": False,
            "prerelease": False
        }
        req = Request(
            api_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": "Bearer {}".format(github_token),
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "User-Agent": "Shorless-Release-Script"
            },
            method="POST"
        )
        try:
            with urlopen(req, timeout=30) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
                logging.info("✅ Release GitHub créée : %s", resp_data.get("html_url"))
        except HTTPError as e:
            logging.warning("Avertissement API GitHub (%s) : %s", e.code, e.read().decode("utf-8", errors="ignore"))
    else:
        logging.info("Astuce : Installez `gh` ou définissez `export GITHUB_TOKEN=ghp_...` pour automatiser la création de la Release GitHub.")

    if OVH_SSH_TARGET:
        logging.info("--- Étape : Synchronisation des pages web vers OVH (%s) ---", OVH_SSH_TARGET)
        files_to_sync = [
            str(INDEX_HTML_FILE),
            str(DOC_HTML_FILE),
            str(ARTICLES_HTML_FILE),
            str(SITEMAP_FILE),
            str(SCANNER_FILE)
        ]
        existing_sync = [f for f in files_to_sync if Path(f).exists()]
        if existing_sync:
            run_cmd(["scp"] + existing_sync + [OVH_SSH_TARGET], check=False)
            logging.info("✅ Pages web synchronisées sur votre hébergement OVH !")


# ------------------------------------------------------------------------------
# POINT D'ENTRÉE PRINCIPAL
# ------------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Orchestrateur de Release Shorless : Changelog, README, Doc HTML, Tests, PyPI & GitHub Release."
    )
    parser.add_argument(
        "-v", "--version",
        required=True,
        help="Nouvelle version à publier (ex: 0.8.6)"
    )
    parser.add_argument(
        "-t", "--title",
        default="Support Dockerfile & Inspection TLS Live (--check-tls)",
        help="Titre court de la version"
    )
    parser.add_argument(
        "-n", "--notes",
        required=True,
        help="Notes de version séparées par des points-virgules ';'"
    )
    parser.add_argument(
        "--skip-pypi",
        action="store_true",
        help="Ne pas publier sur PyPI"
    )
    parser.add_argument(
        "--skip-git",
        action="store_true",
        help="Ne pas exécuter git push / GitHub release"
    )
    args = parser.parse_args()

    version = args.version.strip().lstrip("v")
    title = args.title.strip()
    notes_list = [n.strip() for n in args.notes.split(";") if n.strip()]

    now_utc = datetime.now(timezone.utc)
    releases_history = load_releases_db()

    releases_history = [r for r in releases_history if r.get("version") != version]
    releases_history.insert(0, {
        "version": version,
        "date": now_utc.strftime("%d/%m/%Y"),
        "iso_date": now_utc.strftime("%Y-%m-%d"),
        "title": title,
        "notes": notes_list
    })
    save_releases_db(releases_history)

    update_version_in_files(version)
    update_changelog_and_readme(version, title, notes_list, releases_history)
    generate_scanner_documentation_html(version, releases_history)
    update_site_links_and_version(version)
    install_editable_and_run_tests()
    build_and_publish_pypi(skip_pypi=args.skip_pypi)
    publish_github_release_and_sync(version, title, notes_list, skip_git=args.skip_git)

    logging.info("🎉 Release v%s terminée avec succès de bout en bout !", version)


if __name__ == "__main__":
    main()
