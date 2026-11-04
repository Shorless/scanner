#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
SHORLESS PQC & CBOM SCANNER v1.0.1 (shorless_scanner.py)
================================================================================
Scanner DevSecOps Open Source (Apache 2.0) de préparation Post-Quantique :
1. Analyse statique AST Python & Multi-Langages (Java, Go, Node.js, TS, C#).
2. Inspection Multi-IaC (Nginx, Dockerfile, Traefik, Kubernetes Ingress, Terraform).
3. Analyse des dépendances SCA Post-Quantique (requirements.txt, package.json, go.mod, pom.xml, Cargo.toml).
4. Inspection des certificats X.509 & clés statiques (.pem, .crt, .cer, .key).
5. Gestion des exceptions via .shorlessignore et commentaires inline (shorless: ignore).
6. Inspection en direct des terminaisons TLS distantes (--check-tls https://...).
7. Export natif CBOM OWASP CycloneDX 1.6 (--cbom), SARIF 2.1.0 (--sarif) et HTML/PDF (--report-html).
8. Synchronisation SaaS Multi-Projets (--project), Webhooks Slack/Teams (--webhook-url) & Auto-PR (--auto-pr).
================================================================================
"""

import os
from urllib.request import Request, urlopen
import ast
import fnmatch
import json
import re
import shutil
import socket
import ssl
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

app = typer.Typer(help="Scanner DevSecOps de préparation Post-Quantique (PQC), SCA, SARIF & Générateur CBOM CycloneDX 1.6")
console = Console()

SCANNER_VERSION = "1.0.2"

# Base de connaissances PQC (Règles NIST FIPS 203/204 & ANSSI)
PQC_RULES = {
    "generate_private_key": {
        "algo": "RSA / ECC (Asymétrique)",
        "risk": "CRITIQUE",
        "reason": "Vulnérable à l'algorithme de Shor (Harvest Now, Decrypt Later).",
        "remediation": "Migrer vers une approche hybride (ex: X25519 + ML-KEM-768) ou signatures ML-DSA."
    },
    "SECP256R1": {
        "algo": "ECDSA / ECDH (P-256)",
        "risk": "CRITIQUE",
        "reason": "Courbe elliptique classique cassable par un ordinateur quantique cryptographiquement pertinent.",
        "remediation": "Utiliser liboqs / OpenSSL 3.2+ avec un provider OQS pour hybrider la courbe."
    },
    "SECP384R1": {
        "algo": "ECDSA / ECDH (P-384)",
        "risk": "CRITIQUE",
        "reason": "Courbe elliptique classique vulnérable à l'algorithme de Shor.",
        "remediation": "Hybrider l'échange de clés avec ML-KEM-768 ou ML-KEM-1024 (NIST FIPS 203)."
    },
    "SHA1": {
        "algo": "SHA-1 (Hachage)",
        "risk": "ÉLEVÉ",
        "reason": "Obsolète (collisions classiques + affaiblissement par l'algorithme de Grover).",
        "remediation": "Remplacer par SHA-256, SHA-384 ou SHA-3."
    },
    "MD5": {
        "algo": "MD5 (Hachage)",
        "risk": "ÉLEVÉ",
        "reason": "Totalement compromis.",
        "remediation": "Remplacer par SHA-256 ou SHA-3."
    }
}

FILE_TYPE_MAP = {
    ".py": "Python (AST)",
    ".java": "Java (JCA)",
    ".go": "Go (Stdlib)",
    ".js": "Node.js (Crypto)",
    ".ts": "TypeScript (Crypto)",
    ".cs": "C# (.NET Crypto)",
    ".csproj": "SCA C# (.NET NuGet)",
    ".props": "SCA C# (Directory.Packages)",
    ".gradle": "SCA Java (Gradle)",
    ".kts": "SCA Java (Gradle Kotlin)",
    ".conf": "Nginx Config",
    ".tf": "Terraform IaC & Modules",
    ".hcl": "Terraform Lockfile (.hcl)",
    ".yml": "YAML (Traefik / K8s / Helm)",
    ".yaml": "YAML (Traefik / K8s / Envoy / Istio)",
    ".json": "JSON (JWKS / OIDC / Config)",
    ".pub": "Clé Publique SSH (PUB)",
    ".pem": "Certificat / Clé (PEM)",
    ".crt": "Certificat X.509 (CRT)",
    ".cer": "Certificat X.509 (CER)",
    ".key": "Clé Privée Statique (KEY)",
}

SCA_MANIFEST_NAMES = {
    "requirements.txt": "SCA Python (pip)",
    "pipfile": "SCA Python (Pipfile)",
    "poetry.lock": "SCA Python (Poetry Lock)",
    "package.json": "SCA Node.js (npm)",
    "package-lock.json": "SCA Node.js (npm Lock)",
    "yarn.lock": "SCA Node.js (Yarn Lock)",
    "go.mod": "SCA Go (go.mod)",
    "go.sum": "SCA Go (go.sum)",
    "pom.xml": "SCA Java (Maven)",
    "build.gradle": "SCA Java (Gradle)",
    "build.gradle.kts": "SCA Java (Gradle KTS)",
    "packages.config": "SCA C# (NuGet Config)",
    "directory.packages.props": "SCA C# (Central NuGet)",
    "cargo.toml": "SCA Rust (Cargo)",
    "cargo.lock": "SCA Rust (Cargo Lock)",
    "chart.yaml": "IaC Helm Chart (Dépendances K8s)",
    ".terraform.lock.hcl": "IaC Terraform Provider Lock",
    "sshd_config": "Config Serveur OpenSSH (sshd_config)",
    "ssh_config": "Config Client OpenSSH (ssh_config)",
    "caddyfile": "Serveur Web Caddy (Caddyfile)",
    "haproxy.cfg": "Load Balancer HAProxy (haproxy.cfg)",
}

CRYPTO_HEURISTIC_KEYWORDS = (
    "rsa", "ecdsa", "secp", "prime256", "ed25519", "x25519", "mlkem", "kyber",
    "dilithium", "openssl", "ssl_", "tls", "cipher", "crypto", "private_key",
    "keypair", "sha1", "md5", "cert", "x509", "jwt", "keystore", "pem", "begin "
)


def parse_version_tuple(ver_str: str) -> tuple:
    """Extrait un tuple d'entiers (major, minor, patch) depuis une chaîne de version."""
    nums = re.findall(r"\d+", ver_str or "")
    if not nums:
        return (0, 0, 0)
    vals = [int(x) for x in nums[:3]]
    while len(vals) < 3:
        vals.append(0)
    return tuple(vals)


def load_shorlessignore(target_path: Path) -> list:
    """Charge les motifs d'exclusion définis dans .shorlessignore."""
    ignore_file = target_path / ".shorlessignore"
    patterns = []
    if ignore_file.exists():
        for line in ignore_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            clean = line.strip()
            if clean and not clean.startswith("#"):
                patterns.append(clean)
    return patterns


def is_ignored_path(filepath: Path, root_path: Path, ignore_patterns: list) -> bool:
    """Vérifie si un fichier correspond à un motif de .shorlessignore."""
    if not ignore_patterns:
        return False
    try:
        rel = str(filepath.relative_to(root_path)).replace("\\", "/")
    except ValueError:
        rel = filepath.name
    for pat in ignore_patterns:
        if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(filepath.name, pat):
            return True
    return False


def has_inline_ignore(line_text: str) -> bool:
    """Vérifie si une ligne possède une directive d'exclusion inline (shorless: ignore / shorless-ignore)."""
    low = (line_text or "").lower()
    return ("shorless: ignore" in low) or ("shorless-ignore" in low) or ("shorless:ignore" in low)


def detect_project_name(target_path: Path, explicit_project: str = None) -> str:
    """Détecte automatiquement le nom du projet/dépôt (GitHub, GitLab CI, Bitbucket Pipelines ou Git local)."""
    if explicit_project and explicit_project.strip():
        return explicit_project.strip()
    for env_var in ("GITHUB_REPOSITORY", "CI_PROJECT_PATH", "BITBUCKET_REPO_FULL_NAME"):
        val = os.environ.get(env_var, "").strip()
        if val:
            return val
    try:
        proc = subprocess.run(
            ["git", "-C", str(target_path), "config", "--get", "remote.origin.url"],
            capture_output=True, text=True, timeout=3
        )
        m = re.search(r"[:/]([^/]+/[^/.]+)(?:\.git)?$", (proc.stdout or "").strip())
        if m:
            return m.group(1)
    except Exception:
        pass
    resolved = target_path.resolve().name
    return resolved if resolved and resolved != "." else "local-project"


def detect_file_type_and_crypto_prob(filepath: Path) -> tuple[str, int, str]:
    """
    Détermine le type du fichier et estime la probabilité (0-95 %) qu'il contienne
    des références au chiffrement ou à la cryptographie (heuristique nom + contenu).
    """
    name_lower = filepath.name.lower()
    suffix_lower = filepath.suffix.lower()

    if filepath.name in ("shorless_scanner.py", "pqc_scanner.py", "release_shorless.py", "cron_generate_article.py") or filepath.name.endswith("_test.html") or filepath.name.endswith("_test.json") or filepath.name.endswith("_test.sarif"):
        return ("Ignoré / Non supporté", 0, "Faible")

    # 1. Identification du type de fichier
    if name_lower in SCA_MANIFEST_NAMES:
        file_type = SCA_MANIFEST_NAMES[name_lower]
        base_prob = 75
    elif name_lower.startswith("dockerfile"):
        file_type = "Dockerfile (Container)"
        base_prob = 50
    elif suffix_lower in (".pem", ".crt", ".cer", ".key"):
        file_type = FILE_TYPE_MAP[suffix_lower]
        base_prob = 95
    elif suffix_lower in (".yml", ".yaml"):
        file_type = "YAML (Traefik / K8s)"
        base_prob = 45
    elif suffix_lower in FILE_TYPE_MAP:
        file_type = FILE_TYPE_MAP[suffix_lower]
        base_prob = 35 if suffix_lower not in (".conf", ".tf") else 60
    else:
        return ("Ignoré / Non supporté", 0, "Faible")

    # 2. Bonus heuristique sur le nom du fichier
    if any(k in name_lower for k in ("auth", "crypto", "tls", "ssl", "jwt", "cert", "sec", "key", "ingress", "nginx", "traefik")):
        base_prob += 25

    # 3. Analyse rapide de densité lexicale crypto dans le contenu
    try:
        content_lower = filepath.read_text(encoding="utf-8", errors="ignore").lower()
        if suffix_lower in (".yml", ".yaml"):
            if "ingress" in content_lower or "cert-manager" in content_lower:
                file_type = "Kubernetes Ingress (YAML)"
            elif "traefik" in content_lower or "minversion" in content_lower or "curvepreferences" in content_lower:
                file_type = "Traefik TLS (YAML)"

        matched_keywords = sum(1 for kw in CRYPTO_HEURISTIC_KEYWORDS if kw in content_lower)
        if matched_keywords >= 4:
            base_prob += 35
        elif matched_keywords >= 2:
            base_prob += 20
        elif matched_keywords == 1:
            base_prob += 10
        else:
            base_prob = max(5, base_prob - 25)
    except Exception:
        pass

    prob = min(95, max(5, base_prob))
    level = "Élevée" if prob >= 70 else ("Moyenne" if prob >= 40 else "Faible")
    return (file_type, prob, level)


class PythonCryptoVisitor(ast.NodeVisitor):
    """Analyse l'arbre syntaxique (AST) du code Python pour détecter les appels cryptographiques."""
    def __init__(self, filepath: str, lines: list = None):
        self.filepath = filepath
        self.lines = lines or []
        self.findings = []

    def visit_Call(self, node: ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id

        if func_name == "encode":
            lineno = getattr(node, "lineno", 1)
            raw_line = self.lines[lineno - 1] if 1 <= lineno <= len(self.lines) else ""
            if not has_inline_ignore(raw_line) and any(alg in raw_line for alg in ("RS256", "RS384", "RS512", "ES256", "ES384", "PS256")):
                self.findings.append({
                    "file": self.filepath,
                    "line": lineno,
                    "type": "Authentification JWT (Python AST)",
                    "detected": raw_line.strip(),
                    "algo": "Signature JWT Asymétrique Classique (RS256/ES256 — Vulnérable à Shor)",
                    "risk": "CRITIQUE",
                    "remediation": "Planifier la migration des jetons JWT vers ML-DSA-65 (FIPS 204) ou des jetons hybrides."
                })

        if func_name in PQC_RULES:
            lineno = getattr(node, "lineno", 1)
            raw_line = self.lines[lineno - 1] if 1 <= lineno <= len(self.lines) else ""
            if not has_inline_ignore(raw_line):
                rule = PQC_RULES[func_name]
                self.findings.append({
                    "file": self.filepath,
                    "line": lineno,
                    "type": "Code Python (AST)",
                    "detected": func_name,
                    "algo": rule["algo"],
                    "risk": rule["risk"],
                    "remediation": rule["remediation"]
                })
        self.generic_visit(node)


def scan_multilang_source(filepath: Path) -> list:
    """Scanne les fichiers source Java (.java), Go (.go), Node.js/TS (.js, .ts) et C# (.cs)."""
    findings = []
    suffix = filepath.suffix.lower()
    content = filepath.read_text(encoding="utf-8", errors="ignore")
    lines = content.splitlines()

    for i, line in enumerate(lines, start=1):
        clean = line.strip()
        if not clean or clean.startswith("//") or clean.startswith("/*") or clean.startswith("*"):
            continue
        if has_inline_ignore(clean):
            continue

        # 1. Règles Java (JCA / BouncyCastle)
        if suffix == ".java":
            if "KeyPairGenerator.getInstance" in clean and any(alg in clean.upper() for alg in ('"RSA"', '"EC"', '"ECDSA"', '"DSA"', '"DH"')):
                findings.append({
                    "file": str(filepath),
                    "line": i,
                    "type": "Code Java (JCA)",
                    "detected": clean,
                    "algo": "Java KeyPairGenerator RSA/ECC (Vulnérable à Shor)",
                    "risk": "CRITIQUE",
                    "remediation": "Utiliser BouncyCastle PQC (bcprov-jdk18on 1.78+) avec ML-KEM (Kyber) ou ML-DSA (Dilithium)."
                })
            elif "Cipher.getInstance" in clean and "RSA" in clean.upper():
                findings.append({
                    "file": str(filepath),
                    "line": i,
                    "type": "Code Java (JCA)",
                    "detected": clean,
                    "algo": "Chiffrement RSA Java (Vulnérable à Shor)",
                    "risk": "CRITIQUE",
                    "remediation": "Remplacer le chiffrement asymétrique RSA par une encapsulation KEM hybride (ML-KEM-768 + AES-256-GCM)."
                })
            elif "MessageDigest.getInstance" in clean and any(h in clean.upper() for h in ('"SHA-1"', '"SHA1"', '"MD5"')):
                findings.append({
                    "file": str(filepath),
                    "line": i,
                    "type": "Code Java (JCA)",
                    "detected": clean,
                    "algo": "Hachage Java SHA-1 / MD5 Obsolète",
                    "risk": "ÉLEVÉ",
                    "remediation": "Migrer vers MessageDigest.getInstance(\"SHA-256\") ou \"SHA3-256\"."
                })

        # 2. Règles Go (crypto/rsa, crypto/ecdsa, crypto/sha1)
        elif suffix == ".go":
            if "rsa.GenerateKey" in clean or "ecdsa.GenerateKey" in clean or "elliptic.P256()" in clean or "elliptic.P384()" in clean:
                findings.append({
                    "file": str(filepath),
                    "line": i,
                    "type": "Code Go (Stdlib)",
                    "detected": clean,
                    "algo": "Go crypto/rsa ou crypto/ecdsa (Vulnérable à Shor)",
                    "risk": "CRITIQUE",
                    "remediation": "Migrer vers crypto/mlkem (Go 1.24+) ou cloudflare/circl pour l'encapsulation hybride X25519MLKEM768."
                })
            elif "sha1.New()" in clean or "md5.New()" in clean or "sha1.Sum(" in clean or "md5.Sum(" in clean:
                findings.append({
                    "file": str(filepath),
                    "line": i,
                    "type": "Code Go (Stdlib)",
                    "detected": clean,
                    "algo": "Hachage Go SHA-1 / MD5 Obsolète",
                    "risk": "ÉLEVÉ",
                    "remediation": "Remplacer par crypto/sha256 ou golang.org/x/crypto/sha3."
                })

        # 3. Règles Node.js / TypeScript (node:crypto / WebCrypto)
        elif suffix in (".js", ".ts", ".mjs", ".cjs"):
            if ("generateKeyPair" in clean or "generateKeyPairSync" in clean or "createSign" in clean) and any(
                alg in clean.lower() for alg in ("'rsa'", '"rsa"', "'ec'", '"ec"', "'dsa'", '"dsa"', "secp256k1", "prime256v1", "p-256")
            ):
                findings.append({
                    "file": str(filepath),
                    "line": i,
                    "type": "Code Node.js / TS",
                    "detected": clean,
                    "algo": "Node.js crypto RSA / ECDSA (Vulnérable à Shor)",
                    "risk": "CRITIQUE",
                    "remediation": "Migrer vers un binding liboqs / OpenSSL 3.2+ ou WebCrypto supportant ML-KEM (FIPS 203) et ML-DSA (FIPS 204)."
                })
            elif "createHash(" in clean and any(h in clean.lower() for h in ("'sha1'", '"sha1"', "'md5'", '"md5"')):
                findings.append({
                    "file": str(filepath),
                    "line": i,
                    "type": "Code Node.js / TS",
                    "detected": clean,
                    "algo": "Hachage Node.js SHA-1 / MD5 Obsolète",
                    "risk": "ÉLEVÉ",
                    "remediation": "Utiliser crypto.createHash('sha256') ou 'sha3-256'."
                })

        # 4. Règles C# / .NET (System.Security.Cryptography)
        elif suffix == ".cs":
            if any(k in clean for k in ("RSA.Create(", "RSACryptoServiceProvider", "ECDsa.Create(", "ECDiffieHellman.Create(")):
                findings.append({
                    "file": str(filepath),
                    "line": i,
                    "type": "Code C# (.NET)",
                    "detected": clean,
                    "algo": ".NET RSA / ECDsa Asymétrique Classique (Vulnérable à Shor)",
                    "risk": "CRITIQUE",
                    "remediation": "Migrer vers System.Security.Cryptography.MLKem / MLDsa (.NET 9+) ou BouncyCastle.Cryptography PQC."
                })
            elif any(h in clean for h in ("SHA1.Create(", "SHA1Managed", "MD5.Create(", "MD5CryptoServiceProvider")):
                findings.append({
                    "file": str(filepath),
                    "line": i,
                    "type": "Code C# (.NET)",
                    "detected": clean,
                    "algo": "Hachage .NET SHA-1 / MD5 Obsolète",
                    "risk": "ÉLEVÉ",
                    "remediation": "Remplacer par SHA256.Create() ou SHA3_256.Create()."
                })

        # 5. Règles transverses JWT / OIDC / JWS (RS256, ES256, PS256...) tous langages
        jwt_match = re.search(r'''(?:algorithm|algorithms|alg|SecurityAlgorithms)\s*(?:=|:|\.)\s*[\['"]?(RS256|RS384|RS512|ES256|ES384|ES512|PS256|PS384|PS512|RsaSha256|EcdsaSha256)''', clean)
        if jwt_match:
            jwt_alg = jwt_match.group(1)
            findings.append({
                "file": str(filepath),
                "line": i,
                "type": "Authentification JWT / OIDC",
                "detected": clean,
                "algo": f"Signature JWS/JWT Asymétrique Classique ({jwt_alg} — Vulnérable à Shor)",
                "risk": "CRITIQUE",
                "remediation": f"Préparer la migration des jetons {jwt_alg} vers des signatures post-quantiques ML-DSA-65 (FIPS 204 / draft-ietf-jose-dilithium) ou jetons symétriques HMAC-SHA384 internes."
            })
    return findings


def scan_sca_dependencies(filepath: Path) -> list:
    """
    Scanne les manifestes de dépendances et fichiers d'héritage de tous les langages supportés :
    - Python : requirements.txt, Pipfile, poetry.lock
    - Node.js / TS : package.json, package-lock.json, yarn.lock
    - Go : go.mod, go.sum
    - Java : pom.xml, build.gradle, build.gradle.kts
    - C# (.NET) : *.csproj, packages.config, Directory.Packages.props
    - Rust : Cargo.toml, Cargo.lock
    - IaC Helm / Terraform : Chart.yaml, .terraform.lock.hcl
    """
    findings = []
    fname = filepath.name.lower()
    suffix = filepath.suffix.lower()
    content = filepath.read_text(encoding="utf-8", errors="ignore")
    lines = content.splitlines()

    # 1. Python (requirements.txt, Pipfile, poetry.lock)
    if fname in ("requirements.txt", "pipfile", "poetry.lock"):
        py_sca_rules = {
            "cryptography": ((42, 0, 0), "CRITIQUE", "Mettre à niveau vers cryptography>=42.0.0 (OpenSSL 3.2+ compatible ML-KEM)."),
            "pyopenssl": ((24, 0, 0), "ÉLEVÉ", "Mettre à niveau vers pyOpenSSL>=24.0.0 pour supporter OpenSSL 3.2+."),
            "paramiko": ((3, 4, 0), "ÉLEVÉ", "Mettre à niveau vers paramiko>=3.4.0 et activer les échanges de clés hybrides SSH."),
            "pycrypto": ((999, 0, 0), "CRITIQUE", "Remplacer pycrypto (abandonné et vulnérable) par cryptography>=42.0.0 ou liboqs-python."),
            "pycryptodome": ((3, 20, 0), "MOYEN", "Mettre à niveau pycryptodome>=3.20.0 et hybrider les échanges asymétriques avec liboqs."),
            "rsa": ((999, 0, 0), "CRITIQUE", "Le paquet python-rsa pur repose sur RSA classique vulnérable à Shor. Migrer vers cryptography / liboqs."),
            "ecdsa": ((999, 0, 0), "CRITIQUE", "Le paquet python-ecdsa pur est vulnérable à Shor (et aux attaques par canal auxiliaire). Migrer vers cryptography / ML-DSA."),
        }
        for i, line in enumerate(lines, start=1):
            clean = line.strip()
            if not clean or clean.startswith("#") or has_inline_ignore(clean):
                continue
            m = re.match(r'^([a-zA-Z0-9_.-]+)\s*(?:==|<=|~=|>=|<|=\s*[\'"])\s*([0-9][0-9a-zA-Z._-]*)', clean)
            if m:
                pkg = m.group(1).lower()
                ver = m.group(2)
                if pkg in py_sca_rules:
                    min_ver, risk, rem = py_sca_rules[pkg]
                    if parse_version_tuple(ver) < min_ver:
                        findings.append({
                            "file": str(filepath),
                            "line": i,
                            "type": "Dépendance SCA (Python)",
                            "detected": clean,
                            "algo": f"Dépendance Python {pkg} ({ver}) incompatible PQC",
                            "risk": risk,
                            "remediation": rem
                        })

    # 2. Node.js / TypeScript (package.json, package-lock.json, yarn.lock)
    elif fname in ("package.json", "package-lock.json", "yarn.lock"):
        js_sca_rules = {
            "crypto-js": ("ÉLEVÉ", "Remplacer crypto-js par l'API native Node.js WebCrypto (OpenSSL 3.2+) ou liboqs-node."),
            "node-rsa": ("CRITIQUE", "node-rsa implémente uniquement RSA classique (vulnérable à Shor). Migrer vers WebCrypto / ML-KEM."),
            "jsrsasign": ("ÉLEVÉ", "jsrsasign repose sur RSA/ECDSA classiques. Planifier la migration vers des jetons signés ML-DSA (FIPS 204)."),
            "elliptic": ("CRITIQUE", "La bibliothèque elliptic (ECDSA/ECDH classiques) est vulnérable à Shor et comporte des CVE critiques."),
            "rsa-pem": ("CRITIQUE", "Dépendance RSA classique vulnérable à l'algorithme de Shor."),
            " ssh2": ("MOYEN", "Vérifier que ssh2>=1.15.0 est utilisé avec échange de clés hybride post-quantique."),
        }
        for i, line in enumerate(lines, start=1):
            clean = line.strip()
            if has_inline_ignore(clean):
                continue
            for pkg, (risk, rem) in js_sca_rules.items():
                p_clean = pkg.strip()
                if f'"{p_clean}"' in clean or clean.startswith(f"{p_clean}@"):
                    findings.append({
                        "file": str(filepath),
                        "line": i,
                        "type": "Dépendance SCA (Node.js/TS)",
                        "detected": clean.rstrip(","),
                        "algo": f"Package npm '{p_clean}' non résistant au quantique",
                        "risk": risk,
                        "remediation": rem
                    })

    # 3. Go (go.mod, go.sum)
    elif fname in ("go.mod", "go.sum"):
        for i, line in enumerate(lines, start=1):
            clean = line.strip()
            if not clean or clean.startswith("//") or has_inline_ignore(clean):
                continue
            if fname == "go.mod" and clean.startswith("go "):
                ver_str = clean.split()[1]
                if parse_version_tuple(ver_str) < (1, 24, 0):
                    findings.append({
                        "file": str(filepath),
                        "line": i,
                        "type": "Dépendance SCA (Go)",
                        "detected": clean,
                        "algo": f"Runtime Go {ver_str} (< 1.24 requis pour crypto/mlkem natif)",
                        "risk": "MOYEN",
                        "remediation": "Mettre à niveau vers Go 1.24+ pour bénéficier du support standard crypto/mlkem et TLS X25519MLKEM768."
                    })
            if "golang.org/x/crypto" in clean and any(old in clean for old in ("v0.0.", "v0.1.", "v0.2.", "v0.3.", "v0.4.", "v0.5.", "v0.6.", "v0.7.", "v0.8.", "v0.9.", "v0.10.", "v0.11.", "v0.12.", "v0.13.", "v0.14.", "v0.15.", "v0.16.", "v0.17.")):
                findings.append({
                    "file": str(filepath),
                    "line": i,
                    "type": "Dépendance SCA (Go)",
                    "detected": clean,
                    "algo": "Module golang.org/x/crypto obsolète",
                    "risk": "ÉLEVÉ",
                    "remediation": "Mettre à niveau golang.org/x/crypto vers >= v0.31.0 ou adopter cloudflare/circl (ML-KEM / ML-DSA)."
                })

    # 4. Java (pom.xml, build.gradle, build.gradle.kts)
    elif fname in ("pom.xml", "build.gradle", "build.gradle.kts") or suffix in (".gradle", ".kts"):
        for i, line in enumerate(lines, start=1):
            clean = line.strip()
            if has_inline_ignore(clean):
                continue
            if "bcprov-jdk15on" in clean or "bcprov-jdk15to18" in clean or "bcprov-jdk14" in clean:
                findings.append({
                    "file": str(filepath),
                    "line": i,
                    "type": "Dépendance SCA (Java)",
                    "detected": clean,
                    "algo": "BouncyCastle Legacy (sans support NIST FIPS 203/204)",
                    "risk": "CRITIQUE",
                    "remediation": "Migrer vers org.bouncycastle:bcprov-jdk18on (v1.78+) supportant ML-KEM et ML-DSA."
                })
            elif "bcprov-jdk18on" in clean:
                m_ver = re.search(r"1\.(\d+)", clean)
                if m_ver and int(m_ver.group(1)) < 78:
                    findings.append({
                        "file": str(filepath),
                        "line": i,
                        "type": "Dépendance SCA (Java)",
                        "detected": clean,
                        "algo": f"BouncyCastle 1.{m_ver.group(1)} (< 1.78 requis pour FIPS 203/204 final)",
                        "risk": "ÉLEVÉ",
                        "remediation": "Mettre à niveau org.bouncycastle:bcprov-jdk18on vers la version 1.78 ou supérieure."
                    })

    # 5. C# / .NET (*.csproj, packages.config, Directory.Packages.props)
    elif suffix in (".csproj", ".props") or fname == "packages.config":
        for i, line in enumerate(lines, start=1):
            clean = line.strip()
            if not clean or has_inline_ignore(clean):
                continue
            low = clean.lower()
            if "<targetframework>" in low or "<targetframeworks>" in low:
                if any(old_tf in low for old_tf in ("netcoreapp", "netstandard", "net4", "net5.0", "net6.0", "net7.0", "net8.0")):
                    findings.append({
                        "file": str(filepath),
                        "line": i,
                        "type": "Héritage Runtime (.NET)",
                        "detected": clean,
                        "algo": "Framework .NET < 9.0 (Sans support natif MLKem / MLDsa)",
                        "risk": "MOYEN",
                        "remediation": "Migrer vers <TargetFramework>net9.0</TargetFramework> (System.Security.Cryptography.MLKem) ou ajouter BouncyCastle.Cryptography >= 2.4.0."
                    })
            if 'include="bouncycastle"' in low or 'id="bouncycastle"' in low or "portable.bouncycastle" in low:
                findings.append({
                    "file": str(filepath),
                    "line": i,
                    "type": "Dépendance SCA (NuGet C#)",
                    "detected": clean,
                    "algo": "Package NuGet BouncyCastle Legacy (Obsolète & sans PQC)",
                    "risk": "CRITIQUE",
                    "remediation": "Remplacer par le package officiel 'BouncyCastle.Cryptography' (version >= 2.4.0) supportant ML-KEM et ML-DSA."
                })
            elif "bouncycastle.cryptography" in low:
                m_ver = re.search(r'version\s*=\s*"([0-9.]+)"', low)
                if m_ver and parse_version_tuple(m_ver.group(1)) < (2, 4, 0):
                    findings.append({
                        "file": str(filepath),
                        "line": i,
                        "type": "Dépendance SCA (NuGet C#)",
                        "detected": clean,
                        "algo": f"BouncyCastle.Cryptography {m_ver.group(1)} (< 2.4.0 requis pour FIPS 203)",
                        "risk": "ÉLEVÉ",
                        "remediation": "Mettre à niveau BouncyCastle.Cryptography vers >= 2.4.0."
                    })

    # 6. Rust (Cargo.toml, Cargo.lock)
    elif fname in ("cargo.toml", "cargo.lock"):
        for i, line in enumerate(lines, start=1):
            clean = line.strip()
            if not clean or clean.startswith("#") or has_inline_ignore(clean):
                continue
            if re.match(r"^(rsa|ecdsa|p256|sha1|md-5)\s*=", clean):
                findings.append({
                    "file": str(filepath),
                    "line": i,
                    "type": "Dépendance SCA (Cargo)",
                    "detected": clean,
                    "algo": "Crate Rust asymétrique/hachage classique",
                    "risk": "ÉLEVÉ",
                    "remediation": "Adopter les crates post-quantiques pqcrypto-mlkem / pqcrypto-mldsa ou rustls (0.23+) avec X25519MLKEM768."
                })

    # 7. Dépendances IaC Helm (Chart.yaml) & Providers Terraform (.terraform.lock.hcl)
    elif fname == "chart.yaml":
        for i, line in enumerate(lines, start=1):
            clean = line.strip()
            if not clean or clean.startswith("#") or has_inline_ignore(clean):
                continue
            if "version:" in clean.lower() and any(k in content.lower() for k in ("ingress-nginx", "traefik", "cert-manager")):
                ver_m = re.search(r"([0-9]+\.[0-9]+\.[0-9]+)", clean)
                if ver_m and parse_version_tuple(ver_m.group(1)) < (1, 10, 0):
                    findings.append({
                        "file": str(filepath),
                        "line": i,
                        "type": "Dépendance IaC (Helm Chart)",
                        "detected": clean,
                        "algo": f"Sous-Chart Helm Ingress/TLS ({ver_m.group(1)}) sans support OpenSSL 3.2+ PQC",
                        "risk": "MOYEN",
                        "remediation": "Mettre à jour la dépendance dans Chart.yaml vers une version récente embarquant OpenSSL 3.2+ et X25519MLKEM768."
                    })

    return findings


def inspect_x509_details(filepath: Path) -> tuple[str, str]:
    """Extrait l'algorithme de signature, la taille de clé et la date d'expiration d'un certificat X.509 via OpenSSL."""
    openssl_bin = shutil.which("openssl")
    if not openssl_bin:
        return ("Certificat X.509 Classique (RSA/ECDSA)", "Expiration non inspectée")
    try:
        proc = subprocess.run(
            [openssl_bin, "x509", "-in", str(filepath), "-noout", "-text", "-enddate"],
            capture_output=True, text=True, encoding="utf-8", errors="ignore", timeout=4
        )
        out = proc.stdout or ""
        sig_m = re.search(r"Signature Algorithm:\s*(.+)", out)
        bits_m = re.search(r"Public-Key:\s*\((\d+\s*bit)\)", out)
        exp_m = re.search(r"notAfter=(.+)", out)
        sig_str = sig_m.group(1).strip() if sig_m else "RSA/ECDSA"
        bits_str = f" ({bits_m.group(1)})" if bits_m else ""
        exp_str = f"Expire le : {exp_m.group(1).strip()}" if exp_m else "Certificat X.509 actif"
        return (f"Certificat X.509 {sig_str}{bits_str}", exp_str)
    except Exception:
        return ("Certificat X.509 Classique (RSA/ECDSA)", "Certificat X.509 statique")


def scan_static_cert_or_key(filepath: Path) -> list:
    """
    Scanne les fichiers de certificats X.509 avec inspection cryptographique profonde
    (.pem, .crt, .cer, .key, .pub) pour identifier l'algorithme, la taille de clé et l'expiration.
    """
    findings = []
    content = filepath.read_text(encoding="utf-8", errors="ignore")
    lines = content.splitlines()

    for i, line in enumerate(lines, start=1):
        clean = line.strip()
        if has_inline_ignore(clean):
            continue
        if "-----BEGIN RSA PRIVATE KEY-----" in clean or "-----BEGIN EC PRIVATE KEY-----" in clean or "-----BEGIN PRIVATE KEY-----" in clean or "-----BEGIN OPENSSH PRIVATE KEY-----" in clean:
            findings.append({
                "file": str(filepath),
                "line": i,
                "type": "Clé Statique (PKI)",
                "detected": clean,
                "algo": "Clé Privée Asymétrique Statique sur le disque (RSA/ECC)",
                "risk": "CRITIQUE",
                "remediation": "Révoquer la clé statique versionnée, utiliser un coffre-fort (Vault/KMS) et planifier l'hybridation PQC (ML-KEM / ML-DSA)."
            })
        elif "-----BEGIN CERTIFICATE-----" in clean:
            algo_label, exp_detail = inspect_x509_details(filepath)
            risk_lvl = "CRITIQUE" if ("1024" in algo_label or "sha1" in algo_label.lower() or "md5" in algo_label.lower()) else "MOYEN"
            findings.append({
                "file": str(filepath),
                "line": i,
                "type": "Certificat X.509 (PKI)",
                "detected": f"{clean} ({exp_detail})",
                "algo": algo_label,
                "risk": risk_lvl,
                "remediation": "Inventorié dans le CBOM. Planifier la migration vers des certificats hybrides, ML-DSA (FIPS 204) ou Merkle Tree Certificates (MTC)."
            })
        elif clean.startswith("ssh-rsa ") or clean.startswith("ecdsa-sha2-"):
            findings.append({
                "file": str(filepath),
                "line": i,
                "type": "Clé Publique SSH",
                "detected": clean[:60] + "...",
                "algo": "Clé SSH Asymétrique Classique (ssh-rsa / ecdsa vulnérable à Shor)",
                "risk": "ÉLEVÉ",
                "remediation": "Régénérer les clés SSH et configurer OpenSSH 9.9+ avec KexAlgorithms hybride 'mlkem768x25519-sha256,sntrup761x25519-sha512'."
            })

    return findings


def scan_ssh_and_proxy_configs(filepath: Path) -> list:
    """Scanne sshd_config, ssh_config, Caddyfile et haproxy.cfg pour détecter l'absence de KEX post-quantique."""
    findings = []
    fname = filepath.name.lower()
    content = filepath.read_text(encoding="utf-8", errors="ignore")
    lines = content.splitlines()

    if fname in ("sshd_config", "ssh_config"):
        has_pqc_kex = any(k in content.lower() for k in ("mlkem768x25519", "sntrup761x25519"))
        if not has_pqc_kex:
            findings.append({
                "file": str(filepath),
                "line": 1,
                "type": "Infra SSH (OpenSSH)",
                "detected": f"Configuration {filepath.name} sans KexAlgorithms post-quantique",
                "algo": "Échange de clés SSH classique (ECDH / Diffie-Hellman vulnérable à HNDL)",
                "risk": "ÉLEVÉ",
                "remediation": "Ajouter 'KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256' (OpenSSH 9.0+/9.9+)."
            })
    elif fname == "haproxy.cfg":
        if "ssl-default-bind-options" in content.lower() and "tlsv1.3" not in content.lower():
            findings.append({
                "file": str(filepath),
                "line": 1,
                "type": "Infra (HAProxy)",
                "detected": "ssl-default-bind-options sans force-tlsv13",
                "algo": "HAProxy TLS < 1.3 ou sans courbes PQC",
                "risk": "CRITIQUE",
                "remediation": "Configurer 'ssl-default-bind-options ssl-min-ver TLSv1.3' et 'ssl-default-bind-curves X25519MLKEM768:X25519'."
            })
    return findings


def scan_nginx_config(filepath: Path) -> list:
    """Scanne les fichiers de configuration Nginx pour vérifier la présence de TLS hybride PQC."""
    findings = []
    content = filepath.read_text(encoding="utf-8", errors="ignore")
    lines = content.splitlines()

    has_ssl = False
    has_pqc_curves = False

    for i, line in enumerate(lines, start=1):
        clean_line = line.strip()
        if clean_line.startswith("#") or has_inline_ignore(clean_line):
            continue
        if "ssl_protocols" in clean_line:
            has_ssl = True
            if "TLSv1.3" not in clean_line or any(old in clean_line for old in ("TLSv1 ", "TLSv1.0", "TLSv1.1", "TLSv1.2")):
                findings.append({
                    "file": str(filepath),
                    "line": i,
                    "type": "Infra (Nginx)",
                    "detected": clean_line,
                    "algo": "TLS < 1.3",
                    "risk": "CRITIQUE",
                    "remediation": "Activer TLSv1.3 (prérequis obligatoire pour l'échange de clés post-quantique ML-KEM)."
                })
        if "ssl_ecdh_curve" in clean_line:
            if "MLKEM" in clean_line.upper() or "KYBER" in clean_line.upper():
                has_pqc_curves = True

    if has_ssl and not has_pqc_curves:
        findings.append({
            "file": str(filepath),
            "line": 1,
            "type": "Infra (Nginx)",
            "detected": "Absence de courbe hybride PQC",
            "algo": "Échange de clés ECDHE classique",
            "risk": "MOYEN",
            "remediation": "Ajouter 'ssl_ecdh_curve X25519MLKEM768:X25519;' (Supporté dès OpenSSL 3.2+ / Nginx récent)."
        })
    return findings


def scan_dockerfile(filepath: Path) -> list:
    """
    Scanne les Dockerfiles avec résolution d'héritage Multi-Stage (FROM ... AS stage -> FROM stage)
    et détection des images OS ou runtimes langages embarquant OpenSSL < 3.2.
    """
    findings = []
    content = filepath.read_text(encoding="utf-8", errors="ignore")
    lines = content.splitlines()

    legacy_base_patterns = (
        "buster", "stretch", "bullseye", "ubuntu:18.04", "ubuntu:20.04",
        "alpine:3.12", "alpine:3.13", "alpine:3.14", "alpine:3.15", "alpine:3.16", "alpine:3.17", "alpine:3.18",
        "node:14", "node:16", "node:18", "python:3.7", "python:3.8", "golang:1.18", "golang:1.19", "golang:1.20",
        "aspnet:6.0", "aspnet:7.0", "sdk:6.0", "sdk:7.0"
    )

    vulnerable_stages = {}

    for i, line in enumerate(lines, start=1):
        clean_line = line.strip()
        if not clean_line or clean_line.startswith("#") or has_inline_ignore(clean_line):
            continue

        lower_line = clean_line.lower()

        # 1. Vérification de l'image de base (FROM) et suivi de l'héritage Multi-Stage (AS <stage>)
        if lower_line.startswith("from "):
            m_from = re.match(r"^from\s+(?:--platform=[^\s]+\s+)?([^\s]+)(?:\s+as\s+([^\s]+))?", lower_line)
            base_img = m_from.group(1) if m_from else lower_line
            stage_alias = m_from.group(2) if (m_from and m_from.group(2)) else None

            if any(pat in base_img for pat in legacy_base_patterns):
                if stage_alias:
                    vulnerable_stages[stage_alias] = base_img
                findings.append({
                    "file": str(filepath),
                    "line": i,
                    "type": "Conteneur (Docker)",
                    "detected": clean_line,
                    "algo": f"Image de base Legacy ({base_img} — OpenSSL < 3.2)",
                    "risk": "ÉLEVÉ",
                    "remediation": "Migrer vers une image de base récente (ex: bookworm/trixie, ubuntu:24.04, alpine:3.20+, node:22, dotnet:9.0) embarquant OpenSSL 3.2+."
                })
            elif base_img in vulnerable_stages:
                parent_img = vulnerable_stages[base_img]
                if stage_alias:
                    vulnerable_stages[stage_alias] = parent_img
                findings.append({
                    "file": str(filepath),
                    "line": i,
                    "type": "Héritage Docker (Multi-Stage)",
                    "detected": clean_line,
                    "algo": f"Stage Docker héritant d'un parent non-PQC ('{base_img}' issu de '{parent_img}')",
                    "risk": "MOYEN",
                    "remediation": f"Mettre à niveau le stage parent '{base_img}' ({parent_img}) vers une image compatible OpenSSL 3.2+."
                })

        # 2. Vérification d'installation explicite d'OpenSSL obsolète (1.1.x, 1.0.x, 3.0.x)
        if "openssl" in lower_line and any(ver in lower_line for ver in ("1.1.", "1.0.", "3.0.", "libssl1.1")):
            findings.append({
                "file": str(filepath),
                "line": i,
                "type": "Conteneur (Docker)",
                "detected": clean_line,
                "algo": "OpenSSL Obsolète (Incompatible PQC)",
                "risk": "CRITIQUE",
                "remediation": "Mettre à niveau vers OpenSSL 3.2+ (ou 3.5+) avec oqs-provider pour supporter ML-KEM (FIPS 203) et ML-DSA (FIPS 204)."
            })

        # 3. Détection de génération de clés RSA/ECDSA en ligne de commande dans le Dockerfile
        if "openssl genrsa" in lower_line or "ssh-keygen -t rsa" in lower_line or "ecparam" in lower_line:
            findings.append({
                "file": str(filepath),
                "line": i,
                "type": "Conteneur (Docker)",
                "detected": clean_line,
                "algo": "Génération de clé RSA/ECC dans l'image",
                "risk": "CRITIQUE",
                "remediation": "Ne pas générer de clés asymétriques classiques dans le build Docker ; utiliser des certificats hybrides injectés au runtime."
            })

    return findings


def scan_live_tls_endpoint(target_url: str) -> list:
    """Inspecte un endpoint TLS en direct pour vérifier TLS 1.3, le certificat et l'hybridation PQC."""
    findings = []

    if "://" not in target_url:
        target_url = f"https://{target_url}"
    parsed = urlparse(target_url)
    hostname = parsed.hostname or target_url
    port = parsed.port or 443
    endpoint_label = f"{hostname}:{port}"

    console.print(f"[cyan]🌐 Inspection TLS en direct sur :[/cyan] [bold white]{endpoint_label}[/bold white]")

    tls_version = None
    cipher_name = None
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_version = ssock.version()
                cipher_info = ssock.cipher()
                cipher_name = cipher_info[0] if cipher_info else "Inconnu"
    except Exception as e:
        findings.append({
            "file": endpoint_label,
            "line": port,
            "type": "Réseau (TLS Live)",
            "detected": f"Erreur de connexion : {e}",
            "algo": "Endpoint TLS Injoignable / Invalide",
            "risk": "ÉLEVÉ",
            "remediation": "Vérifier l'accessibilité réseau, le pare-feu et la validité de la chaîne de certificats X.509."
        })
        return findings

    if tls_version != "TLSv1.3":
        findings.append({
            "file": endpoint_label,
            "line": port,
            "type": "Réseau (TLS Live)",
            "detected": f"Protocole négocié : {tls_version} ({cipher_name})",
            "algo": f"{tls_version} (< TLS 1.3)",
            "risk": "CRITIQUE",
            "remediation": "Activer TLSv1.3 sur le reverse-proxy / Load Balancer (requis pour l'échange de clés hybride ML-KEM)."
        })

    openssl_bin = shutil.which("openssl")
    negotiated_group = ""
    cert_sig_algo = ""

    if openssl_bin:
        try:
            proc = subprocess.run(
                [openssl_bin, "s_client", "-connect", endpoint_label, "-servername", hostname, "-brief"],
                input="",
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                timeout=6
            )
            output = (proc.stdout or "") + "\n" + (proc.stderr or "")
            for line in output.splitlines():
                low = line.lower()
                if "Server Temp Key" in line or "Peer Temp Key" in line or "Negotiated TLS1.3 group" in line:
                    negotiated_group = line.strip()
                elif "peer signing digest" in low or "signature type" in low:
                    cert_sig_algo = line.strip()
        except Exception:
            pass

    is_pqc_hybrid = any(k in negotiated_group.upper() for k in ("MLKEM", "KYBER"))
    if not is_pqc_hybrid:
        detected_kem = negotiated_group if negotiated_group else f"Handshake {tls_version} ({cipher_name}) sans KEM hybride"
        findings.append({
            "file": endpoint_label,
            "line": port,
            "type": "Réseau (TLS Live)",
            "detected": detected_kem,
            "algo": "Échange de clés TLS non hybridé (ECDHE classique)",
            "risk": "MOYEN",
            "remediation": "Activer la courbe hybride 'X25519MLKEM768:X25519' (OpenSSL 3.2+ / Nginx / Cloudflare) contre Harvest Now, Decrypt Later."
        })
    else:
        console.print(f"[bold green]🔒 Échange de clés hybride Post-Quantique actif sur {endpoint_label} ({negotiated_group})[/bold green]")

    findings.append({
        "file": endpoint_label,
        "line": port,
        "type": "Certificat (X.509)",
        "detected": cert_sig_algo or f"Certificat leaf sur {cipher_name}",
        "algo": "Certificat X.509 Asymétrique Classique (RSA/ECDSA)",
        "risk": "MOYEN",
        "remediation": "Inventorié dans le CBOM. Planifier la migration PKI vers des certificats hybrides ou ML-DSA (FIPS 204) d'ici 2028-2030."
    })

    return findings


def scan_yaml_iac(filepath: Path) -> list:
    """Scanne les fichiers YAML (Traefik & Kubernetes Ingress) pour vérifier TLS 1.3 et l'hybridation PQC."""
    findings = []
    content = filepath.read_text(encoding="utf-8", errors="ignore")
    lines = content.splitlines()
    lower_content = content.lower()

    is_k8s_ingress = ("kind: ingress" in lower_content) or ("networking.k8s.io" in lower_content)
    is_cert_manager = ("kind: certificate" in lower_content) and ("cert-manager.io" in lower_content)

    if is_k8s_ingress and "tls:" in lower_content:
        has_pqc_curve = any(k in lower_content for k in ("mlkem", "kyber", "x25519mlkem768"))
        for i, line in enumerate(lines, start=1):
            clean = line.strip()
            if clean.startswith("#") or has_inline_ignore(clean):
                continue
            if "ssl-protocols" in clean.lower() and "tlsv1.3" not in clean.lower():
                findings.append({
                    "file": str(filepath),
                    "line": i,
                    "type": "Infra (K8s Ingress)",
                    "detected": clean,
                    "algo": "Annotation Ingress TLS < 1.3",
                    "risk": "CRITIQUE",
                    "remediation": "Forcer 'nginx.ingress.kubernetes.io/ssl-protocols: \"TLSv1.3\"'."
                })
        if not has_pqc_curve:
            findings.append({
                "file": str(filepath),
                "line": 1,
                "type": "Infra (K8s Ingress)",
                "detected": "Terminaison TLS Ingress sans courbe hybride PQC",
                "algo": "K8s Ingress ECDHE Classique",
                "risk": "MOYEN",
                "remediation": "Ajouter l'annotation 'nginx.ingress.kubernetes.io/server-snippet: ssl_ecdh_curve X25519MLKEM768:X25519;'."
            })

    if is_cert_manager:
        for i, line in enumerate(lines, start=1):
            clean = line.strip()
            if has_inline_ignore(clean):
                continue
            if "algorithm:" in clean.lower() and any(a in clean.upper() for a in ("RSA", "ECDSA")):
                findings.append({
                    "file": str(filepath),
                    "line": i,
                    "type": "Infra (Cert-Manager K8s)",
                    "detected": clean,
                    "algo": "Clé privée X.509 Asymétrique Classique (RSA/ECDSA)",
                    "risk": "MOYEN",
                    "remediation": "Inventorié dans le CBOM. Préparer la migration PKI vers des certificats hybrides ou ML-DSA (FIPS 204)."
                })

    is_traefik = ("tls:" in lower_content) and (
        "options:" in lower_content or "curvepreferences" in lower_content or "minversion" in lower_content or "entrypoints" in lower_content
    )
    if is_traefik:
        has_traefik_pqc = any(k in lower_content for k in ("mlkem", "kyber", "x25519mlkem768"))
        for i, line in enumerate(lines, start=1):
            clean = line.strip()
            if clean.startswith("#") or has_inline_ignore(clean):
                continue
            if "minversion" in clean.lower() and "versiontls13" not in clean.lower() and "tlsv1.3" not in clean.lower():
                findings.append({
                    "file": str(filepath),
                    "line": i,
                    "type": "Infra (Traefik)",
                    "detected": clean,
                    "algo": "Traefik TLS minVersion < 1.3",
                    "risk": "CRITIQUE",
                    "remediation": "Définir 'minVersion: VersionTLS13' dans tls.options de Traefik."
                })
        if not has_traefik_pqc:
            findings.append({
                "file": str(filepath),
                "line": 1,
                "type": "Infra (Traefik)",
                "detected": "Absence de courbe post-quantique dans curvePreferences",
                "algo": "Traefik ECDHE Classique",
                "risk": "MOYEN",
                "remediation": "Configurer 'curvePreferences: [X25519MLKEM768, X25519]' dans tls.options (Traefik v3.1+)."
            })

    # Support Envoy Proxy (DownstreamTlsContext / ecdh_curves / tls_minimum_protocol_version)
    is_envoy = ("downstreamtlscontext" in lower_content) or ("envoy.transport_sockets.tls" in lower_content) or ("common_tls_context" in lower_content)
    if is_envoy:
        has_envoy_pqc = any(k in lower_content for k in ("mlkem", "kyber", "x25519mlkem768"))
        for i, line in enumerate(lines, start=1):
            clean = line.strip()
            if clean.startswith("#") or has_inline_ignore(clean):
                continue
            if "tls_minimum_protocol_version" in clean.lower() and "tlsv1_3" not in clean.lower():
                findings.append({
                    "file": str(filepath),
                    "line": i,
                    "type": "Infra (Envoy Proxy)",
                    "detected": clean,
                    "algo": "Envoy TLS minimum_protocol_version < TLSv1_3",
                    "risk": "CRITIQUE",
                    "remediation": "Forcer 'tls_minimum_protocol_version: TLSv1_3' dans common_tls_context.tls_params."
                })
        if not has_envoy_pqc:
            findings.append({
                "file": str(filepath),
                "line": 1,
                "type": "Infra (Envoy Proxy)",
                "detected": "DownstreamTlsContext sans groupe hybride dans ecdh_curves",
                "algo": "Envoy Proxy mTLS / TLS ECDHE Classique",
                "risk": "MOYEN",
                "remediation": "Ajouter 'ecdh_curves: [X25519MLKEM768, X25519]' dans tls_params d'Envoy Proxy."
            })

    # Support Istio Service Mesh (kind: Gateway / DestinationRule)
    is_istio = ("networking.istio.io" in lower_content) and ("tls:" in lower_content)
    if is_istio and "tlsv1_3" not in lower_content:
        findings.append({
            "file": str(filepath),
            "line": 1,
            "type": "Infra (Istio Mesh)",
            "detected": "Passerelle Istio sans minProtocolVersion: TLSV1_3",
            "algo": "Istio Gateway / mTLS < TLS 1.3",
            "risk": "ÉLEVÉ",
            "remediation": "Définir 'minProtocolVersion: TLSV1_3' et activer BoringSSL/OpenSSL PQC sur istio-ingressgateway."
        })

    return findings


def scan_terraform_file(filepath: Path) -> list:
    """
    Scanne les fichiers Terraform (.tf) pour détecter :
    1. Les ressources tls_private_key / KMS asymétriques RSA/ECDSA.
    2. Les politiques Load Balancer / CDN < TLS 1.3.
    3. Les appels de modules Terraform (module "..." { source = "..." }) liés à ALB/ELB/CloudFront/TLS/Ingress
       qui héritent d'une politique TLS 1.2 par défaut sans surcharger ssl_policy en TLS 1.3.
    """
    findings = []
    content = filepath.read_text(encoding="utf-8", errors="ignore")
    lines = content.splitlines()

    for i, line in enumerate(lines, start=1):
        clean = line.strip()
        if not clean or clean.startswith("#") or clean.startswith("//") or has_inline_ignore(clean):
            continue
        low = clean.lower()

        if "algorithm" in low and "=" in low and any(alg in clean.upper() for alg in ('"RSA"', '"ECDSA"', '"ED25519"')):
            findings.append({
                "file": str(filepath),
                "line": i,
                "type": "IaC (Terraform)",
                "detected": clean,
                "algo": "Génération de clé Terraform RSA / ECDSA (Vulnérable à Shor)",
                "risk": "CRITIQUE",
                "remediation": "Remplacer les clés statiques RSA/ECDSA par des mécanismes d'encapsulation hybrides (ML-KEM) ou signatures ML-DSA."
            })

        if ("ssl_policy" in low or "security_policy" in low or "minimum_protocol_version" in low) and (
            any(old_tls in clean.upper() for old_tls in ("TLS-1-0", "TLS-1-1", "TLS-1-2", "TLS1_0", "TLS1_1", "TLS1_2", "2016", "2017", "2021"))
            and "1-3" not in clean.upper()
            and "1_3" not in clean.upper()
        ):
            findings.append({
                "file": str(filepath),
                "line": i,
                "type": "IaC (Terraform)",
                "detected": clean,
                "algo": "Politique Cloud Load Balancer / CDN < TLS 1.3",
                "risk": "CRITIQUE",
                "remediation": "Mettre à niveau vers une politique TLS 1.3 supportant l'échange de clés post-quantique (ex: ELBSecurityPolicy-TLS13-1-2-2021-06 ou PQ-TLS)."
            })

    # 3. Analyse des blocs d'héritage `module "<name>" { ... }`
    for m_mod in re.finditer(r'module\s+"([^"]+)"\s*\{([^}]*)\}', content, flags=re.DOTALL):
        mod_name = m_mod.group(1)
        mod_body = m_mod.group(2)
        mod_line = content[:m_mod.start()].count("\n") + 1
        first_line = content.splitlines()[mod_line - 1] if mod_line <= len(lines) else ""
        if has_inline_ignore(first_line):
            continue

        body_low = mod_body.lower()
        is_net_or_crypto_mod = any(
            k in body_low or k in mod_name.lower()
            for k in ("alb", "elb", "load-balancer", "cloudfront", "cdn", "ingress", "acm", "kms", "tls", "gateway")
        )
        if is_net_or_crypto_mod:
            has_tls13_override = ("tls13" in body_low or "tls-1-3" in body_low or "tls_1_3" in body_low or "tlsv1.3" in body_low)
            if not has_tls13_override:
                src_match = re.search(r'source\s*=\s*"([^"]+)"', mod_body)
                src_label = src_match.group(1) if src_match else mod_name
                findings.append({
                    "file": str(filepath),
                    "line": mod_line,
                    "type": "Module IaC (Terraform)",
                    "detected": f'module "{mod_name}" (source: {src_label})',
                    "algo": f"Module Terraform '{mod_name}' héritant d'une politique TLS par défaut (< TLS 1.3)",
                    "risk": "ÉLEVÉ",
                    "remediation": "Surcharger explicitement 'ssl_policy = \"ELBSecurityPolicy-TLS13-1-2-2021-06\"' (ou équivalent TLS 1.3 PQC) dans les paramètres du module."
                })

    return findings



def simulate_mtu_impact(target_url: str = None, findings: list = None) -> dict:
    """
    Simule l'impact réseau MTU (1 500 octets) et la fragmentation TCP/IP lors du passage
    au handshake TLS 1.3 hybride (X25519MLKEM768) et aux signatures post-quantiques (ML-DSA-65 vs MTC).
    """
    # Tailles normalisées NIST FIPS 203 (ML-KEM-768) & FIPS 204 (ML-DSA-65)
    mtu_limit = 1500
    tcp_ip_overhead = 40
    mss = mtu_limit - tcp_ip_overhead  # 1460 octets utiles par segment TCP

    classical_client_hello = 320  # X25519 key_share (32B) + extensions TLS 1.3
    mlkem768_pubkey_bytes = 1184
    mlkem768_ciphertext_bytes = 1088
    mldsa65_cert_chain_bytes = 7850  # 2 certificats (Intermediate + Leaf) signés ML-DSA-65 (~3309B sig + 1952B pubkey chacun)
    mtc_merkle_proof_bytes = 960     # Preuve d'inclusion Merkle Tree Certificate (MTC)

    pqc_client_hello = classical_client_hello + mlkem768_pubkey_bytes  # ~1504 octets
    pqc_server_flight_mldsa = 280 + mlkem768_ciphertext_bytes + mldsa65_cert_chain_bytes  # ~9218 octets
    pqc_server_flight_mtc = 280 + mlkem768_ciphertext_bytes + mtc_merkle_proof_bytes      # ~2328 octets

    ch_segments = (pqc_client_hello + mss - 1) // mss
    sh_mldsa_segments = (pqc_server_flight_mldsa + mss - 1) // mss
    sh_mtc_segments = (pqc_server_flight_mtc + mss - 1) // mss

    sim_table = Table(
        title="🌐 Simulation d'Impact Réseau MTU (1 500 B) & Fragmentation TCP/TLS Post-Quantique (--simulate-mtu)",
        header_style="bold cyan"
    )
    sim_table.add_column("Scénario Handshake TLS 1.3", style="white")
    sim_table.add_column("Taille ClientHello", justify="right", style="cyan")
    sim_table.add_column("Taille ServerHello + Certs", justify="right", style="cyan")
    sim_table.add_column("Segments TCP (MSS 1460B)", justify="center")
    sim_table.add_column("Impact Latence & Middlebox", style="bold")

    sim_table.add_row(
        "1. Classique (X25519 + ECDSA P-256)",
        "320 B (1 seg)",
        "1 650 B (2 segs)",
        "3 segments",
        "[yellow]0 ms (Mais vulnérable à HNDL / Shor)[/yellow]"
    )
    sim_table.add_row(
        "2. Hybride KEM (X25519MLKEM768 + Cert X.509 ECDSA)",
        f"{pqc_client_hello} B ({ch_segments} segs)",
        "2 738 B (2 segs)",
        f"{ch_segments + 2} segments",
        "[bold green]✓ +0.8 ms (Optimal — Recommandé ANSSI 2026)[/bold green]"
    )
    sim_table.add_row(
        "3. Full PQC X.509 (X25519MLKEM768 + Chaîne ML-DSA-65)",
        f"{pqc_client_hello} B ({ch_segments} segs)",
        f"{pqc_server_flight_mldsa} B ({sh_mldsa_segments} segs)",
        f"{ch_segments + sh_mldsa_segments} segments",
        "[bold red]⚠️ +4.2 ms (Risque de rejet MTU / Firewall IP Frag)[/bold red]"
    )
    sim_table.add_row(
        "4. Full PQC + Merkle Tree Certificates (MTC IETF)",
        f"{pqc_client_hello} B ({ch_segments} segs)",
        f"{pqc_server_flight_mtc} B ({sh_mtc_segments} segs)",
        f"{ch_segments + sh_mtc_segments} segments",
        "[bold green]✓ +1.1 ms (Zéro dépassement initcwnd TCP)[/bold green]"
    )

    console.print("\n")
    console.print(sim_table)
    console.print(
        "[dim]💡 Diagnostic MTU Shorless : Activez dès maintenant X25519MLKEM768 (Scénario 2) et vérifiez que vos Load Balancers "
        "autorisent les ClientHello > 1460 octets (TCP Jumbo / Path MTU Discovery actif).[/dim]\n"
    )
    return {
        "mtu": mtu_limit,
        "mss": mss,
        "pqc_client_hello_bytes": pqc_client_hello,
        "pqc_server_mldsa_bytes": pqc_server_flight_mldsa,
        "pqc_server_mtc_bytes": pqc_server_flight_mtc
    }

def compute_pqc_score(total_findings: int, critical_count: int) -> int:
    """Calcule le Score de Maturité PQC (0 à 100) selon la courbe d'amortissement pondérée Shorless."""
    if total_findings <= 0:
        return 100
    other_count = max(0, total_findings - critical_count)
    weighted_penalty = (critical_count * 12) + (other_count * 4)
    return int(round(100 * (100 / (100 + weighted_penalty))))


def generate_cyclonedx_cbom(findings: list, output_path: str):
    """Génère un fichier CBOM (Cryptography Bill of Materials) au format standard CycloneDX 1.6."""
    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "Shorless", "name": "shorless-scanner", "version": SCANNER_VERSION}]
        },
        "components": []
    }

    for idx, f in enumerate(findings):
        cbom["components"].append({
            "type": "cryptographic-asset",
            "bom-ref": f"crypto-asset-{idx}",
            "name": f["algo"],
            "evidence": {
                "occurrences": [{"location": f["file"], "line": f["line"]}]
            },
            "cryptoProperties": {
                "assetType": "algorithm",
                "quantumSafe": "false",
                "remediation": f["remediation"]
            }
        })

    Path(output_path).write_text(json.dumps(cbom, indent=2, ensure_ascii=False), encoding="utf-8")


def generate_sarif_report(findings: list, output_path: str):
    """Génère un rapport au standard OASIS SARIF 2.1.0 pour GitHub Code Scanning & GitLab SAST."""
    rules_map = {}
    results = []

    for f in findings:
        rule_id = "SHORLESS-" + re.sub(r"[^A-Z0-9]+", "-", f["type"].upper()).strip("-")
        sarif_level = "error" if f["risk"] == "CRITIQUE" else ("warning" if f["risk"] == "ÉLEVÉ" else "note")

        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "name": f["type"],
                "shortDescription": {"text": f"Risque Post-Quantique ({f['type']})"},
                "fullDescription": {"text": "Détection d'algorithmes, de dépendances ou de configurations TLS vulnérables à l'algorithme de Shor ou Grover."},
                "help": {"text": f["remediation"]},
                "properties": {"tags": ["security", "post-quantum", "cryptography", "cbom", "nis2"]}
            }

        uri = str(f["file"]).replace("\\", "/").lstrip("./")
        results.append({
            "ruleId": rule_id,
            "level": sarif_level,
            "message": {
                "text": f"[{f['risk']}] {f['algo']} — Détecté : {f['detected']} | Remédiation : {f['remediation']}"
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": max(1, int(f.get("line", 1)))}
                }
            }]
        })

    sarif_doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "1.0.2",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Shorless PQC & CBOM Scanner",
                    "informationUri": "https://shorless.io",
                    "version": SCANNER_VERSION,
                    "rules": list(rules_map.values())
                }
            },
            "results": results
        }]
    }
    Path(output_path).write_text(json.dumps(sarif_doc, indent=2, ensure_ascii=False), encoding="utf-8")


def send_webhook_notification(webhook_url: str, project_name: str, score: int, total_findings: int, critical_count: int, pr_url: str = "") -> bool:
    """Envoie une alerte temps réel vers un Webhook Slack, Microsoft Teams ou Discord."""
    if not webhook_url or not webhook_url.strip():
        return False
    status_emoji = "🟢" if score >= 80 else ("🟠" if score >= 50 else "🔴")
    summary_text = (
        f"{status_emoji} *Shorless PQC Audit — Projet `{project_name}`*\n"
        f"• *Score de Maturité PQC :* `{score}/100`\n"
        f"• *Alertes détectées :* `{total_findings}` (dont `{critical_count}` critiques face à Shor)\n"
    )
    if pr_url:
        summary_text += f"• *Pull Request Auto-Fix :* {pr_url}\n"
    summary_text += "• *Console Cloud CBOM :* https://shorless.io/dashboard.html"

    # Format universel compatible Slack ("text"), Discord ("content") et Teams
    payload = json.dumps({
        "text": summary_text,
        "content": summary_text
    }).encode("utf-8")

    req = Request(
        webhook_url.strip(),
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": f"Shorless-Webhook/{SCANNER_VERSION}"},
        method="POST"
    )
    try:
        with urlopen(req, timeout=6) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


def generate_executive_html_report(findings: list, output_path: str, target_dir: str):
    """Génère un rapport d'audit exécutif HTML/PDF autonome pour RSSI, CTO et auditeurs NIS 2 / DORA."""
    now_str = datetime.now(timezone.utc).strftime("%d/%m/%Y à %H:%M UTC")
    total = len(findings)
    crit_count = sum(1 for f in findings if f["risk"] == "CRITIQUE")
    high_count = sum(1 for f in findings if f["risk"] == "ÉLEVÉ")
    med_count = sum(1 for f in findings if f["risk"] == "MOYEN")

    score = compute_pqc_score(total, crit_count)

    if score >= 80:
        grade, badge_color, status_text = "A — Prêt pour l'ère Post-Quantique", "#10B981", "CONFORME"
    elif score >= 50:
        grade, badge_color, status_text = "C — Transition Hybride Requise", "#F59E0B", "EXPOSITION MODÉRÉE"
    else:
        grade, badge_color, status_text = "E — Vulnérable à l'Algorithme de Shor", "#EF4444", "NON CONFORME (RISQUE CRITIQUE)"

    rows_html = []
    for f in findings:
        r_color = "#EF4444" if f["risk"] == "CRITIQUE" else ("#F59E0B" if f["risk"] == "ÉLEVÉ" else "#3B82F6")
        rows_html.append(f"""
        <tr>
            <td class="mono">{f['file']}:{f['line']}</td>
            <td><span class="tag">{f['type']}</span></td>
            <td><strong>{f['algo']}</strong><br><span class="detected">{f['detected']}</span></td>
            <td><span class="badge" style="background:{r_color}20;color:{r_color};border:1px solid {r_color}50;">{f['risk']}</span></td>
            <td>{f['remediation']}</td>
        </tr>""")

    html_content = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Rapport d'Audit Exécutif Post-Quantique (CBOM) — Shorless.io</title>
    <style>
        :root {{ --bg: #0B0F17; --card: #111827; --text: #F3F4F6; --muted: #9CA3AF; --accent: #10B981; --border: #1F2937; }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; background: var(--bg); color: var(--text); padding: 32px; line-height: 1.5; }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 20px; margin-bottom: 28px; }}
        .brand {{ font-family: monospace; font-size: 22px; font-weight: 800; color: #fff; }}
        .brand span {{ color: var(--accent); }}
        .btn-print {{ background: var(--accent); color: #06080D; border: none; padding: 10px 18px; border-radius: 8px; font-weight: 700; cursor: pointer; font-size: 13px; }}
        .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 28px; }}
        .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 20px; }}
        .card-title {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); margin-bottom: 8px; font-family: monospace; }}
        .score-val {{ font-size: 36px; font-weight: 800; font-family: monospace; }}
        .section-title {{ font-size: 18px; font-weight: 700; margin: 28px 0 14px; color: #fff; }}
        table {{ width: 100%; border-collapse: collapse; background: var(--card); border-radius: 12px; overflow: hidden; border: 1px solid var(--border); font-size: 13px; }}
        th {{ background: #06080D; color: var(--muted); text-align: left; padding: 12px 14px; font-family: monospace; font-size: 11px; text-transform: uppercase; border-bottom: 1px solid var(--border); }}
        td {{ padding: 12px 14px; border-bottom: 1px solid var(--border); vertical-align: top; }}
        .mono {{ font-family: monospace; color: #38BDF8; font-size: 12px; word-break: break-all; }}
        .detected {{ font-family: monospace; font-size: 11px; color: var(--muted); }}
        .tag {{ background: #1F2937; color: #E5E7EB; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-family: monospace; }}
        .badge {{ padding: 4px 10px; border-radius: 999px; font-size: 11px; font-weight: 700; font-family: monospace; display: inline-block; }}
        .compliance-box {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 28px; }}
        .cta-box {{ margin-top: 32px; background: linear-gradient(135deg, #064E3B 0%, #0F172A 100%); border: 1px solid #10B98150; border-radius: 12px; padding: 20px 24px; display: flex; justify-content: space-between; align-items: center; }}
        .footer {{ margin-top: 32px; text-align: center; font-size: 12px; color: var(--muted); border-top: 1px solid var(--border); padding-top: 16px; font-family: monospace; }}
        @media print {{
            body {{ background: #fff; color: #111; padding: 0; }}
            .card, table, .cta-box {{ background: #fff !important; border: 1px solid #ccc !important; color: #111 !important; }}
            th {{ background: #f3f4f6 !important; color: #111 !important; }}
            .brand, .section-title, strong {{ color: #000 !important; }}
            .btn-print {{ display: none !important; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <div class="brand">⚡ shorless<span>.io</span> — Rapport d'Audit Exécutif PQC &amp; CBOM</div>
                <div style="font-size:12px;color:var(--muted);margin-top:4px;font-family:monospace;">
                    Périmètre audité : {target_dir} • Généré le {now_str} • Standard OWASP CycloneDX 1.6
                </div>
            </div>
            <button class="btn-print" onclick="window.print()">🖨️ Imprimer / Exporter en PDF</button>
        </div>

        <div class="grid">
            <div class="card">
                <div class="card-title">Score de Maturité PQC</div>
                <div class="score-val" style="color:{badge_color};">{score}/100</div>
                <div style="font-size:12px;color:{badge_color};font-weight:600;margin-top:4px;">{grade}</div>
            </div>
            <div class="card">
                <div class="card-title">Risques Critiques (Shor)</div>
                <div class="score-val" style="color:#EF4444;">{crit_count}</div>
                <div style="font-size:12px;color:var(--muted);margin-top:4px;">Clés RSA/ECC &amp; TLS &lt; 1.3</div>
            </div>
            <div class="card">
                <div class="card-title">Risques Élevés (Grover / SCA)</div>
                <div class="score-val" style="color:#F59E0B;">{high_count}</div>
                <div style="font-size:12px;color:var(--muted);margin-top:4px;">SHA-1, MD5, Libs Legacy</div>
            </div>
            <div class="card">
                <div class="card-title">Risques Moyens (Non-Hybridé)</div>
                <div class="score-val" style="color:#3B82F6;">{med_count}</div>
                <div style="font-size:12px;color:var(--muted);margin-top:4px;">Absence de KEM X25519MLKEM768</div>
            </div>
        </div>

        <div class="section-title">1. État de Conformité Réglementaire &amp; Normative</div>
        <div class="compliance-box">
            <div class="card">
                <div class="card-title">NIST FIPS 203 (ML-KEM) &amp; FIPS 204</div>
                <div style="font-weight:700;color:{badge_color};margin-bottom:6px;">{status_text}</div>
                <p style="font-size:12px;color:var(--muted);">Vérifie l'encapsulation de clés post-quantique hybride et le remplacement des primitives RSA/ECDSA vulnérables à l'algorithme de Shor.</p>
            </div>
            <div class="card">
                <div class="card-title">Recommandations ANSSI (Hybridation)</div>
                <div style="font-weight:700;color:{'#10B981' if crit_count == 0 else '#EF4444'};margin-bottom:6px;">
                    {'PRÉREQUIS TLS 1.3 VALIDÉ' if crit_count == 0 else 'ACTION REQUISE SUR TLS / ASYMÉTRIQUE'}
                </div>
                <p style="font-size:12px;color:var(--muted);">L'ANSSI recommande l'hybridation systématique associant un algorithme classique (X25519) à un KEM post-quantique (ML-KEM-768) dès 2026.</p>
            </div>
            <div class="card">
                <div class="card-title">Directives UE NIS 2 &amp; DORA (Art. 21)</div>
                <div style="font-weight:700;color:#10B981;margin-bottom:6px;">INVENTAIRE CBOM GÉNÉRÉ</div>
                <p style="font-size:12px;color:var(--muted);">Exigence de cartographie des actifs cryptographiques (Cryptography Bill of Materials) et politique de crypto-agilité documentée.</p>
            </div>
        </div>

        <div class="section-title">2. Inventaire Détaillé des Actifs Cryptographiques Vulnérables ({total} alertes)</div>
        <table>
            <thead>
                <tr>
                    <th style="width:22%;">Fichier / Endpoint</th>
                    <th style="width:14%;">Source</th>
                    <th style="width:22%;">Algorithme Détecté</th>
                    <th style="width:12%;">Risque PQC</th>
                    <th style="width:30%;">Plan de Remédiation</th>
                </tr>
            </thead>
            <tbody>
                {"".join(rows_html)}
            </tbody>
        </table>

        <div class="cta-box">
            <div>
                <div style="font-weight:700;font-size:15px;color:#fff;">🚀 Automatisez la remédiation Post-Quantique avec Shorless SaaS</div>
                <div style="font-size:12px;color:#D1FAE5;margin-top:4px;">
                    Lancez <code>shorless . --fix</code> en local ou activez l'agent Auto-PR sur GitHub / GitLab pour corriger vos configurations TLS, dépendances SCA &amp; IaC automatiquement.
                </div>
            </div>
            <a href="https://shorless.io" target="_blank" style="background:#10B981;color:#06080D;text-decoration:none;padding:10px 16px;border-radius:8px;font-weight:700;font-size:12px;white-space:nowrap;">
                Essai SaaS Gratuit →
            </a>
        </div>

        <div class="footer">
            Généré par Shorless PQC &amp; CBOM Scanner v{SCANNER_VERSION} (Open Source Apache 2.0) • https://shorless.io
        </div>
    </div>
</body>
</html>"""

    Path(output_path).write_text(html_content, encoding="utf-8")


def apply_auto_remediation(target_path: Path, dry_run: bool = False) -> list:
    """
    Corrige automatiquement les configurations IaC, le code Backend et les manifestes SCA (requirements.txt)
    pour activer TLS 1.3, X25519MLKEM768 et les versions de bibliothèques compatibles PQC.
    """
    patched_files = []

    # 1. Auto-remédiation Nginx (*.conf)
    for conf_file in target_path.rglob("*.conf"):
        orig = conf_file.read_text(encoding="utf-8", errors="ignore")
        updated = orig
        updated = re.sub(
            r"ssl_protocols\s+[^;]*TLSv1\.[012][^;]*;",
            "ssl_protocols TLSv1.3;",
            updated
        )
        if "ssl_ecdh_curve" in updated and "MLKEM" not in updated.upper():
            updated = re.sub(
                r"ssl_ecdh_curve\s+[^;]+;",
                "ssl_ecdh_curve X25519MLKEM768:X25519:secp384r1;",
                updated
            )
        elif "ssl_protocols" in updated and "ssl_ecdh_curve" not in updated:
            updated = updated.replace(
                "ssl_protocols TLSv1.3;",
                "ssl_protocols TLSv1.3;\n    ssl_ecdh_curve X25519MLKEM768:X25519:secp384r1;"
            )
        if updated != orig:
            if not dry_run:
                conf_file.write_text(updated, encoding="utf-8")
            patched_files.append((str(conf_file), "Nginx : TLSv1.3 + Courbe hybride X25519MLKEM768"))

    # 2. Auto-remédiation Dockerfile
    for item in target_path.rglob("*"):
        if item.is_file() and (
            item.name == "Dockerfile"
            or item.name.startswith("Dockerfile.")
            or item.name.lower().endswith(".dockerfile")
        ):
            orig = item.read_text(encoding="utf-8", errors="ignore")
            updated = orig
            updated = re.sub(r"-slim-(buster|stretch|bullseye)", "-slim-bookworm", updated)
            updated = re.sub(r"debian:(buster|stretch|bullseye)", "debian:bookworm", updated)
            updated = re.sub(r"ubuntu:(18\.04|20\.04)", "ubuntu:24.04", updated)
            updated = re.sub(r"openssl=1\.1\.[0-9a-zA-Z.-]+", "openssl", updated)
            if updated != orig:
                if not dry_run:
                    item.write_text(updated, encoding="utf-8")
                patched_files.append((str(item), "Dockerfile : Migration OS & OpenSSL 3.x compatible PQC"))

    # 3. Auto-remédiation YAML (Traefik & Kubernetes Ingress)
    for yaml_file in list(target_path.rglob("*.yml")) + list(target_path.rglob("*.yaml")):
        if ".github" in yaml_file.parts or yaml_file.name == "action.yml":
            continue
        orig = yaml_file.read_text(encoding="utf-8", errors="ignore")
        updated = orig
        updated = re.sub(r"minVersion:\s*VersionTLS1[012]", "minVersion: VersionTLS13", updated)
        updated = re.sub(r"-\s*CurveP384", "- X25519MLKEM768\n        - X25519", updated)
        updated = re.sub(
            r'(nginx\.ingress\.kubernetes\.io/ssl-protocols:\s*)"[^"]*TLSv1\.[012][^"]*"',
            r'\1"TLSv1.3"',
            updated
        )
        updated = re.sub(r"tls_minimum_protocol_version:\s*TLSv1_[012]", "tls_minimum_protocol_version: TLSv1_3", updated)
        updated = re.sub(r"minProtocolVersion:\s*TLSV1_[012]", "minProtocolVersion: TLSV1_3", updated)
        if updated != orig:
            if not dry_run:
                yaml_file.write_text(updated, encoding="utf-8")
            patched_files.append((str(yaml_file), "YAML IaC (Traefik/K8s) : Activation TLS 1.3 & X25519MLKEM768"))

    # 4. Auto-remédiation Terraform (*.tf)
    for tf_file in target_path.rglob("*.tf"):
        orig = tf_file.read_text(encoding="utf-8", errors="ignore")
        updated = re.sub(
            r'ssl_policy\s*=\s*"ELBSecurityPolicy-(2016-08|TLS-1-2-[^"]+)"',
            'ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"',
            orig
        )
        if updated != orig:
            if not dry_run:
                tf_file.write_text(updated, encoding="utf-8")
            patched_files.append((str(tf_file), "Terraform : Politique Load Balancer migrée vers TLS 1.3"))

    # 5. Auto-remédiation SCA Multi-Langages (requirements.txt, go.mod, pom.xml, *.csproj)
    for req_file in target_path.rglob("requirements.txt"):
        orig = req_file.read_text(encoding="utf-8", errors="ignore")
        updated = orig
        updated = re.sub(r"^cryptography\s*(?:==|<=|~=|>=|<)\s*[0-9][0-9a-zA-Z._-]*", "cryptography>=42.0.0", updated, flags=re.MULTILINE)
        updated = re.sub(r"^pyOpenSSL\s*(?:==|<=|~=|>=|<)\s*[0-9][0-9a-zA-Z._-]*", "pyOpenSSL>=24.0.0", updated, flags=re.MULTILINE | re.IGNORECASE)
        updated = re.sub(r"^paramiko\s*(?:==|<=|~=|>=|<)\s*[0-9][0-9a-zA-Z._-]*", "paramiko>=3.4.0", updated, flags=re.MULTILINE)
        if updated != orig:
            if not dry_run:
                req_file.write_text(updated, encoding="utf-8")
            patched_files.append((str(req_file), "SCA Python (requirements.txt) : Mise à niveau cryptography>=42.0.0 / OpenSSL 3.2+"))

    for gomod_file in target_path.rglob("go.mod"):
        orig = gomod_file.read_text(encoding="utf-8", errors="ignore")
        updated = re.sub(r"^go\s+1\.(1[0-9]|2[0-3])(\.[0-9]+)?", "go 1.24.0", orig, flags=re.MULTILINE)
        if updated != orig:
            if not dry_run:
                gomod_file.write_text(updated, encoding="utf-8")
            patched_files.append((str(gomod_file), "SCA Go (go.mod) : Mise à niveau vers Go 1.24.0 (support crypto/mlkem natif)"))

    for pom_file in target_path.rglob("pom.xml"):
        orig = pom_file.read_text(encoding="utf-8", errors="ignore")
        updated = orig.replace("bcprov-jdk15on", "bcprov-jdk18on").replace("bcprov-jdk15to18", "bcprov-jdk18on")
        if updated != orig:
            if not dry_run:
                pom_file.write_text(updated, encoding="utf-8")
            patched_files.append((str(pom_file), "SCA Java (pom.xml) : Migration vers BouncyCastle bcprov-jdk18on (FIPS 203/204)"))

    for csproj_file in target_path.rglob("*.csproj"):
        orig = csproj_file.read_text(encoding="utf-8", errors="ignore")
        updated = re.sub(r'Include="BouncyCastle"', 'Include="BouncyCastle.Cryptography"', orig)
        if updated != orig:
            if not dry_run:
                csproj_file.write_text(updated, encoding="utf-8")
            patched_files.append((str(csproj_file), "SCA C# (.csproj) : Migration vers BouncyCastle.Cryptography PQC"))

    # 6. Auto-remédiation Code Source Multi-Langages (.py, .java, .go, .js, .ts, .cs)
    for py_file in target_path.rglob("*.py"):
        if py_file.name in ("shorless_scanner.py", "pqc_scanner.py", "release_shorless.py", "cron_generate_article.py"):
            continue
        orig = py_file.read_text(encoding="utf-8", errors="ignore")
        updated = orig
        updated = re.sub(r"\bhashes\.SHA1\(\)", "hashes.SHA256()", updated)
        updated = re.sub(r"\bhashes\.MD5\(\)", "hashes.SHA256()", updated)
        updated = re.sub(r"\bec\.SECP256R1\(\)", "ec.SECP384R1()  # [Shorless Auto-Fix: Courbe durcie en attente d'hybridation ML-KEM]", updated)
        if "rsa.generate_private_key" in updated and "# [SHORLESS-PQC]" not in updated:
            updated = updated.replace(
                "rsa.generate_private_key(",
                "# [SHORLESS-PQC] TODO: Migrer vers oqs.KeyEncapsulation('ML-KEM-768')\nprivate_key = rsa.generate_private_key("
            ).replace("private_key = # [SHORLESS-PQC]", "# [SHORLESS-PQC]")
        if updated != orig:
            if not dry_run:
                py_file.write_text(updated, encoding="utf-8")
            patched_files.append((str(py_file), "Python : Durcissement cryptographique (SHA-256 / P-384) & Annotation ML-KEM"))

    for java_file in target_path.rglob("*.java"):
        orig = java_file.read_text(encoding="utf-8", errors="ignore")
        updated = orig
        updated = re.sub(r'MessageDigest\.getInstance\(\s*"(SHA-1|SHA1|MD5)"\s*\)', 'MessageDigest.getInstance("SHA-256")', updated)
        if 'KeyPairGenerator.getInstance("RSA")' in updated and "/* [SHORLESS-PQC] */" not in updated:
            updated = updated.replace(
                'KeyPairGenerator.getInstance("RSA")',
                'KeyPairGenerator.getInstance("RSA") /* [SHORLESS-PQC] Migrer vers BouncyCastle ML-KEM-768 / ML-DSA */'
            )
        if updated != orig:
            if not dry_run:
                java_file.write_text(updated, encoding="utf-8")
            patched_files.append((str(java_file), "Java (JCA) : Migration SHA-256 & Annotation BouncyCastle PQC"))

    for go_file in target_path.rglob("*.go"):
        orig = go_file.read_text(encoding="utf-8", errors="ignore")
        updated = orig
        updated = updated.replace("sha1.New()", "sha256.New()").replace("md5.New()", "sha256.New()")
        if "rsa.GenerateKey(" in updated and "/* [SHORLESS-PQC] */" not in updated:
            updated = updated.replace(
                "rsa.GenerateKey(",
                "/* [SHORLESS-PQC: Migrer vers crypto/mlkem (Go 1.24+)] */ rsa.GenerateKey("
            )
        if updated != orig:
            if not dry_run:
                go_file.write_text(updated, encoding="utf-8")
            patched_files.append((str(go_file), "Go (Stdlib) : Remplacement SHA-256 & Annotation crypto/mlkem"))

    for js_file in list(target_path.rglob("*.js")) + list(target_path.rglob("*.ts")):
        if "node_modules" in js_file.parts or "dist" in js_file.parts:
            continue
        orig = js_file.read_text(encoding="utf-8", errors="ignore")
        updated = orig
        updated = re.sub(r"createHash\(\s*['\"](md5|sha1)['\"]\s*\)", "createHash('sha256')", updated)
        updated = re.sub(r"namedCurve:\s*['\"]prime256v1['\"]", "namedCurve: 'secp384r1' /* [SHORLESS-PQC: Hybrider avec ML-KEM] */", updated)
        if "generateKeyPairSync('rsa'" in updated and "/* [SHORLESS-PQC] */" not in updated:
            updated = updated.replace(
                "generateKeyPairSync('rsa'",
                "/* [SHORLESS-PQC] */ generateKeyPairSync('rsa'"
            )
        if updated != orig:
            if not dry_run:
                js_file.write_text(updated, encoding="utf-8")
            patched_files.append((str(js_file), f"Node.js / TS ({js_file.suffix}) : Migration SHA-256, secp384r1 & Annotation PQC"))

    for cs_file in target_path.rglob("*.cs"):
        orig = cs_file.read_text(encoding="utf-8", errors="ignore")
        updated = orig
        updated = re.sub(r"\b(SHA1|MD5)\.Create\(\)", "SHA256.Create()", updated)
        updated = re.sub(r"\bRSA\.Create\(\s*2048\s*\)", "RSA.Create(4096) /* [SHORLESS-PQC: Migrer vers MLKem (.NET 9+)] */", updated)
        if updated != orig:
            if not dry_run:
                cs_file.write_text(updated, encoding="utf-8")
            patched_files.append((str(cs_file), "C# (.NET) : Migration SHA256.Create(), durcissement RSA-4096 & Annotation MLKem"))

    for ssh_file in list(target_path.rglob("sshd_config")) + list(target_path.rglob("ssh_config")):
        orig = ssh_file.read_text(encoding="utf-8", errors="ignore")
        if "mlkem768x25519" not in orig.lower() and "sntrup761x25519" not in orig.lower():
            updated = orig.rstrip() + "\n# [Shorless PQC Auto-Fix] Hybrid Post-Quantum SSH Key Exchange\nKexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256\n"
            if not dry_run:
                ssh_file.write_text(updated, encoding="utf-8")
            patched_files.append((str(ssh_file), "OpenSSH : Activation KexAlgorithms hybride mlkem768x25519-sha256"))

    return patched_files


CLI_LANG = os.environ.get("SHORLESS_LANG", "fr").lower()

def tr_cli(fr_text: str, en_text: str) -> str:
    return en_text if CLI_LANG == "en" else fr_text

def translate_finding_to_en(f: dict) -> dict:
    if CLI_LANG != "en":
        return f
    out = dict(f)
    risk_map = {"CRITIQUE": "CRITICAL", "ÉLEVÉ": "HIGH", "MOYEN": "MEDIUM", "FAIBLE": "LOW"}
    out["risk"] = risk_map.get(out.get("risk", ""), out.get("risk", ""))
    rem = out.get("remediation", "")
    rem = rem.replace("Migrer vers une approche hybride", "Migrate to a hybrid approach")
    rem = rem.replace("Remplacer par", "Replace with")
    rem = rem.replace("Mettre à niveau vers", "Upgrade to")
    rem = rem.replace("Activer", "Enable")
    rem = rem.replace("Forcer", "Enforce")
    rem = rem.replace("Utiliser", "Use")
    out["remediation"] = rem
    return out

def verify_saas_api_key(api_key: str, findings_count: int, critical_count: int, auto_pr: bool, project_name: str = "default", findings: list = None) -> dict:
    """Vérifie la validité de la clé d'API SaaS auprès de shorless.io et enregistre la télémétrie + le détail CBOM par projet."""
    clean_key = (api_key or "").strip()
    if not re.match(r"^shorless_(trial|pro)_[a-fA-F0-9]{16,32}$", clean_key):
        return {
            "valid": False,
            "message": "Format de clé invalide (attendu: shorless_trial_xxxxxxxxxxxxxxxx). Obtenez une clé sur https://shorless.io"
        }

    compact_findings = []
    for f in (findings or [])[:100]:
        compact_findings.append({
            "file": str(f.get("file", "")),
            "line": int(f.get("line", 1)),
            "type": str(f.get("type", "")),
            "algo": str(f.get("algo", "")),
            "risk": str(f.get("risk", "MOYEN")),
            "remediation": str(f.get("remediation", ""))
        })

    payload = json.dumps({
        "api_key": clean_key,
        "project": project_name,
        "findings_count": findings_count,
        "critical_count": critical_count,
        "auto_pr": auto_pr,
        "version": SCANNER_VERSION,
        "lang": CLI_LANG,
        "findings": compact_findings
    }).encode("utf-8")

    req = Request(
        "https://shorless.io/api_verify.php",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": f"Shorless-CLI/{SCANNER_VERSION}"
        },
        method="POST"
    )
    try:
        with urlopen(req, timeout=6) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return {
            "valid": True,
            "plan": "TRIAL (Validation Locale)",
            "days_remaining": 14,
            "message": "Clé API validée localement (mode CI/CD)."
        }


def create_automated_pull_request(patched_files: list, findings: list, base_branch: str = "main") -> str:
    """Crée une branche Git, commit les fichiers corrigés par --fix et ouvre une Pull Request GitHub."""
    if not patched_files:
        return ""

    branch_name = f"shorless-pqc-fix-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    pr_title = "🔒 fix(pqc): Migration Post-Quantique TLS 1.3, SCA & Hybride ML-KEM (Shorless Auto-PR)"

    patched_bullets = "\n".join([f"- `{fpath}` : {desc}" for fpath, desc in patched_files])
    pr_body = (
        "## ⚡ Remédiation Automatique Post-Quantique (Shorless SaaS)\n\n"
        "Cette Pull Request a été générée automatiquement par **Shorless PQC Scanner** (`--fix --auto-pr`) "
        "pour mettre en conformité votre code, vos dépendances SCA et vos configurations d'infrastructure avec les recommandations **ANSSI** "
        "et **NIST FIPS 203 (`X25519MLKEM768`)**.\n\n"
        f"### 🛠️ Fichiers corrigés ({len(patched_files)})\n"
        f"{patched_bullets}\n\n"
        f"### 📊 Résumé de l'audit CBOM CycloneDX 1.6\n"
        f"- **Alertes totales détectées avant patch :** {len(findings)}\n"
        "- **Standard d'inventaire :** OWASP CycloneDX 1.6 & OASIS SARIF 2.1.0\n"
    )
    try:
        subprocess.run(["git", "config", "user.name", "Shorless PQC Bot"], check=False, capture_output=True)
        subprocess.run(["git", "config", "user.email", "bot@shorless.io"], check=False, capture_output=True)
        subprocess.run(["git", "checkout", "-B", branch_name], check=True, capture_output=True, text=True)
        for fpath, _ in patched_files:
            subprocess.run(["git", "add", "-f", fpath], check=True, capture_output=True, text=True)
        diff_cached = subprocess.run(["git", "diff", "--cached", "--quiet"], check=False)
        if diff_cached.returncode != 0:
            subprocess.run(["git", "commit", "-m", pr_title], check=True, capture_output=True, text=True)
        subprocess.run(["git", "push", "-f", "-u", "origin", branch_name], check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        err_detail = (e.stderr or e.stdout or str(e)).strip()
        console.print(f"[yellow]⚠️ Impossible de créer/pousser la branche Git ({branch_name}) : {err_detail}[/yellow]")
        return ""

    rem = subprocess.run(["git", "config", "--get", "remote.origin.url"], capture_output=True, text=True)
    remote_url = (rem.stdout or "").strip()

    # 1. Support GitHub (CLI `gh` ou API REST GitHub)
    gh_bin = shutil.which("gh")
    if gh_bin and ("github.com" in remote_url or os.environ.get("GITHUB_REPOSITORY")):
        proc = subprocess.run(
            [gh_bin, "pr", "create", "--title", pr_title, "--body", pr_body, "--base", base_branch, "--head", branch_name],
            capture_output=True, text=True
        )
        if proc.returncode == 0:
            return proc.stdout.strip()

    github_token = os.environ.get("GITHUB_TOKEN", "").strip()
    gh_slug = os.environ.get("GITHUB_REPOSITORY", "").strip()
    if not gh_slug:
        m_gh = re.search(r"github\.com[:/]([^/]+/[^/.]+?)(?:\.git)?$", remote_url)
        if m_gh:
            gh_slug = m_gh.group(1)

    if github_token and gh_slug:
        api_url = f"https://api.github.com/repos/{gh_slug}/pulls"
        req = Request(
            api_url,
            data=json.dumps({
                "title": pr_title,
                "body": pr_body,
                "head": branch_name,
                "base": base_branch
            }).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {github_token}",
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "User-Agent": "Shorless-AutoPR"
            },
            method="POST"
        )
        try:
            with urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("html_url", branch_name)
        except Exception as e:
            console.print(f"[yellow]⚠️ Branche poussée ({branch_name}), mais erreur API GitHub PR : {e}[/yellow]")

    # 2. Support GitLab (CLI `glab` ou API REST GitLab v4)
    glab_bin = shutil.which("glab")
    if glab_bin and ("gitlab" in remote_url.lower() or os.environ.get("CI_PROJECT_ID")):
        proc = subprocess.run(
            [glab_bin, "mr", "create", "--title", pr_title, "--description", pr_body, "--target-branch", base_branch, "--source-branch", branch_name, "--yes"],
            capture_output=True, text=True
        )
        if proc.returncode == 0:
            return proc.stdout.strip()

    gitlab_token = (os.environ.get("GITLAB_TOKEN") or os.environ.get("CI_JOB_TOKEN") or "").strip()
    gitlab_api = os.environ.get("CI_API_V4_URL", "https://gitlab.com/api/v4").rstrip("/")
    gitlab_proj = os.environ.get("CI_PROJECT_ID", "").strip()
    if not gitlab_proj:
        m_gl = re.search(r"gitlab\.[^/:]+[:/](.+?)(?:\.git)?$", remote_url)
        if m_gl:
            from urllib.parse import quote
            gitlab_proj = quote(m_gl.group(1), safe="")

    if gitlab_token and gitlab_proj:
        gl_url = f"{gitlab_api}/projects/{gitlab_proj}/merge_requests"
        headers_gl = {"Content-Type": "application/json", "User-Agent": "Shorless-AutoPR"}
        if os.environ.get("GITLAB_TOKEN"):
            headers_gl["PRIVATE-TOKEN"] = gitlab_token
        else:
            headers_gl["JOB-TOKEN"] = gitlab_token
        req = Request(
            gl_url,
            data=json.dumps({
                "source_branch": branch_name,
                "target_branch": base_branch,
                "title": pr_title,
                "description": pr_body
            }).encode("utf-8"),
            headers=headers_gl,
            method="POST"
        )
        try:
            with urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("web_url", branch_name)
        except Exception as e:
            console.print(f"[yellow]⚠️ Branche poussée ({branch_name}), mais erreur API GitLab MR : {e}[/yellow]")

    # 3. Support Bitbucket Cloud (API REST 2.0 via BITBUCKET_TOKEN)
    bb_token = (os.environ.get("BITBUCKET_TOKEN") or os.environ.get("BITBUCKET_STEP_OAUTH_ACCESS_TOKEN") or "").strip()
    bb_slug = os.environ.get("BITBUCKET_REPO_FULL_NAME", "").strip()
    if not bb_slug:
        m_bb = re.search(r"bitbucket\.org[:/]([^/]+/[^/.]+?)(?:\.git)?$", remote_url)
        if m_bb:
            bb_slug = m_bb.group(1)

    if bb_token and bb_slug:
        bb_url = f"https://api.bitbucket.org/2.0/repositories/{bb_slug}/pullrequests"
        req = Request(
            bb_url,
            data=json.dumps({
                "title": pr_title,
                "description": pr_body,
                "source": {"branch": {"name": branch_name}},
                "destination": {"branch": {"name": base_branch}}
            }).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {bb_token}",
                "Content-Type": "application/json",
                "User-Agent": "Shorless-AutoPR"
            },
            method="POST"
        )
        try:
            with urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("links", {}).get("html", {}).get("href", branch_name)
        except Exception as e:
            console.print(f"[yellow]⚠️ Branche poussée ({branch_name}), mais erreur API Bitbucket PR : {e}[/yellow]")

    return f"Branche '{branch_name}' poussée sur origin (ouvrez la PR/MR sur votre forge Git)."


@app.command()
def scan(
    target_dir: str = typer.Argument(".", help="Dossier du projet à scanner"),
    cbom_out: str = typer.Option("cbom.json", "--cbom", help="Fichier de sortie CycloneDX 1.6 CBOM"),
    sarif_out: str = typer.Option(None, "--sarif", help="Génère un rapport OASIS SARIF 2.1.0 pour GitHub Code Scanning (ex: shorless.sarif)"),
    report_html: str = typer.Option(None, "--report-html", help="Génère un rapport d'audit exécutif HTML/PDF (ex: pqc-report.html)"),
    check_tls: str = typer.Option(None, "--check-tls", help="URL ou domaine:port à inspecter en direct (ex: https://shorless.io)"),
    simulate_mtu: bool = typer.Option(False, "--simulate-mtu", "--simulate-mtu-fragmentation", help="Simule l'impact MTU (1500 octets) et la fragmentation TCP/TLS des clés ML-KEM-768 et signatures ML-DSA"),
    fix: bool = typer.Option(False, "--fix", help="Corrige automatiquement le code, les dépendances SCA et les fichiers IaC"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simule les corrections --fix sans modifier les fichiers sur le disque"),
    api_key: str = typer.Option(None, "--api-key", envvar="SHORLESS_API_KEY", help="Clé d'API Shorless SaaS (active la télémétrie et --auto-pr)"),
    project: str = typer.Option(None, "--project", help="Nom du projet ou dépôt Git pour segmenter la télémétrie dans le Dashboard SaaS"),
    webhook_url: str = typer.Option(None, "--webhook-url", envvar="SHORLESS_WEBHOOK_URL", help="URL de Webhook Slack / Microsoft Teams / Discord pour recevoir une alerte de score PQC"),
    auto_pr: bool = typer.Option(False, "--auto-pr", help="Crée une branche Git et ouvre automatiquement une Pull Request avec les correctifs --fix (requiert --api-key)"),
    pr_base: str = typer.Option("main", "--pr-base", help="Branche cible pour la Pull Request automatique (--auto-pr)"),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Affiche le détail des fichiers analysés / Display detailed inventory of scanned files."
    ),
    lang: str = typer.Option(
        "fr",
        "--lang", "-l",
        envvar="SHORLESS_LANG",
        help="Langue d'affichage du terminal et des rapports : 'fr' ou 'en' / Output language: 'fr' or 'en'."
    ),
    fail_on_critical: bool = typer.Option(False, "--ci", help="Renvoie un code d'erreur (1) pour bloquer la CI/CD / Exit code 1 on critical findings")
):
    """Lance un audit Post-Quantique complet (Code 6 langages, 5 IaC, SCA dépendances, Certificats X.509 & TLS Live)."""
    global CLI_LANG
    CLI_LANG = "en" if str(lang).lower().startswith("en") else "fr"
    banner_txt = tr_cli(
        f"⚡ Shorless PQC-Scanner v{SCANNER_VERSION} — Audit DevSecOps Post-Quantique, SCA & SARIF",
        f"⚡ Shorless PQC-Scanner v{SCANNER_VERSION} — Post-Quantum DevSecOps, SCA & SARIF Scanner"
    )
    console.print(Panel.fit(f"[bold cyan]{banner_txt}[/bold cyan]"))

    path = Path(target_dir)
    all_findings = []
    ignore_patterns = load_shorlessignore(path) if path.exists() else []
    project_name = detect_project_name(path, project)

    if path.exists():
        if verbose:
            v_table = Table(
                title=f"🔍 Inventaire Détaillé des Fichiers Analysés (--verbose) • Projet : {project_name}",
                show_header=True,
                header_style="bold cyan"
            )
            v_table.add_column("Fichier", style="white", no_wrap=False)
            v_table.add_column("Type Détecté", style="green")
            v_table.add_column("Probabilité Crypto", justify="right")
            v_table.add_column("Indice d'Exposition", justify="center")

            scanned_files_meta = []
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build")]
                for fname in sorted(files):
                    fpath = Path(root) / fname
                    if is_ignored_path(fpath, path, ignore_patterns):
                        continue
                    ftype, prob, level = detect_file_type_and_crypto_prob(fpath)
                    if ftype != "Ignoré / Non supporté":
                        scanned_files_meta.append((fpath, ftype, prob, level))

            for fpath, ftype, prob, level in scanned_files_meta:
                rel_path = os.path.relpath(fpath, path)
                if prob >= 70:
                    prob_str = f"[bold red]{prob} %[/bold red]"
                    badge = "[bold red]🔥 ÉLEVÉE[/bold red]"
                elif prob >= 40:
                    prob_str = f"[bold yellow]{prob} %[/bold yellow]"
                    badge = "[yellow]⚠️ MOYENNE[/yellow]"
                else:
                    prob_str = f"[dim]{prob} %[/dim]"
                    badge = "[dim]FAIBLE[/dim]"

                v_table.add_row(str(rel_path), ftype, prob_str, badge)

            console.print(v_table)
            console.print(f"[dim]ℹ️  {len(scanned_files_meta)} fichier(s) éligible(s) inspecté(s) dans '{path}'.[/dim]\n")

        # 1. Scan des fichiers Python (.py)
        for py_file in path.rglob("*.py"):
            if py_file.name in ("shorless_scanner.py", "pqc_scanner.py", "release_shorless.py", "cron_generate_article.py"):
                continue
            if is_ignored_path(py_file, path, ignore_patterns):
                continue
            try:
                raw_text = py_file.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(raw_text)
                visitor = PythonCryptoVisitor(str(py_file), raw_text.splitlines())
                visitor.visit(tree)
                all_findings.extend(visitor.findings)
            except SyntaxError:
                pass

        # 1b. Scan des fichiers Multi-Langages Backend (.java, .go, .js, .ts, .cs)
        for ext in ("*.java", "*.go", "*.js", "*.ts", "*.cs"):
            for src_file in path.rglob(ext):
                if "node_modules" in src_file.parts or "vendor" in src_file.parts or "dist" in src_file.parts:
                    continue
                if is_ignored_path(src_file, path, ignore_patterns):
                    continue
                all_findings.extend(scan_multilang_source(src_file))

        # 2. Scan des configurations Nginx (.conf)
        for conf_file in path.rglob("*.conf"):
            if not is_ignored_path(conf_file, path, ignore_patterns):
                all_findings.extend(scan_nginx_config(conf_file))

        # 3. Scan des Dockerfiles, manifestes SCA et certificats/clés statiques
        for item in path.rglob("*"):
            if not item.is_file() or is_ignored_path(item, path, ignore_patterns):
                continue
            if "node_modules" in item.parts or ".git" in item.parts or "dist" in item.parts:
                continue

            low_name = item.name.lower()
            low_suffix = item.suffix.lower()
            if item.name == "Dockerfile" or item.name.startswith("Dockerfile.") or low_name.endswith(".dockerfile"):
                all_findings.extend(scan_dockerfile(item))
            elif low_name in SCA_MANIFEST_NAMES or low_suffix in (".csproj", ".props", ".gradle", ".kts"):
                all_findings.extend(scan_sca_dependencies(item))
            elif low_suffix in (".pem", ".crt", ".cer", ".key", ".pub"):
                all_findings.extend(scan_static_cert_or_key(item))
            elif low_name in ("sshd_config", "ssh_config", "haproxy.cfg", "caddyfile"):
                all_findings.extend(scan_ssh_and_proxy_configs(item))

        # 3b. Scan des configurations YAML (Traefik & Kubernetes Ingress)
        for yaml_file in list(path.rglob("*.yml")) + list(path.rglob("*.yaml")):
            if ".github" in yaml_file.parts or yaml_file.name == "action.yml":
                continue
            if not is_ignored_path(yaml_file, path, ignore_patterns):
                all_findings.extend(scan_yaml_iac(yaml_file))

        # 3c. Scan des fichiers Terraform (.tf)
        for tf_file in path.rglob("*.tf"):
            if not is_ignored_path(tf_file, path, ignore_patterns):
                all_findings.extend(scan_terraform_file(tf_file))

    # 4. Scan TLS en direct si --check-tls est fourni + Simulateur MTU si --simulate-mtu est actif
    if check_tls:
        all_findings.extend(scan_live_tls_endpoint(check_tls))
    if simulate_mtu:
        simulate_mtu_impact(check_tls, all_findings)

    # 5. Affichage des résultats dans le terminal
    if not all_findings:
        console.print(tr_cli(
            "[bold green]✅ Aucune vulnérabilité post-quantique détectée ![/bold green]",
            "[bold green]✅ No post-quantum vulnerabilities detected![/bold green]"
        ))
        if sarif_out:
            generate_sarif_report([], sarif_out)
        raise typer.Exit(0)

    table = Table(title=tr_cli(
        f"Inventaire Cryptographique & Risques Quantiques ({len(all_findings)} alertes)",
        f"Cryptographic Inventory & Quantum Risks ({len(all_findings)} findings)"
    ))
    table.add_column(tr_cli("Fichier / Endpoint", "File / Endpoint"), style="cyan")
    table.add_column("Source", style="magenta")
    table.add_column(tr_cli("Actif / Algorithme détecté", "Detected Crypto Asset"), style="white")
    table.add_column(tr_cli("Risque PQC", "PQC Risk"), style="bold")
    table.add_column(tr_cli("Plan de remédiation (Auto-PR disponible en SaaS)", "Remediation Plan (SaaS Auto-PR Ready)"), style="green")

    critical_count = 0
    for f in all_findings:
        if f["risk"] == "CRITIQUE":
            critical_count += 1
        df = translate_finding_to_en(f)
        risk_color = "red" if f["risk"] == "CRITIQUE" else "yellow"
        table.add_row(
            f"{df['file']}:{df['line']}",
            df["type"],
            df["algo"],
            f"[{risk_color}]{df['risk']}[/{risk_color}]",
            df["remediation"]
        )

    console.print(table)

    # 6. Export du CBOM CycloneDX 1.6 et du rapport SARIF 2.1.0
    generate_cyclonedx_cbom(all_findings, cbom_out)
    console.print(tr_cli(f"\n📄 [bold]CBOM CycloneDX 1.6 généré avec succès :[/bold] [underline]{cbom_out}[/underline]", f"\n📄 [bold]CycloneDX 1.6 CBOM successfully generated:[/bold] [underline]{cbom_out}[/underline]"))

    if sarif_out:
        generate_sarif_report(all_findings, sarif_out)
        console.print(tr_cli(f"🛡️  [bold]Rapport OASIS SARIF 2.1.0 généré (GitHub Code Scanning) :[/bold] [underline]{sarif_out}[/underline]", f"🛡️  [bold]OASIS SARIF 2.1.0 report generated (GitHub Code Scanning):[/bold] [underline]{sarif_out}[/underline]"))

    # 6a. Vérification de la clé SaaS (--api-key) si fournie ou si --auto-pr est demandé
    if auto_pr and not api_key:
        console.print(
            "\n[bold red]🔒 L'option --auto-pr est une fonctionnalité Shorless SaaS.[/bold red]\n"
            "[yellow]👉 Obtenez une clé d'essai (500 crédits offerts) sur https://shorless.io puis ajoutez :[/yellow] "
            "[bold white]--api-key shorless_trial_...[/bold white]"
        )
        raise typer.Exit(code=1)

    # 6b. Exécution de l'Auto-Remédiation (--fix, --dry-run ou --auto-pr)
    patched = []
    if fix or dry_run or auto_pr:
        mode_label = "SIMULATION (--dry-run)" if dry_run else "APPLICATION DES CORRECTIFS (--fix)"
        console.print(f"\n[bold cyan]🛠️  Auto-Remédiation Post-Quantique — {mode_label}[/bold cyan]")
        patched = apply_auto_remediation(path, dry_run=dry_run)
        if patched:
            for fpath, action_desc in patched:
                prefix = "[yellow][DRY-RUN][/yellow]" if dry_run else "[bold green][CORRIGÉ][/bold green]"
                console.print(f"  {prefix} [white]{fpath}[/white] → [green]{action_desc}[/green]")
            if not dry_run:
                console.print("\n[bold green]✨ Fichiers mis à jour localement ![/bold green]")
        else:
            console.print("[yellow]ℹ️  Aucun fichier automatiquement corrigeable trouvé.[/yellow]")

    patched_paths = {str(p[0]) for p in patched} if ((fix or auto_pr) and not dry_run) else set()
    residual_findings_list = [f for f in all_findings if str(f.get("file")) not in patched_paths] if patched_paths else all_findings

    remediated_count = len(patched) if (fix or auto_pr) and not dry_run else 0
    rem_findings = max(0, len(all_findings) - remediated_count)
    rem_critical = max(0, critical_count - remediated_count)
    final_score = compute_pqc_score(rem_findings, rem_critical)

    # Envoi de la télémétrie SaaS + détail CBOM (avec filtrage des fichiers corrigés si --fix est actif sans --dry-run)
    if api_key:
        auth_res = verify_saas_api_key(api_key, rem_findings, rem_critical, auto_pr, project_name=project_name, findings=residual_findings_list)
        if not auth_res.get("valid"):
            console.print(f"\n[bold red]❌ Erreur d'authentification SaaS : {auth_res.get('message')}[/bold red]")
            raise typer.Exit(code=1)
        console.print(f"\n[bold green]🔑 {auth_res.get('message')} • Projet : {project_name} • Score PQC : {final_score}/100[/bold green]")

    pr_url = ""
    if patched and not dry_run and auto_pr:
        console.print("[cyan]🚀 Création de la branche Git et ouverture de la Pull Request automatique...[/cyan]")
        pr_url = create_automated_pull_request(patched, all_findings, base_branch=pr_base)
        if pr_url:
            console.print(f"[bold green]✅ Pull Request Post-Quantique ouverte :[/bold green] [underline]{pr_url}[/underline]")

    # Notification Webhook Slack / Teams / Discord si configuré
    if webhook_url:
        sent = send_webhook_notification(webhook_url, project_name, final_score, rem_findings, rem_critical, pr_url)
        if sent:
            console.print("[bold green]🔔 Notification Webhook (Slack / Teams) envoyée avec succès.[/bold green]")
        else:
            console.print("[yellow]⚠️ Échec de l'envoi de la notification Webhook.[/yellow]")

    # 7. Génération du Rapport d'Audit Exécutif HTML/PDF si demandé
    if report_html:
        generate_executive_html_report(all_findings, report_html, target_dir)
        console.print(f"📊 [bold]Rapport Exécutif HTML/PDF généré :[/bold] [underline]{report_html}[/underline]")

    # 8. Mode bloqueur CI/CD (GitHub Actions / GitLab CI)
    if fail_on_critical and critical_count > 0:
        console.print(tr_cli(f"\n[bold red]❌ Pipeline CI bloquée : {critical_count} vulnérabilité(s) critique(s) face au risque quantique.[/bold red]", f"\n[bold red]❌ CI Pipeline blocked: {critical_count} critical quantum vulnerability(ies) found.[/bold red]"))
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
