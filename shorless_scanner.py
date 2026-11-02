#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
SHORLESS PQC & CBOM SCANNER (shorless_scanner.py)
================================================================================
Scanner DevSecOps Open Source (Apache 2.0) de préparation Post-Quantique :
1. Analyse statique AST Python (RSA, ECDSA P-256, SHA-1, MD5).
2. Inspection des configurations TLS Nginx (.conf) et courbes hybrides ML-KEM.
3. Inspection des Dockerfiles (Dockerfile, Dockerfile.*, *.dockerfile) et versions OpenSSL.
4. Inspection en direct des terminaisons TLS distantes (--check-tls https://...).
5. Génération native de l'inventaire CBOM au standard OWASP CycloneDX 1.6 (cbom.json).
================================================================================
"""

import os
from urllib.request import Request, urlopen
import ast
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

app = typer.Typer(help="Scanner DevSecOps de préparation Post-Quantique (PQC) & Générateur CBOM CycloneDX 1.6")
console = Console()

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
    ".conf": "Nginx Config",
    ".tf": "Terraform IaC",
    ".yml": "YAML (Traefik / K8s)",
    ".yaml": "YAML (Traefik / K8s)",
}

CRYPTO_HEURISTIC_KEYWORDS = (
    "rsa", "ecdsa", "secp", "prime256", "ed25519", "x25519", "mlkem", "kyber",
    "dilithium", "openssl", "ssl_", "tls", "cipher", "crypto", "private_key",
    "keypair", "sha1", "md5", "cert", "x509", "jwt", "keystore", "pem"
)


def detect_file_type_and_crypto_prob(filepath: Path) -> tuple[str, int, str]:
    """
    Détermine le type du fichier et estime la probabilité (0-95 %) qu'il contienne
    des références au chiffrement ou à la cryptographie (heuristique nom + contenu).
    """
    name_lower = filepath.name.lower()
    suffix_lower = filepath.suffix.lower()

    if filepath.name in ("shorless_scanner.py", "pqc_scanner.py", "release_shorless.py", "cron_generate_article.py") or filepath.name.endswith("_test.html") or filepath.name.endswith("_test.json"):
        return ("Ignoré / Non supporté", 0, "Faible")

    # 1. Identification du type de fichier
    if name_lower.startswith("dockerfile"):
        file_type = "Dockerfile (Container)"
        base_prob = 50
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
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.findings = []

    def visit_Call(self, node: ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id

        if func_name in PQC_RULES:
            rule = PQC_RULES[func_name]
            self.findings.append({
                "file": self.filepath,
                "line": node.lineno,
                "type": "Code Python (AST)",
                "detected": func_name,
                "algo": rule["algo"],
                "risk": rule["risk"],
                "remediation": rule["remediation"]
            })
        self.generic_visit(node)

def scan_multilang_source(filepath: Path) -> list:
    """Scanne les fichiers source Java (.java), Go (.go) et Node.js/TypeScript (.js, .ts) pour détecter les primitives vulnérables."""
    findings = []
    suffix = filepath.suffix.lower()
    content = filepath.read_text(encoding="utf-8", errors="ignore")
    lines = content.splitlines()

    for i, line in enumerate(lines, start=1):
        clean = line.strip()
        if not clean or clean.startswith("//") or clean.startswith("/*") or clean.startswith("*"):
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
                    "remediation": "Utiliser BouncyCastle PQC (bcprov-jdk18on) avec ML-KEM (Kyber) ou ML-DSA (Dilithium)."
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
        if clean_line.startswith("#"):
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
    """Scanne les Dockerfiles pour détecter les images ou versions d'OpenSSL incompatibles avec la PQC."""
    findings = []
    content = filepath.read_text(encoding="utf-8", errors="ignore")
    lines = content.splitlines()

    legacy_base_patterns = (
        "buster", "stretch", "bullseye", "ubuntu:18.04", "ubuntu:20.04",
        "alpine:3.12", "alpine:3.13", "alpine:3.14", "alpine:3.15", "alpine:3.16", "alpine:3.17", "alpine:3.18"
    )

    for i, line in enumerate(lines, start=1):
        clean_line = line.strip()
        if not clean_line or clean_line.startswith("#"):
            continue

        lower_line = clean_line.lower()

        # 1. Vérification de l'image de base (FROM)
        if lower_line.startswith("from "):
            if any(pat in lower_line for pat in legacy_base_patterns):
                findings.append({
                    "file": str(filepath),
                    "line": i,
                    "type": "Conteneur (Docker)",
                    "detected": clean_line,
                    "algo": "Image OS Legacy (OpenSSL < 3.2)",
                    "risk": "ÉLEVÉ",
                    "remediation": "Migrer vers une image de base récente (ex: debian:trixie, ubuntu:24.04, alpine:3.20+) embarquant OpenSSL 3.2+."
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

    # 1. Détection Kubernetes Ingress & Cert-Manager
    is_k8s_ingress = ("kind: ingress" in lower_content) or ("networking.k8s.io" in lower_content)
    is_cert_manager = ("kind: certificate" in lower_content) and ("cert-manager.io" in lower_content)

    if is_k8s_ingress and "tls:" in lower_content:
        has_pqc_curve = any(k in lower_content for k in ("mlkem", "kyber", "x25519mlkem768"))
        for i, line in enumerate(lines, start=1):
            clean = line.strip()
            if clean.startswith("#"):
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

    # 2. Détection Traefik (tls.options, curvePreferences, minVersion)
    is_traefik = ("tls:" in lower_content) and (
        "options:" in lower_content or "curvepreferences" in lower_content or "minversion" in lower_content or "entrypoints" in lower_content
    )
    if is_traefik:
        has_traefik_pqc = any(k in lower_content for k in ("mlkem", "kyber", "x25519mlkem768"))
        for i, line in enumerate(lines, start=1):
            clean = line.strip()
            if clean.startswith("#"):
                continue
            if "minversion" in clean.lower() and " versiontls13" not in clean.lower() and "tlsv1.3" not in clean.lower() and "versiontls13" not in clean.lower():
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

    return findings


def scan_terraform_file(filepath: Path) -> list:
    """Scanne les fichiers Terraform (.tf) pour détecter les clés RSA/ECDSA et politiques TLS obsolètes."""
    findings = []
    content = filepath.read_text(encoding="utf-8", errors="ignore")
    lines = content.splitlines()

    for i, line in enumerate(lines, start=1):
        clean = line.strip()
        if not clean or clean.startswith("#") or clean.startswith("//"):
            continue
        low = clean.lower()

        # 1. Ressource tls_private_key ou clés KMS asymétriques RSA / ECDSA
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

        # 2. Politiques TLS AWS ALB / CloudFront / GCP / Azure < TLS 1.3
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

    return findings

def generate_cyclonedx_cbom(findings: list, output_path: str):
    """Génère un fichier CBOM (Cryptography Bill of Materials) au format standard CycloneDX 1.6."""
    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "Shorless", "name": "shorless-scanner", "version": "0.9.7"}]
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

def generate_executive_html_report(findings: list, output_path: str, target_dir: str):
    """Génère un rapport d'audit exécutif HTML/PDF autonome pour RSSI, CTO et auditeurs NIS 2 / DORA."""
    now_str = datetime.now(timezone.utc).strftime("%d/%m/%Y à %H:%M UTC")
    total = len(findings)
    crit_count = sum(1 for f in findings if f["risk"] == "CRITIQUE")
    high_count = sum(1 for f in findings if f["risk"] == "ÉLEVÉ")
    med_count = sum(1 for f in findings if f["risk"] == "MOYEN")

    # Calcul du Score de Maturité Post-Quantique (0 à 100)
    penalty = (crit_count * 18) + (high_count * 10) + (med_count * 5)
    score = max(0, 100 - penalty)

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
                <div class="card-title">Risques Élevés (Grover / OS)</div>
                <div class="score-val" style="color:#F59E0B;">{high_count}</div>
                <div style="font-size:12px;color:var(--muted);margin-top:4px;">SHA-1, MD5, Images Legacy</div>
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
                    Lancez <code>shorless . --fix</code> en local ou activez l'agent Auto-PR sur GitHub / GitLab pour corriger vos configurations TLS &amp; IaC automatiquement.
                </div>
            </div>
            <a href="https://shorless.io" target="_blank" style="background:#10B981;color:#06080D;text-decoration:none;padding:10px 16px;border-radius:8px;font-weight:700;font-size:12px;white-space:nowrap;">
                Essai SaaS Gratuit →
            </a>
        </div>

        <div class="footer">
            Généré par Shorless PQC &amp; CBOM Scanner (Open Source Apache 2.0) • https://shorless.io
        </div>
    </div>
</body>
</html>"""

    Path(output_path).write_text(html_content, encoding="utf-8")

def apply_auto_remediation(target_path: Path, dry_run: bool = False) -> list:
    """
    Corrige automatiquement les configurations IaC (Nginx, Dockerfile, Traefik, K8s, Terraform)
    pour activer TLS 1.3 et l'échange de clés hybride post-quantique X25519MLKEM768.
    """
    patched_files = []

    # 1. Auto-remédiation Nginx (*.conf)
    for conf_file in target_path.rglob("*.conf"):
        orig = conf_file.read_text(encoding="utf-8", errors="ignore")
        updated = orig

        # Forcer TLSv1.3 uniquement
        updated = re.sub(
            r"ssl_protocols\s+[^;]*TLSv1\.[012][^;]*;",
            "ssl_protocols TLSv1.3;",
            updated
        )
        # Remplacer la courbe elliptique classique par la courbe hybride ANSSI/NIST
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

        # Traefik
        updated = re.sub(r"minVersion:\s*VersionTLS1[012]", "minVersion: VersionTLS13", updated)
        updated = re.sub(r"-\s*CurveP384", "- X25519MLKEM768\n        - X25519", updated)

        # Kubernetes Ingress
        updated = re.sub(
            r'(nginx\.ingress\.kubernetes\.io/ssl-protocols:\s*)"[^"]*TLSv1\.[012][^"]*"',
            r'\1"TLSv1.3"',
            updated
        )

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

    # 5. Auto-remédiation Code Source Multi-Langages (.py, .java, .go, .js, .ts, .cs)
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

    return patched_files

def verify_saas_api_key(api_key: str, findings_count: int, critical_count: int, auto_pr: bool) -> dict:
    """Vérifie la validité de la clé d'API SaaS auprès de shorless.io et enregistre la télémétrie."""
    clean_key = (api_key or "").strip()
    if not re.match(r"^shorless_(trial|pro)_[a-fA-F0-9]{16,32}$", clean_key):
        return {
            "valid": False,
            "message": "Format de clé invalide (attendu: shorless_trial_xxxxxxxxxxxxxxxx). Obtenez une clé sur https://shorless.io"
        }

    payload = json.dumps({
        "api_key": clean_key,
        "findings_count": findings_count,
        "critical_count": critical_count,
        "auto_pr": auto_pr,
        "version": "0.9.7"
    }).encode("utf-8")

    req = Request(
        "https://shorless.io/api_verify.php",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Shorless-CLI/0.9.6"
        },
        method="POST"
    )
    try:
        with urlopen(req, timeout=6) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        # Mode tolérant hors-ligne si le runner CI n'a pas accès à Internet
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
    pr_title = "🔒 fix(pqc): Migration Post-Quantique TLS 1.3 & Hybride ML-KEM (Shorless Auto-PR)"

    patched_bullets = "\n".join([f"- `{fpath}` : {desc}" for fpath, desc in patched_files])
    pr_body = (
        "## ⚡ Remédiation Automatique Post-Quantique (Shorless SaaS)\n\n"
        "Cette Pull Request a été générée automatiquement par **Shorless PQC Scanner** (`--fix --auto-pr`) "
        "pour mettre en conformité vos configurations d'infrastructure avec les recommandations **ANSSI** "
        "et **NIST FIPS 203 (`X25519MLKEM768`)**.\n\n"
        f"### 🛠️ Fichiers IaC corrigés ({len(patched_files)})\n"
        f"{patched_bullets}\n\n"
        f"### 📊 Résumé de l'audit CBOM CycloneDX 1.6\n"
        f"- **Alertes totales détectées avant patch :** {len(findings)}\n"
        "- **Standard d'inventaire :** OWASP CycloneDX 1.6\n"
    )
    try:
        subprocess.run(["git", "config", "user.name", "Shorless PQC Bot"], check=False, capture_output=True)
        subprocess.run(["git", "config", "user.email", "bot@shorless.io"], check=False, capture_output=True)
        subprocess.run(["git", "checkout", "-B", branch_name], check=True, capture_output=True, text=True)
        for fpath, _ in patched_files:
            subprocess.run(["git", "add", "-f", fpath], check=True, capture_output=True, text=True)
        # Commit uniquement s'il y a des changements indexés
        diff_cached = subprocess.run(["git", "diff", "--cached", "--quiet"], check=False)
        if diff_cached.returncode != 0:
            subprocess.run(["git", "commit", "-m", pr_title], check=True, capture_output=True, text=True)
        subprocess.run(["git", "push", "-f", "-u", "origin", branch_name], check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        err_detail = (e.stderr or e.stdout or str(e)).strip()
        console.print(f"[yellow]⚠️ Impossible de créer/pousser la branche Git ({branch_name}) : {err_detail}[/yellow]")
        return ""


    # 1. Ouverture via GitHub CLI (`gh`) si disponible
    gh_bin = shutil.which("gh")
    if gh_bin:
        proc = subprocess.run(
            [gh_bin, "pr", "create", "--title", pr_title, "--body", pr_body, "--base", base_branch, "--head", branch_name],
            capture_output=True, text=True
        )
        if proc.returncode == 0:
            return proc.stdout.strip()

    # 2. Ouverture via l'API REST GitHub si GITHUB_TOKEN est défini
    github_token = os.environ.get("GITHUB_TOKEN", "").strip()
    repo_slug = os.environ.get("GITHUB_REPOSITORY", "").strip()
    if not repo_slug:
        rem = subprocess.run(["git", "config", "--get", "remote.origin.url"], capture_output=True, text=True)
        m = re.search(r"github\.com[:/]([^/]+/[^/.]+)", rem.stdout or "")
        if m:
            repo_slug = m.group(1)

    if github_token and repo_slug:
        api_url = f"https://api.github.com/repos/{repo_slug}/pulls"
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

    return f"Branche '{branch_name}' poussée sur origin (ouvrez la PR sur GitHub)."

@app.command()
def scan(
    target_dir: str = typer.Argument(".", help="Dossier du projet à scanner"),
    cbom_out: str = typer.Option("cbom.json", "--cbom", help="Fichier de sortie CycloneDX CBOM"),
    report_html: str = typer.Option(None, "--report-html", help="Génère un rapport d'audit exécutif HTML/PDF (ex: pqc-report.html)"),
    check_tls: str = typer.Option(None, "--check-tls", help="URL ou domaine:port à inspecter en direct (ex: https://shorless.io)"),
    fix: bool = typer.Option(False, "--fix", help="Corrige automatiquement les fichiers IaC (Nginx, Docker, Traefik, K8s, Terraform)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simule les corrections --fix sans modifier les fichiers sur le disque"),
    api_key: str = typer.Option(None, "--api-key", envvar="SHORLESS_API_KEY", help="Clé d'API Shorless SaaS (active la télémétrie et --auto-pr)"),
    auto_pr: bool = typer.Option(False, "--auto-pr", help="Crée une branche Git et ouvre automatiquement une Pull Request avec les correctifs --fix (requiert --api-key)"),
    pr_base: str = typer.Option("main", "--pr-base", help="Branche cible pour la Pull Request automatique (--auto-pr)"),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Affiche le détail des fichiers analysés, leur type détecté et la probabilité d'exposition cryptographique."
    ),
    fail_on_critical: bool = typer.Option(False, "--ci", help="Renvoie un code d'erreur (1) pour bloquer la CI/CD")
):
    """Lance un audit de vulnérabilité Post-Quantique sur le code, l'infra (Nginx/Docker) et les endpoints TLS."""
    console.print(Panel.fit("[bold cyan]⚡ Shorless PQC-Scanner - Audit DevSecOps Post-Quantique[/bold cyan]"))

    path = Path(target_dir)
    all_findings = []

    if path.exists():
        if verbose:
            v_table = Table(
                title="🔍 Inventaire Détaillé des Fichiers Analysés (--verbose)",
                show_header=True,
                header_style="bold cyan"
            )
            v_table.add_column("Fichier", style="white", no_wrap=False)
            v_table.add_column("Type Détecté", style="emerald" if hasattr(console, "emerald") else "green")
            v_table.add_column("Probabilité Crypto", justify="right")
            v_table.add_column("Indice d'Exposition", justify="center")

            scanned_files_meta = []
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build")]
                for fname in sorted(files):
                    fpath = Path(root) / fname
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
            try:
                tree = ast.parse(py_file.read_text(encoding="utf-8", errors="ignore"))
                visitor = PythonCryptoVisitor(str(py_file))
                visitor.visit(tree)
                all_findings.extend(visitor.findings)
            except SyntaxError:
                pass
        # 1b. Scan des fichiers Multi-Langages Backend (.java, .go, .js, .ts, "*.cs")
        for ext in ("*.java", "*.go", "*.js", "*.ts", "*.cs"):
            for src_file in path.rglob(ext):
                if "node_modules" in src_file.parts or "vendor" in src_file.parts or "dist" in src_file.parts:
                    continue
                all_findings.extend(scan_multilang_source(src_file))

        # 2. Scan des configurations Nginx (.conf)
        for conf_file in path.rglob("*.conf"):
            all_findings.extend(scan_nginx_config(conf_file))

        # 3. Scan des Dockerfiles (Dockerfile, Dockerfile.*, *.dockerfile)
        for item in path.rglob("*"):
            if item.is_file() and (
                item.name == "Dockerfile"
                or item.name.startswith("Dockerfile.")
                or item.name.lower().endswith(".dockerfile")
            ):
                all_findings.extend(scan_dockerfile(item))
        # 3b. Scan des configurations YAML (Traefik & Kubernetes Ingress)
        for yaml_file in list(path.rglob("*.yml")) + list(path.rglob("*.yaml")):
            if ".github" in yaml_file.parts or yaml_file.name == "action.yml":
                continue
            all_findings.extend(scan_yaml_iac(yaml_file))

        # 3c. Scan des fichiers Terraform (.tf)
        for tf_file in path.rglob("*.tf"):
            all_findings.extend(scan_terraform_file(tf_file))

    # 4. Scan TLS en direct si --check-tls est fourni
    if check_tls:
        all_findings.extend(scan_live_tls_endpoint(check_tls))

    # 5. Affichage des résultats dans le terminal
    if not all_findings:
        console.print("[bold green]✅ Aucune vulnérabilité post-quantique détectée ![/bold green]")
        raise typer.Exit(0)

    table = Table(title=f"Inventaire Cryptographique & Risques Quantiques ({len(all_findings)} alertes)")
    table.add_column("Fichier / Endpoint", style="cyan")
    table.add_column("Source", style="magenta")
    table.add_column("Actif / Algorithme détecté", style="white")
    table.add_column("Risque PQC", style="bold")
    table.add_column("Plan de remédiation (Auto-PR disponible en SaaS)", style="green")

    critical_count = 0
    for f in all_findings:
        risk_color = "red" if f["risk"] == "CRITIQUE" else "yellow"
        if f["risk"] == "CRITIQUE":
            critical_count += 1
        table.add_row(
            f"{f['file']}:{f['line']}",
            f["type"],
            f["algo"],
            f"[{risk_color}]{f['risk']}[/{risk_color}]",
            f["remediation"]
        )

    console.print(table)

    # 6. Export du CBOM CycloneDX 1.6
    generate_cyclonedx_cbom(all_findings, cbom_out)
    console.print(f"\n📄 [bold]CBOM CycloneDX 1.6 généré avec succès :[/bold] [underline]{cbom_out}[/underline]")


    # 6a. Vérification de la clé SaaS (--api-key) si fournie ou si --auto-pr est demandé
    if auto_pr and not api_key:
        console.print(
            "\n[bold red]🔒 L'option --auto-pr est une fonctionnalité Shorless SaaS.[/bold red]\n"
            "[yellow]👉 Obtenez une clé d'essai gratuite (14j) sur https://shorless.io puis ajoutez :[/yellow] "
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
            console.print("[yellow]ℹ️  Aucun fichier IaC automatiquement corrigeable trouvé.[/yellow]")

    # Envoi de la télémétrie SaaS (avec déduction des risques corrigés si --fix est actif sans --dry-run)
    if api_key:
        remediated_count = len(patched) if (fix or auto_pr) and not dry_run else 0
        rem_findings = max(0, len(all_findings) - remediated_count)
        rem_critical = max(0, critical_count - remediated_count)
        auth_res = verify_saas_api_key(api_key, rem_findings, rem_critical, auto_pr)
        if not auth_res.get("valid"):
            console.print(f"\n[bold red]❌ Erreur d'authentification SaaS : {auth_res.get('message')}[/bold red]")
            raise typer.Exit(code=1)
        console.print(f"\n[bold green]🔑 {auth_res.get('message')}[/bold green]")

    if patched and not dry_run and auto_pr:
        console.print("[cyan]🚀 Création de la branche Git et ouverture de la Pull Request automatique...[/cyan]")
        pr_url = create_automated_pull_request(patched, all_findings, base_branch=pr_base)
        if pr_url:
            console.print(f"[bold green]✅ Pull Request Post-Quantique ouverte :[/bold green] [underline]{pr_url}[/underline]")

    # 7. Génération du Rapport d'Audit Exécutif HTML/PDF si demandé
    if report_html:
        generate_executive_html_report(all_findings, report_html, target_dir)
        console.print(f"📊 [bold]Rapport Exécutif HTML/PDF généré :[/bold] [underline]{report_html}[/underline]")

    # 8. Mode bloqueur CI/CD (GitHub Actions / GitLab CI)
    if fail_on_critical and critical_count > 0:
        console.print(f"\n[bold red]❌ Pipeline CI bloquée : {critical_count} vulnérabilité(s) critique(s) face au risque quantique.[/bold red]")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
