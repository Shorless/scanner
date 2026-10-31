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
    is_traefik = (" tls:" in lower_content or "\ntls:" in lower_content) and (
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
            "tools": [{"vendor": "Shorless", "name": "shorless-scanner", "version": "0.9.1"}]
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
        if ".github" in yaml_file.parts:
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

    return patched_files

@app.command()
def scan(
    target_dir: str = typer.Argument(".", help="Dossier du projet à scanner"),
    cbom_out: str = typer.Option("cbom.json", "--cbom", help="Fichier de sortie CycloneDX CBOM"),
    check_tls: str = typer.Option(None, "--check-tls", help="URL ou domaine:port à inspecter en direct (ex: https://shorless.io)"),
    fix: bool = typer.Option(False, "--fix", help="Corrige automatiquement les fichiers IaC (Nginx, Docker, Traefik, K8s, Terraform)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simule les corrections --fix sans modifier les fichiers sur le disque"),
    fail_on_critical: bool = typer.Option(False, "--ci", help="Renvoie un code d'erreur (1) pour bloquer la CI/CD")
):
    """Lance un audit de vulnérabilité Post-Quantique sur le code, l'infra (Nginx/Docker) et les endpoints TLS."""
    console.print(Panel.fit("[bold cyan]⚡ Shorless PQC-Scanner - Audit DevSecOps Post-Quantique[/bold cyan]"))

    path = Path(target_dir)
    all_findings = []

    if path.exists():
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
            if ".github" in yaml_file.parts:
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

    # 6b. Exécution de l'Auto-Remédiation (--fix ou --dry-run)
    if fix or dry_run:
        mode_label = "SIMULATION (--dry-run)" if dry_run else "APPLICATION DES CORRECTIFS (--fix)"
        console.print(f"\n[bold cyan]🛠️  Auto-Remédiation Post-Quantique — {mode_label}[/bold cyan]")
        patched = apply_auto_remediation(path, dry_run=dry_run)
        if patched:
            for fpath, action_desc in patched:
                prefix = "[yellow][DRY-RUN][/yellow]" if dry_run else "[bold green][CORRIGÉ][/bold green]"
                console.print(f"  {prefix} [white]{fpath}[/white] → [emerald]{action_desc}[/emerald]")
            if not dry_run:
                console.print(
                    "\n[bold green]✨ Fichiers mis à jour localement ![/bold green] "
                    "[dim]Astuce SaaS : Automatisez l'ouverture de Pull Requests GitHub/GitLab et les tests MTU sur https://shorless.io[/dim]"
                )
        else:
            console.print("[yellow]ℹ️  Aucun fichier IaC automatiquement corrigeable trouvé (les clés AST dans le code métier nécessitent une refacto manuelle ou l'agent Auto-PR SaaS).[/yellow]")

    # 7. Mode bloqueur CI/CD (GitHub Actions / GitLab CI)
    if fail_on_critical and critical_count > 0:
        console.print(f"\n[bold red]❌ Pipeline CI bloquée : {critical_count} vulnérabilité(s) critique(s) face au risque quantique.[/bold red]")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
