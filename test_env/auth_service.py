from cryptography.hazmat.primitives.asymmetric import rsa, ec
# Génération d'une clé RSA-2048 et courbe P-256 vulnérables à Shor
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
curve = ec.SECP256R1()
