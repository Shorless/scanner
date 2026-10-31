package main
import ("crypto/rand"; "crypto/rsa")
func gen() { _, _ = /* [SHORLESS-PQC: Migrer vers crypto/mlkem (Go 1.24+)] */ rsa.GenerateKey(rand.Reader, 2048) }
