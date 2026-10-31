package main
import ("crypto/rand"; "crypto/rsa")
func gen() { _, _ = rsa.GenerateKey(rand.Reader, 2048) }
