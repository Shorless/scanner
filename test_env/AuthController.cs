using System.Security.Cryptography;
public class AuthController {
    public void Generate() {
        using var rsa = RSA.Create(2048);
        using var sha1 = SHA1.Create();
    }
}
