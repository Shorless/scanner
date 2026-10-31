using System.Security.Cryptography;
public class AuthController {
    public void Generate() {
        using var rsa = RSA.Create(4096) /* [SHORLESS-PQC: Migrer vers MLKem (.NET 9+)] */;
        using var sha1 = SHA256.Create();
    }
}
