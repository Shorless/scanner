import java.security.KeyPairGenerator;
public class CryptoService {
    public void init() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA") /* [SHORLESS-PQC] Migrer vers BouncyCastle ML-KEM-768 / ML-DSA */;
        kpg.initialize(2048);
    }
}
