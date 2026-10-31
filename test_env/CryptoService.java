import java.security.KeyPairGenerator;
public class CryptoService {
    public void init() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
    }
}
