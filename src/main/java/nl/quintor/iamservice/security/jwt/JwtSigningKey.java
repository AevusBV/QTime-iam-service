package nl.quintor.iamservice.security.jwt;

import java.io.File;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStoreException;

public abstract class JwtSigningKey {

    public abstract Key getSigningKeyForCreation();
    public abstract Key getSigningKeyForVerification();

    public static JwtSigningKey secretKey(String secret) {
        return new JwtSecretKey(secret);
    }

    public static JwtSigningKey rsaKey(File keyStoreFile, String alias, String password) throws KeyStoreException, IOException {
        return new JwtRsaKey(keyStoreFile, alias, password);
    }
}
