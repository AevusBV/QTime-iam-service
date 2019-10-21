package nl.quintor.iamservice.security.jwt;

import io.jsonwebtoken.security.Keys;
import lombok.Builder;

import java.security.Key;

public class JwtSecretKey extends JwtSigningKey {
    private Key secretKey;

    public JwtSecretKey(String secretKey) {
        this.secretKey = Keys.hmacShaKeyFor(secretKey.getBytes());
    }

    @Override
    public Key getSigningKeyForCreation() {
        return secretKey;
    }

    @Override
    public Key getSigningKeyForVerification() {
        return secretKey;
    }
}
