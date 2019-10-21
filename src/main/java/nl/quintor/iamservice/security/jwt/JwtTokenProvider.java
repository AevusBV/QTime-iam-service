package nl.quintor.iamservice.security.jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import java.util.stream.Collectors;

public class JwtTokenProvider {

    private static final String ROLES_KEY = "roles";

    private JwtSigningKey key;

    public JwtTokenProvider(JwtSigningKey key) {
        this.key = key;
    }

    public String createToken(Authentication authentication) {
        Objects.requireNonNull(authentication, "Authentication object cannot be null");
        Objects.requireNonNull(authentication.getPrincipal(), "Username must be provided for authentication");

        var roles = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim(ROLES_KEY, roles)
                .signWith(key.getSigningKeyForCreation())
                .compact();
    }
}
