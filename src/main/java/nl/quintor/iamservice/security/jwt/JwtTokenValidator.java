package nl.quintor.iamservice.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;
import java.util.Optional;
import java.util.stream.Collectors;


public class JwtTokenValidator {
    private static final String ROLES_KEY = "roles";
    private static final String ROLES_DELIMITTER = ",";

 private JwtSigningKey key;

    public JwtTokenValidator(JwtSigningKey key) {
        this.key = key;
    }


    public Optional<Authentication> getAuthentication(String token) {
        Jws<Claims> claims;

        try {
            claims = Jwts.parser()
                    .setSigningKey(key.getSigningKeyForVerification())
                    .parseClaimsJws(token);
        } catch (Exception ignored) {
            return Optional.empty();
        }

        var username = claims.getBody().getSubject();
        var roles = Arrays.stream(claims.getBody()
                .get(ROLES_KEY, String.class)
                .split(ROLES_DELIMITTER))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        return Optional.of(new UsernamePasswordAuthenticationToken(username, "", roles));
    }

}
