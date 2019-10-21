package nl.quintor.iamservice.security.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;


import static org.assertj.core.api.Assertions.*;

@RunWith(SpringRunner.class)
@SpringBootTest
@ActiveProfiles("test")
public class JwtTokenProviderTest {

    private String secretKey = "ThisIsMySecretKeyToSignJwtTokensasjkdhh23h43kjhrufhjk3hk23kj4h3ulankfffsgsdfgdsFDVSDDFDSFSSDFDS";

    private JwtSigningKey signingKey = JwtSigningKey.secretKey(secretKey);

    private JwtTokenProvider jwtTokenProvider = new JwtTokenProvider(signingKey);

    @Test
    public void createToken_withMultipleRoles_createsValidToken_() {
        var inputRoles = Arrays.asList("ROLE_ONE", "ROLE_TWO", "ROLE_THREE", "ADMIN");
        var inputUserName = "username";
        var auth = new UsernamePasswordAuthenticationToken(
                inputUserName,
                "",
                inputRoles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList())
        );

        var token = jwtTokenProvider.createToken(auth);

        assertThat(token).isNotNull();
        var claims = Jwts.parser()
                .setSigningKey(signingKey.getSigningKeyForVerification())
                .parseClaimsJws(token);

        assertThat(claims).isNotNull();
        assertThat(claims.getBody().getSubject()).isEqualTo(inputUserName);
        List<String> extractedRoles = Arrays.asList(claims.getBody().get("roles", String.class).split(","));
        assertThat(extractedRoles).containsExactly(inputRoles.toArray(String[]::new));
    }

    @Test
    public void createToken_withSingleRole_createsValidToken_() {
        var inputRoles = Arrays.asList("ROLE_ONE");
        var inputUserName = "username";
        var auth = new UsernamePasswordAuthenticationToken(
                inputUserName,
                "",
                inputRoles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList())
        );

        var token = jwtTokenProvider.createToken(auth);

        assertThat(token).isNotNull();
        var claims = Jwts.parser()
                .setSigningKey(Keys.hmacShaKeyFor(secretKey.getBytes()))
                .parseClaimsJws(token);

        assertThat(claims).isNotNull();
        assertThat(claims.getBody().getSubject()).isEqualTo(inputUserName);
        List<String> extractedRoles = Arrays.asList(claims.getBody().get("roles", String.class).split(","));
        assertThat(extractedRoles).containsExactly(inputRoles.toArray(String[]::new));
    }

    @Test
    public void createToken_withNullParam_throwsException() {
        Authentication input = null;

        assertThatThrownBy(() -> jwtTokenProvider
                                        .createToken(input))
                                        .isExactlyInstanceOf(NullPointerException.class)
                                        .hasMessage("Authentication object cannot be null");
    }

    @Test
    public void createToken_withNullUsername_throwsException() {
        var inputRoles = Arrays.asList("ROLE_ONE", "ROLE_TWO", "ROLE_THREE", "ADMIN");
        String inputUserName = null;
        var auth = new UsernamePasswordAuthenticationToken(
                inputUserName,
                "",
                inputRoles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList())
        );

        assertThatThrownBy(() -> jwtTokenProvider
                .createToken(auth))
                .isExactlyInstanceOf(NullPointerException.class)
                .hasMessage("Username must be provided for authentication");
    }



}
