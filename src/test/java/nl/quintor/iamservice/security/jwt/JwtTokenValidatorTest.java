package nl.quintor.iamservice.security.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.Arrays;
import java.util.Objects;
import java.util.stream.Collectors;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

@RunWith(SpringRunner.class)
@SpringBootTest
@ActiveProfiles("test")
public class JwtTokenValidatorTest {

    private String secretKey = "ThisIsMySecretKeyToSignJwtTokensasjkdhh23h43kjhrufhjk3hk23kj4h3ulankfffsgsdfgdsFDVSDDFDSFSSDFDS";

    private JwtSigningKey jwtSigningKey = JwtSigningKey.secretKey(secretKey);

    private JwtTokenValidator jwtTokenValidator = new JwtTokenValidator(jwtSigningKey);

    @Test
    public void getAuthentication_withMultipleRoles_VerifiesTokenCorrectly() {
        var key = Keys.hmacShaKeyFor(secretKey.getBytes());

        var authorities = Arrays.asList(new SimpleGrantedAuthority("role1"), new SimpleGrantedAuthority("role2"));

        var token = Jwts.builder()
                .setSubject("username")
                .claim("roles", authorities.stream().map(Objects::toString).collect(Collectors.joining(",")))
                .signWith(key)
                .compact();

        var auth = jwtTokenValidator.getAuthentication(token);

        assertThat(auth.isPresent(), is(true));
        assertThat(auth.get().getPrincipal(), is("username"));
        assertThat(auth.get().getAuthorities().containsAll(authorities), is(true));
    }

    @Test
    public void getAuthentication_VerifiesTokenCorrectly_Fail() {
        var differentKey = secretKey + "different";
        var key = Keys.hmacShaKeyFor(differentKey.getBytes());

        var authorities = Arrays.asList(new SimpleGrantedAuthority("role1"), new SimpleGrantedAuthority("role2"));

        var token = Jwts.builder()
                .setSubject("username")
                .claim("roles", authorities.stream().map(Objects::toString).collect(Collectors.joining(",")))
                .signWith(key)
                .compact();

        var auth = jwtTokenValidator.getAuthentication(token);

        assertThat(auth.isEmpty(), is(true));
    }
}
