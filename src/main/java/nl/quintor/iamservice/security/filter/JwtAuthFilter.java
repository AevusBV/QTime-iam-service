package nl.quintor.iamservice.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import nl.quintor.iamservice.model.Quser;
import nl.quintor.iamservice.security.jwt.JwtTokenProvider;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.server.ResponseStatusException;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;


/**
 * Filter for authenticating and assigning JWT tokens.
 */

public class JwtAuthFilter extends UsernamePasswordAuthenticationFilter {

    private static final String TOKEN_PREFIX  = "Bearer ";
    private static final String AUTHORIZATION_HEADER  = "Authorization";

    private AuthenticationManager authenticationManager;
    private JwtTokenProvider jwtTokenProvider;

    public JwtAuthFilter(AuthenticationManager authenticationManager, JwtTokenProvider jwtTokenProvider) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        return parseUserFromRequestBody(request)
                .map(user -> authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword())))

                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.BAD_REQUEST,
                        "Can't fetch credentials from body"
                ));
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication auth) {

        var token = jwtTokenProvider.createToken(auth);

        response.addHeader(AUTHORIZATION_HEADER, TOKEN_PREFIX + token);
    }

    private Optional<Quser> parseUserFromRequestBody(HttpServletRequest request) {
        try {
            return Optional.of(new ObjectMapper().readValue(request.getInputStream(), Quser.class));
        } catch (IOException e) {
            e.printStackTrace();
        }

        return Optional.empty();
    }

}
