package nl.quintor.iamservice.controller;

import nl.quintor.iamservice.security.jwt.JwtSigningKey;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private JwtSigningKey jwtSigningKey;

    public AuthController(JwtSigningKey jwtSigningKey) {
        this.jwtSigningKey = jwtSigningKey;
    }

    @GetMapping("/key")
    public String getPublicKeyPretty() {
        return Base64.getEncoder().encodeToString(jwtSigningKey.getSigningKeyForVerification().getEncoded());
    }
}
