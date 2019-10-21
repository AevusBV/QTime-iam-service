package nl.quintor.iamservice.security.config;

import nl.quintor.iamservice.security.MyUserDetailService;
import nl.quintor.iamservice.security.filter.JwtAuthFilter;
import nl.quintor.iamservice.security.filter.JwtTokenFilter;
import nl.quintor.iamservice.security.jwt.JwtSigningKey;
import nl.quintor.iamservice.security.jwt.JwtTokenProvider;
import nl.quintor.iamservice.security.jwt.JwtTokenValidator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${security.login.path}")
    private String LOGIN_PATH;

    @Value("${security.secret-key}")
    private String SECRET_KEY;

    @Value("${security.keystore.path}")
    private String KEYSTORE_PATH;

    @Value("${security.keystore.password}")
    private String KEYSTORE_PASSWORD;

    @Value("${security.keystore.alias}")
    private String KEYSTORE_ALIAS;

    private MyUserDetailService userDetailService;

    public SecurityConfig(MyUserDetailService userDetailService) {
        this.userDetailService = userDetailService;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()

                .authorizeRequests()
                .antMatchers(LOGIN_PATH).permitAll()
                .antMatchers("/auth/key").permitAll()
                .anyRequest().authenticated()

                .and()
                .addFilterBefore(JwtAuthFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(JwtTokenFilter(), UsernamePasswordAuthenticationFilter.class)
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }


    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailService).passwordEncoder(bCryptPasswordEncoder());
    }

    @Bean
    public JwtSigningKey jwtSigningKey() throws IOException, KeyStoreException {
        return JwtSigningKey.rsaKey(new File(KEYSTORE_PATH), KEYSTORE_ALIAS, KEYSTORE_PASSWORD);
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JwtTokenValidator jwtTokenValidator() throws IOException, KeyStoreException {
        return new JwtTokenValidator(jwtSigningKey());
    }

    @Bean
    public JwtTokenProvider jwtTokenProvider() throws IOException, KeyStoreException {
        return new JwtTokenProvider(jwtSigningKey());
    }

    private JwtTokenFilter JwtTokenFilter() throws IOException, KeyStoreException {
        return new JwtTokenFilter(jwtTokenValidator());
    }

    private JwtAuthFilter JwtAuthFilter() throws Exception {
        JwtAuthFilter jwtAuthFilter = new JwtAuthFilter(authenticationManager(), jwtTokenProvider());
        jwtAuthFilter.setContinueChainBeforeSuccessfulAuthentication(false);
        jwtAuthFilter.setFilterProcessesUrl(LOGIN_PATH);
        return jwtAuthFilter;
    }
}
