package com.fifo.oidc.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.time.Duration;
import java.util.UUID;

/**
 * OIDC Core Authorization Server Configuration
 * 
 * Exposes native Authorization Server endpoints:
 * - GET  /oauth2/authorize         (Authorization Code flow with PKCE)
 * - POST /oauth2/token              (Token endpoint)
 * - GET  /oauth2/jwks               (JSON Web Key Set)
 * - GET  /.well-known/openid-configuration (OIDC Discovery)
 * 
 * Issues:
 * - access_token as JWT (self-contained)
 * - id_token when scope includes 'openid'
 * 
 * No custom @RestController endpoints for OAuth/OIDC; uses Spring Authorization Server built-in endpoints.
 */
@Configuration
public class AuthorizationServerConfig {
    
    // Pre-configured test client
    private static final String CLIENT_ID = "fifo-client";
    private static final String CLIENT_SECRET = "{noop}secret";
    private static final String REDIRECT_URI_1 = "http://localhost:8081/login/oauth2/code/fifo";
    private static final String REDIRECT_URI_2 = "http://127.0.0.1:8081/login/oauth2/code/fifo";
    private static final String REDIRECT_URI_3 = "http://localhost:8081/callback";
    
    // RSA key pair for signing JWTs (generated at startup, for dev only)
    private static final RSAKey RSA_KEY;
    
    static {
        try {
            RSA_KEY = new RSAKeyGenerator(2048)
                .keyID(UUID.randomUUID().toString())
                .generate();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate RSA key", e);
        }
    }
    
    /**
     * Order(1): Authorization Server filter chain (higher priority than application security).
     * Uses Spring Authorization Server's default security configuration which:
     * - Registers all OAuth2 endpoints (/oauth2/authorize, /oauth2/token, /oauth2/jwks, etc.)
     * - Enables OIDC endpoints (/.well-known/openid-configuration, /userinfo, etc.)
     * - Protects endpoints with appropriate authentication
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // Apply Spring Authorization Server default security
        // This automatically registers all OAuth2/OIDC endpoints
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        // Get the OAuth2 configurer to customize OIDC settings
        var authorizationServerConfigurer = http.getConfigurer(
            org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer.class
        );

        // Enable all OIDC endpoints
        authorizationServerConfigurer.oidc(oidc -> oidc
            .userInfoEndpoint(Customizer.withDefaults())
            .providerConfigurationEndpoint(Customizer.withDefaults())
            .logoutEndpoint(Customizer.withDefaults())
        );

        // Handle unauthenticated requests by redirecting to SAML2 login
        http.exceptionHandling(exceptions ->
            exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/saml2/authenticate/bet"))
        );

        return http.build();
    }
    
    /**
     * Registered Client Repository: JDBC-backed (persists to H2).
     * Bootstrap fifo-client if not exists.
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        JdbcRegisteredClientRepository repository = new JdbcRegisteredClientRepository(jdbcTemplate);
        
        // Clean up old client if exists (for testing)
        try {
            if (repository.findByClientId(CLIENT_ID) != null) {
                jdbcTemplate.update("DELETE FROM oauth2_registered_client WHERE client_id = ?", CLIENT_ID);
                System.out.println("[STARTUP] Cleaned up old " + CLIENT_ID);
            }
        } catch (Exception e) {
            System.out.println("[STARTUP] Could not clean up old client: " + e.getMessage());
        }
        
        // Bootstrap fifo-client
        RegisteredClient client = RegisteredClient
            .withId(UUID.randomUUID().toString())
            .clientId(CLIENT_ID)
            .clientSecret(CLIENT_SECRET)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .redirectUri(REDIRECT_URI_1)
            .redirectUri(REDIRECT_URI_2)
            .redirectUri(REDIRECT_URI_3)
            .scope(OidcScopes.OPENID)
            .scope(OidcScopes.PROFILE)
            .scope(OidcScopes.EMAIL)
            .tokenSettings(TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                .accessTokenTimeToLive(Duration.ofHours(1))
                .refreshTokenTimeToLive(Duration.ofDays(7))
                .reuseRefreshTokens(true)
                .build())
            .clientSettings(ClientSettings.builder()
                .requireProofKey(false)  // Allow requests without PKCE
                .build())
            .build();
        repository.save(client);
        System.out.println("[STARTUP] Registered client: " + CLIENT_ID + " with redirect_uris: " + 
            REDIRECT_URI_1 + ", " + REDIRECT_URI_2 + ", " + REDIRECT_URI_3);
        
        return repository;
    }

    /**
     * OAuth2AuthorizationService: JDBC-backed (persists to H2).
     */
    @Bean
    public org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService authorizationService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    /**
     * OAuth2AuthorizationConsentService: JDBC-backed (persists to H2).
     */
    @Bean
    public org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService authorizationConsentService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }
    
    /**
     * Authorization Server Settings.
     * Issuer must match what clients expect for id_token validation.
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
            .issuer("http://localhost:8080")
            .build();
    }
    
    /**
     * JWK Source: holds RSA public key for /oauth2/jwks endpoint.
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        JWKSet jwkSet = new JWKSet(RSA_KEY);
        return new ImmutableJWKSet<>(jwkSet);
    }
    
    /**
     * JWT Decoder for validating JWTs (used internally by Authorization Server).
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) throws Exception {
        return NimbusJwtDecoder.withPublicKey(RSA_KEY.toRSAPublicKey()).build();
    }
}
