package com.authserver.oidc.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
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
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
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
public class OidcAuthorizationServerConfig {

    @Value("${saml.enabled:true}")
    private boolean samlEnabled;
    
    // Pre-configured test client
    private static final String CLIENT_ID = "fifo-client";
    private static final String EXAMPLE_CLIENT_ID = "example-client";
    private static final String CLIENT_SECRET = "{noop}secret";
    private static final String EXAMPLE_CLIENT_SECRET = "{noop}example-secret";
    private static final String GATEWAY_CLIENT_ID = "gateway-introspect";
    private static final String GATEWAY_CLIENT_SECRET = "{noop}changeit";
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

        // Enable all OIDC endpoints with custom userInfo mapper
        authorizationServerConfigurer.oidc(oidc -> oidc
            .userInfoEndpoint(userInfo -> userInfo
                .userInfoMapper(this::createUserInfo)
            )
            .providerConfigurationEndpoint(Customizer.withDefaults())
            .logoutEndpoint(Customizer.withDefaults())
        );

        // Configure OAuth2 Resource Server for JWT validation (needed for /userinfo endpoint)
        http.oauth2ResourceServer(oauth2 -> oauth2
            .jwt(Customizer.withDefaults())
        );

        // Permit public access to OIDC discovery and JWKS endpoints (required for OAuth2 clients)
        http.authorizeHttpRequests(authz -> authz
            .requestMatchers("/.well-known/openid-configuration").permitAll()
            .requestMatchers("/oauth2/jwks").permitAll()
            .anyRequest().authenticated()
        );

        // Handle unauthenticated requests by redirecting to SAML2 login (only when SAML enabled)
        if (samlEnabled) {
            http.exceptionHandling(exceptions ->
                exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/saml2/authenticate/bet"))
            );
        }

        return http.build();
    }
    
    /**
     * Create OidcUserInfo from SAML2 authentication context.
     * Extracts user attributes from the SAML2 principal and maps them to OIDC claims.
     */
    private OidcUserInfo createUserInfo(OidcUserInfoAuthenticationContext context) {
        OAuth2Authorization authorization = context.getAuthorization();
        
        // Build claims map
        Map<String, Object> claims = new HashMap<>();
        
        // Get the principal name (NameID from SAML)
        if (authorization != null && authorization.getPrincipalName() != null) {
            String username = authorization.getPrincipalName();
            claims.put("sub", username);
            claims.put("name", username);
            claims.put("preferred_username", username);
            
            // Try to extract email from username if it looks like an email
            if (username.contains("@")) {
                claims.put("email", username);
                claims.put("email_verified", true);
            }
        }
        
        // Try to extract additional SAML attributes
        if (authorization != null) {
            Object principal = authorization.getAttribute("java.security.Principal");
            if (principal instanceof Saml2AuthenticatedPrincipal) {
                Saml2AuthenticatedPrincipal saml2Principal = (Saml2AuthenticatedPrincipal) principal;
                
                // Map common SAML attributes to OIDC claims
                saml2Principal.getAttributes().forEach((key, values) -> {
                    if (!values.isEmpty()) {
                        Object value = values.size() == 1 ? values.get(0) : values;
                        
                        switch (key.toLowerCase()) {
                            case "email":
                            case "emailaddress":
                                claims.put("email", value);
                                claims.put("email_verified", true);
                                break;
                            case "givenname":
                            case "firstname":
                                claims.put("given_name", value);
                                break;
                            case "surname":
                            case "lastname":
                                claims.put("family_name", value);
                                break;
                            case "displayname":
                                claims.put("name", value);
                                break;
                            default:
                                // Include other attributes as-is
                                claims.put(key, value);
                        }
                    }
                });
            }
        }
        
        return new OidcUserInfo(claims);
    }
    
    /**
     * Registered Client Repository: JDBC-backed (persists to H2).
     * Bootstrap fifo-client if not exists.
     */
    @Bean
    @DependsOn("dataSourceScriptDatabaseInitializer")
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
        
        // Bootstrap client
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

        // Bootstrap example-client for local browser/manual testing
        try {
            if (repository.findByClientId(EXAMPLE_CLIENT_ID) != null) {
                jdbcTemplate.update("DELETE FROM oauth2_registered_client WHERE client_id = ?", EXAMPLE_CLIENT_ID);
                System.out.println("[STARTUP] Cleaned up old " + EXAMPLE_CLIENT_ID);
            }
            RegisteredClient exampleClient = RegisteredClient
                    .withId(UUID.randomUUID().toString())
                    .clientId(EXAMPLE_CLIENT_ID)
                    .clientSecret(EXAMPLE_CLIENT_SECRET)
                    .clientName(EXAMPLE_CLIENT_ID)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
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
                        .requireProofKey(false)
                        .build())
                    .build();
            repository.save(exampleClient);
            System.out.println("[STARTUP] Registered client: " + EXAMPLE_CLIENT_ID + " with redirect_uri: " + REDIRECT_URI_3);
        } catch (Exception e) {
            System.out.println("[STARTUP] Could not register example-client: " + e.getMessage());
        }

        // Bootstrap gateway introspection client if missing
        try {
            RegisteredClient existingGateway = repository.findByClientId(GATEWAY_CLIENT_ID);
            if (existingGateway == null) {
                RegisteredClient gatewayClient = RegisteredClient
                    .withId(UUID.randomUUID().toString())
                    .clientId(GATEWAY_CLIENT_ID)
                    .clientSecret(GATEWAY_CLIENT_SECRET)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .scope("introspect")
                    .build();
                repository.save(gatewayClient);
                System.out.println("[STARTUP] Registered client: " + GATEWAY_CLIENT_ID + " for introspection");
            }
        } catch (Exception e) {
            System.out.println("[STARTUP] Could not register gateway client: " + e.getMessage());
        }
        
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
