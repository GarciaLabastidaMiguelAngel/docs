package com.authserver.oidc.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.web.SecurityFilterChain;

import com.authserver.oidc.config.Saml2SuccessHandler;
import com.authserver.oidc.config.properties.SamlProperties;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

/**
 * Configuración de seguridad para SAML2.
 * 
 * Flujo integrado (sin controladores):
 * 1. GET /oauth2/authorize → usuario no autenticado → redirige a /saml2/authenticate/bet
 * 2. SAML2 autentica con IdP
 * 3. Saml2SuccessHandler se ejecuta automáticamente (sin endpoint extra)
 * 4. Redirige a /oauth2/authorize con credenciales SAML
 * 5. Spring Authorization Server genera authorization code
 */
@Configuration
@EnableConfigurationProperties(SamlProperties.class)
@ConditionalOnProperty(name = "saml.enabled", havingValue = "true", matchIfMissing = true)
public class SecurityConfig {

    @Autowired(required = false)
    private Saml2SuccessHandler saml2SuccessHandler;

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                // SAML endpoints only (OAuth2 endpoints handled by @Order(1) filter chain)
                .requestMatchers("/error").permitAll()
                .requestMatchers("/saml2/**").permitAll()
                // All other requests require authentication
                .anyRequest().authenticated()
            )
            .saml2Login(saml2 -> {
                if (saml2SuccessHandler != null) {
                    saml2.successHandler(saml2SuccessHandler);
                }
            })
            .saml2Metadata(Customizer.withDefaults());
        
        return http.build();
    }

    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository(
            SamlProperties samlProperties, 
            ResourceLoader resourceLoader) {
        
        try {
            // Load SAML keystore
            Resource keystoreResource = resourceLoader.getResource(samlProperties.getKeystore().getLocation());
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            
            try (InputStream is = keystoreResource.getInputStream()) {
                keyStore.load(is, samlProperties.getKeystore().getPassword().toCharArray());
            }
            
            // Get SP signing key (optional, commented out for minimal setup)
            RSAPrivateKey privateKey = (RSAPrivateKey) keyStore.getKey(
                samlProperties.getKeystore().getAlias(),
                samlProperties.getKeystore().getKeyPassword().toCharArray()
            );
            X509Certificate spCertificate = (X509Certificate) keyStore.getCertificate(
                samlProperties.getKeystore().getAlias()
            );
            
            // Get IdP verification certificate from PEM file
            X509Certificate idpCertificate;
            String certLocation = samlProperties.getIdp().getVerificationCertLocation();
            
            if (certLocation != null && !certLocation.isEmpty()) {
                // Load from PEM file
                Resource certResource = resourceLoader.getResource(certLocation);
                try (InputStream certStream = certResource.getInputStream()) {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    idpCertificate = (X509Certificate) cf.generateCertificate(certStream);
                }
            } else {
                // Fallback: Load from keystore (legacy)
                Certificate idpCert = keyStore.getCertificate(samlProperties.getIdp().getVerificationCertAlias());
                if (idpCert == null) {
                    throw new RuntimeException("IdP verification certificate not found");
                }
                idpCertificate = (X509Certificate) idpCert;
            }
            
            // Build RelyingPartyRegistration
            RelyingPartyRegistration registration = RelyingPartyRegistration.withRegistrationId("bet")
                .entityId("{baseUrl}/saml2/service-provider-metadata/bet")
                .assertionConsumerServiceLocation("{baseUrl}/login/saml2/sso/bet")
                .assertionConsumerServiceBinding(Saml2MessageBinding.POST)
                .singleLogoutServiceLocation("{baseUrl}/logout/saml2/slo")
                .singleLogoutServiceResponseLocation("{baseUrl}/logout/saml2/slo")
                .singleLogoutServiceBinding(Saml2MessageBinding.POST)
                .signingX509Credentials(c -> c.add(
                    org.springframework.security.saml2.core.Saml2X509Credential.signing(privateKey, spCertificate)
                ))
                .assertingPartyDetails(party -> party
                    .entityId(samlProperties.getIdp().getEntityId())
                    .singleSignOnServiceLocation(samlProperties.getIdp().getSsoUrl())
                    .singleSignOnServiceBinding(Saml2MessageBinding.REDIRECT)
                    .verificationX509Credentials(c -> c.add(
                        org.springframework.security.saml2.core.Saml2X509Credential.verification(idpCertificate)
                    ))
                )
                .build();
            
            return new InMemoryRelyingPartyRegistrationRepository(registration);
            
        } catch (Exception e) {
            throw new RuntimeException("Failed to configure SAML2 SP", e);
        }
    }
}
