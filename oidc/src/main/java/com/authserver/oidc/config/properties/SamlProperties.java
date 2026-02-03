package com.authserver.oidc.config.properties;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "saml")
@Validated
public class SamlProperties {

    private Keystore keystore = new Keystore();
    private Idp idp = new Idp();

    public Keystore getKeystore() {
        return keystore;
    }

    public void setKeystore(Keystore keystore) {
        this.keystore = keystore;
    }

    public Idp getIdp() {
        return idp;
    }

    public void setIdp(Idp idp) {
        this.idp = idp;
    }

    public static class Keystore {
        @NotBlank
        private String location;
        @NotBlank
        private String password;
        @NotBlank
        private String alias;
        @NotBlank
        private String keyPassword;

        public String getLocation() {
            return location;
        }

        public void setLocation(String location) {
            this.location = location;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public String getAlias() {
            return alias;
        }

        public void setAlias(String alias) {
            this.alias = alias;
        }

        public String getKeyPassword() {
            return keyPassword;
        }

        public void setKeyPassword(String keyPassword) {
            this.keyPassword = keyPassword;
        }
    }

    public static class Idp {
        @NotBlank
        private String entityId;
        @NotBlank
        private String ssoUrl;
        
        // Support both cert from keystore (legacy) or PEM file
        private String verificationCertAlias;
        private String verificationCertLocation;

        public String getEntityId() {
            return entityId;
        }

        public void setEntityId(String entityId) {
            this.entityId = entityId;
        }

        public String getSsoUrl() {
            return ssoUrl;
        }

        public void setSsoUrl(String ssoUrl) {
            this.ssoUrl = ssoUrl;
        }

        public String getVerificationCertAlias() {
            return verificationCertAlias;
        }

        public void setVerificationCertAlias(String verificationCertAlias) {
            this.verificationCertAlias = verificationCertAlias;
        }

        public String getVerificationCertLocation() {
            return verificationCertLocation;
        }

        public void setVerificationCertLocation(String verificationCertLocation) {
            this.verificationCertLocation = verificationCertLocation;
        }
    }
}
