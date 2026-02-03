package com.authserver.oidc.test.technical.oidc;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * BLACK-BOX HTTP test for complete OIDC → SAML2 → code flow.
 * 
 * Validates observable HTTP behavior without mocking the IdP:
 * - 302 redirect from /oauth2/authorize to /saml2/authenticate/bet (UNAUTHENTICATED)
 * 
 * Note: Full SAML roundtrip requires IdP server running separately.
 */
@SpringBootTest
@AutoConfigureMockMvc
class OidcAuthorizeThenSamlAuthenticateTechnicalTest {

    @Autowired
    private MockMvc mockMvc;

    private static final String REGISTRATION_ID = "bet";

    @Test
    void http_flow_oidc_authorize_to_saml_authenticate_redirect() throws Exception {
        // GIVEN: OIDC authorize parameters
        Map<String, String> params = new HashMap<>();
        params.put("client_id", "example-client");
        params.put("response_type", "code");
        params.put("redirect_uri", "http://localhost:8081/callback");
        params.put("scope", "openid profile");
        params.put("state", "test-state-123");
        params.put("nonce", "test-nonce-456");
        
        String authorizeUrl = buildQueryString("/oauth2/authorize", params);

        // WHEN: Call authorize endpoint without authentication
        MvcResult result = mockMvc.perform(get(authorizeUrl))
            .andExpect(status().isFound())
            .andReturn();

        // THEN: Verify redirect to SAML endpoint
        String location = result.getResponse().getHeader("Location");
        assertThat(location)
            .contains("/saml2/authenticate/" + REGISTRATION_ID);
    }

    private String buildQueryString(String baseUrl, Map<String, String> params) {
        StringBuilder sb = new StringBuilder(baseUrl).append("?");
        params.forEach((k, v) -> sb.append(k).append("=").append(v).append("&"));
        return sb.toString().replaceFirst("&$", "");
    }
}
