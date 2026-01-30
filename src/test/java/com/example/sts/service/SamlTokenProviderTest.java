package com.example.sts.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class SamlTokenProviderTest {

    private SamlTokenProvider tokenProvider;

    @BeforeEach
    void setUp() {
        tokenProvider = new SamlTokenProvider();
    }

    @Test
    void testCreateSamlAssertion() throws Exception {
        String subjectName = "test-subject";
        String audienceUri = "https://example.com/service";
        
        // Create a mock certificate (null is acceptable for this test)
        String assertion = tokenProvider.createSamlAssertion(subjectName, audienceUri, null);
        
        assertNotNull(assertion);
        assertTrue(assertion.contains("<saml2:Assertion"));
        assertTrue(assertion.contains("Version=\"2.0\""));
        assertTrue(assertion.contains("test-subject"));
        assertTrue(assertion.contains("https://example.com/service"));
        assertTrue(assertion.contains("urn:oasis:names:tc:SAML:2.0:cm:bearer"));
        assertTrue(assertion.contains("urn:oasis:names:tc:SAML:2.0:ac:classes:X509"));
    }

    @Test
    void testCreateSamlAssertionWithIssuer() throws Exception {
        String subjectName = "client@example.com";
        String audienceUri = "https://service.example.com/api";
        
        String assertion = tokenProvider.createSamlAssertion(subjectName, audienceUri, null);
        
        assertTrue(assertion.contains("<saml2:Issuer>STS-Security-Token-Service</saml2:Issuer>"));
    }

    @Test
    void testCreateSamlAssertionWithConditions() throws Exception {
        String subjectName = "test-user";
        String audienceUri = "https://target.service.com";
        
        String assertion = tokenProvider.createSamlAssertion(subjectName, audienceUri, null);
        
        assertTrue(assertion.contains("<saml2:Conditions"));
        assertTrue(assertion.contains("NotBefore"));
        assertTrue(assertion.contains("NotOnOrAfter"));
        assertTrue(assertion.contains("<saml2:AudienceRestriction>"));
    }

    @Test
    void testCreateSamlAssertionWithAuthnStatement() throws Exception {
        String subjectName = "test-user";
        String audienceUri = "https://service.com";
        
        String assertion = tokenProvider.createSamlAssertion(subjectName, audienceUri, null);
        
        assertTrue(assertion.contains("<saml2:AuthnStatement"));
        assertTrue(assertion.contains("AuthnInstant"));
        assertTrue(assertion.contains("<saml2:AuthnContext>"));
        assertTrue(assertion.contains("urn:oasis:names:tc:SAML:2.0:ac:classes:X509"));
    }

    @Test
    void testSamlAssertionStructure() throws Exception {
        String subjectName = "CN=testuser,O=TestOrg";
        String audienceUri = "https://usr.upvsfixnew.gov.sk/ServiceBus/ServiceBusToken.svc";
        
        String assertion = tokenProvider.createSamlAssertion(subjectName, audienceUri, null);
        
        // Verify it's valid XML with proper structure
        assertTrue(assertion.contains("<?xml version"));
        assertTrue(assertion.contains("xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\""));
        assertTrue(assertion.contains("<saml2:Subject>"));
        assertTrue(assertion.contains("<saml2:NameID"));
        assertTrue(assertion.contains("Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName\""));
        assertTrue(assertion.contains("<saml2:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\""));
    }
}
