package com.example.sts.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RedisKeyStoreTest {

    @Mock
    private StringRedisTemplate redisTemplate;

    @Mock
    private ValueOperations<String, String> valueOperations;

    @InjectMocks
    private RedisKeyStore keyStore;

    // Valid self-signed test certificate (PEM format)
    private static final String VALID_PEM_CERT = "-----BEGIN CERTIFICATE-----\n" +
        "MIICxjCCAa6gAwIBAgIJAKqYwRKhRgXUMA0GCSqGSIb3DQEBCwUAMBExDzANBgNV\n" +
        "BAMTBnRlc3RjYTAeFw0yNjAxMzAyMTQ1NTFaFw0yNzAxMzAyMTQ1NTFaMBExDzAN\n" +
        "BgNVBAMTBnRlc3RjYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALQT\n" +
        "Y3D8jPWd97A/DBjfsz0ut4e0NXdyObC1GU6FAbZrJZ3+3yYj2A0keeK5a/zbEzqo\n" +
        "VGr6g2V0LUiL3hrgrvueLvYFL66H8iXoWlbzNl/pmpGDddO+wHmWFo1IXwC56leC\n" +
        "D5AKUjQ/Jsmw5G0k7cA6nV3PJS9yWpMO4uyfFwuCY/1WamLskw00tmESg8OnZf93\n" +
        "hLArg9AAT2k6/xY13YiyTEDI8XXeRihSn8eJims5kF/tnHWNhkO0tw/vSZy5rClp\n" +
        "onl8jymq9G8a49qnL5brWGHABjs/wei8+kVgUL9znscEO+i/72nGRXU6ChVoZV4i\n" +
        "ymZ9hf1vlqmSQox4IdMCAwEAAaMhMB8wHQYDVR0OBBYEFNqD8K/hFxNwkNT3g/Bk\n" +
        "I0WKScCIMA0GCSqGSIb3DQEBCwUAA4IBAQCJzR1qtYE2UraBiYMVXJ8fUhRndr1E\n" +
        "3RTbXQLnUTdisWgmK2n7KwvQPe7LNVUR0T8dqXIs9lwJ/9/3uiR3ma7a4dheCJ/r\n" +
        "h+4lzf6rFZrgrWSn+YSaQUrHXrnB13PTBQyV3c6tvI9fOoHa+J++bBrcbbzvwrKT\n" +
        "mHYhyAiQ7dDDCUbVYr8ztn7C1dJUH/21AfS6swh6QKMuHbH+bICB/5GUgO5KHgib\n" +
        "UHmMSWI9vrmAdGT9y+t9Bw2RC54uS4oYd6mPC+YKPsVXaaUtzfXjImVxnxMGj8PT\n" +
        "MUkiAv4F5TGJxVB41/GXL5+BcY1BjOUib6BHiJ0VLEA810G4IO220h5Q\n" +
        "-----END CERTIFICATE-----";

    @BeforeEach
    void setUp() {
        lenient().when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    }

    @Test
    void testStoreCertificate() {
        String clientId = "test-client";
        String pemCert = VALID_PEM_CERT;

        keyStore.storeCertificate(clientId, pemCert);

        verify(valueOperations).set(eq("sts:keys:test-client"), eq(pemCert), eq(1L), eq(TimeUnit.DAYS));
    }

    @Test
    void testGetCertificateNotFound() {
        String clientId = "non-existent-client";
        when(valueOperations.get("sts:keys:non-existent-client")).thenReturn(null);

        X509Certificate result = keyStore.getCertificate(clientId);

        assertNull(result);
    }

    @Test
    void testGetCertificateFound() {
        String clientId = "test-client";
        when(valueOperations.get("sts:keys:test-client")).thenReturn(VALID_PEM_CERT);

        X509Certificate result = keyStore.getCertificate(clientId);

        assertNotNull(result);
        assertEquals("CN=testca", result.getSubjectX500Principal().getName());
    }

    @Test
    void testValidateCertificateWithMatchingKeys() throws Exception {
        String clientId = "test-client";
        when(valueOperations.get("sts:keys:test-client")).thenReturn(VALID_PEM_CERT);

        // Parse the certificate to get the actual certificate object
        X509Certificate cert = keyStore.parseCertificate(VALID_PEM_CERT);
        assertNotNull(cert);

        // Validate that the certificate matches itself
        boolean result = keyStore.validateCertificate(clientId, cert);

        assertTrue(result);
    }

    @Test
    void testDeleteCertificate() {
        String clientId = "test-client";
        keyStore.deleteCertificate(clientId);
        verify(redisTemplate).delete("sts:keys:test-client");
    }
}
