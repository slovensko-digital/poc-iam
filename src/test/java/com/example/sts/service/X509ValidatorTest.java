package com.example.sts.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class X509ValidatorTest {

    private X509Validator validator;

    // Valid self-signed test certificate (Base64 encoded, no line breaks)
    private static final String VALID_BASE64_CERT = "MIICxjCCAa6gAwIBAgIJAKqYwRKhRgXUMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMTBnRlc3RjYTAeFw0yNjAxMzAyMTQ1NTFaFw0yNzAxMzAyMTQ1NTFaMBExDzANBgNVBAMTBnRlc3RjYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALQTY3D8jPWd97A/DBjfsz0ut4e0NXdyObC1GU6FAbZrJZ3+3yYj2A0keeK5a/zbEzqoVGr6g2V0LUiL3hrgrvueLvYFL66H8iXoWlbzNl/pmpGDddO+wHmWFo1IXwC56leCD5AKUjQ/Jsmw5G0k7cA6nV3PJS9yWpMO4uyfFwuCY/1WamLskw00tmESg8OnZf93hLArg9AAT2k6/xY13YiyTEDI8XXeRihSn8eJims5kF/tnHWNhkO0tw/vSZy5rClponl8jymq9G8a49qnL5brWGHABjs/wei8+kVgUL9znscEO+i/72nGRXU6ChVoZV4iymZ9hf1vlqmSQox4IdMCAwEAAaMhMB8wHQYDVR0OBBYEFNqD8K/hFxNwkNT3g/BkI0WKScCIMA0GCSqGSIb3DQEBCwUAA4IBAQCJzR1qtYE2UraBiYMVXJ8fUhRndr1E3RTbXQLnUTdisWgmK2n7KwvQPe7LNVUR0T8dqXIs9lwJ/9/3uiR3ma7a4dheCJ/rh+4lzf6rFZrgrWSn+YSaQUrHXrnB13PTBQyV3c6tvI9fOoHa+J++bBrcbbzvwrKTmHYhyAiQ7dDDCUbVYr8ztn7C1dJUH/21AfS6swh6QKMuHbH+bICB/5GUgO5KHgibUHmMSWI9vrmAdGT9y+t9Bw2RC54uS4oYd6mPC+YKPsVXaaUtzfXjImVxnxMGj8PTMUkiAv4F5TGJxVB41/GXL5+BcY1BjOUib6BHiJ0VLEA810G4IO220h5Q";

    @BeforeEach
    void setUp() {
        validator = new X509Validator();
    }

    @Test
    void testParseCertificateFromBytes() throws Exception {
        byte[] certBytes = Base64.getDecoder().decode(VALID_BASE64_CERT);
        
        // This should parse successfully
        assertDoesNotThrow(() -> validator.parseCertificate(certBytes));
    }

    @Test
    void testParseCertificateFromPEM() throws Exception {
        String pemCert = "-----BEGIN CERTIFICATE-----\n" +
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
        
        X509Certificate cert = validator.parseCertificate(pemCert);
        assertNotNull(cert);
        assertEquals("CN=testca", cert.getSubjectX500Principal().getName());
    }

    @Test
    void testExtractAndValidateWithSoapMessage() throws Exception {
        // Create a simple SOAP message with BinarySecurityToken
        String soapMessage = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\"\n" +
            "               xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">\n" +
            "  <soap:Header>\n" +
            "    <wsse:Security soap:mustUnderstand=\"true\">\n" +
            "      <wsse:BinarySecurityToken EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\"\n" +
            "                                  ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\">\n" +
            VALID_BASE64_CERT + "\n" +
            "      </wsse:BinarySecurityToken>\n" +
            "    </wsse:Security>\n" +
            "  </soap:Header>\n" +
            "  <soap:Body>\n" +
            "    <test>Content</test>\n" +
            "  </soap:Body>\n" +
            "</soap:Envelope>";
        
        // With valid certificate, this should successfully extract and return the certificate
        X509Certificate result = validator.extractAndValidate(soapMessage);
        assertNotNull(result);
        assertEquals("CN=testca", result.getSubjectX500Principal().getName());
    }

    @Test
    void testExtractAndValidateWithNoCertificate() {
        String soapMessage = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\">\n" +
            "  <soap:Header>\n" +
            "  </soap:Header>\n" +
            "  <soap:Body>\n" +
            "    <test>Content</test>\n" +
            "  </soap:Body>\n" +
            "</soap:Envelope>";
        
        Exception exception = assertThrows(SecurityException.class, () -> {
            validator.extractAndValidate(soapMessage);
        });
        
        assertTrue(exception.getMessage().contains("No BinarySecurityToken found"));
    }
}
