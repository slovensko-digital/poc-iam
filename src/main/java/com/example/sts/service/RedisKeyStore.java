package com.example.sts.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

@Service
public class RedisKeyStore {
    
    private static final Logger logger = LoggerFactory.getLogger(RedisKeyStore.class);
    private static final String KEY_PREFIX = "sts:keys:";
    
    @Autowired
    private StringRedisTemplate redisTemplate;
    
    public void storeCertificate(String clientId, String pemCertificate) {
        String key = KEY_PREFIX + clientId;
        redisTemplate.opsForValue().set(key, pemCertificate, 1, TimeUnit.DAYS);
        logger.info("Stored certificate for client: {}", clientId);
    }
    
    public X509Certificate getCertificate(String clientId) {
        String key = KEY_PREFIX + clientId;
        String pemCert = redisTemplate.opsForValue().get(key);
        
        if (pemCert == null) {
            logger.warn("Certificate not found for client: {}", clientId);
            return null;
        }
        
        try {
            return parseCertificate(pemCert);
        } catch (Exception e) {
            logger.error("Failed to parse certificate for client: {}", clientId, e);
            return null;
        }
    }
    
    public boolean validateCertificate(String clientId, X509Certificate providedCert) {
        X509Certificate storedCert = getCertificate(clientId);
        
        if (storedCert == null) {
            return false;
        }
        
        try {
            // Compare certificates by public key
            return storedCert.getPublicKey().equals(providedCert.getPublicKey()) &&
                   storedCert.getSubjectX500Principal().equals(providedCert.getSubjectX500Principal());
        } catch (Exception e) {
            logger.error("Certificate validation failed for client: {}", clientId, e);
            return false;
        }
    }
    
    public X509Certificate parseCertificate(String pemCert) throws Exception {
        // Remove PEM headers and whitespace
        String cleanCert = pemCert.replaceAll("-----BEGIN CERTIFICATE-----", "")
                                  .replaceAll("-----END CERTIFICATE-----", "")
                                  .replaceAll("\\s", "");
        
        byte[] certBytes = Base64.getDecoder().decode(cleanCert);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(new java.io.ByteArrayInputStream(certBytes));
    }
    
    public X509Certificate parseCertificate(byte[] certBytes) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(new java.io.ByteArrayInputStream(certBytes));
    }
    
    public void deleteCertificate(String clientId) {
        redisTemplate.delete(KEY_PREFIX + clientId);
        logger.info("Deleted certificate for client: {}", clientId);
    }
}
