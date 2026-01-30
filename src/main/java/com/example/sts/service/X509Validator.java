package com.example.sts.service;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.crypto.SecretKey;
import javax.security.auth.callback.CallbackHandler;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.regex.Pattern;

@Service
public class X509Validator {
    
    private static final Logger logger = LoggerFactory.getLogger(X509Validator.class);
    private static final String WS_SECURITY_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    
    public X509Validator() {
    }
    
    public X509Certificate extractAndValidate(String soapMessage) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        
        Document document = builder.parse(new ByteArrayInputStream(soapMessage.getBytes()));
        
        // Extract BinarySecurityToken
        NodeList binaryTokens = document.getElementsByTagNameNS(WS_SECURITY_NS, "BinarySecurityToken");
        if (binaryTokens.getLength() == 0) {
            logger.error("No BinarySecurityToken found in SOAP message");
            throw new SecurityException("No BinarySecurityToken found");
        }
        
        Element tokenElement = (Element) binaryTokens.item(0);
        String base64Cert = tokenElement.getTextContent().trim();
        
        // Decode certificate
        byte[] certBytes = Base64.getDecoder().decode(base64Cert);
        X509Certificate certificate = parseCertificate(certBytes);
        
        // Validate certificate basic properties
        validateCertificate(certificate);
        
        logger.info("Certificate extracted and validated: {}", certificate.getSubjectX500Principal());
        
        return certificate;
    }
    
    public X509Certificate parseCertificate(byte[] certBytes) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
    }
    
    public X509Certificate parseCertificate(String pemCert) throws Exception {
        String cleanCert = pemCert.replaceAll("-----BEGIN CERTIFICATE-----", "")
                                  .replaceAll("-----END CERTIFICATE-----", "")
                                  .replaceAll("\\s", "");
        byte[] certBytes = Base64.getDecoder().decode(cleanCert);
        return parseCertificate(certBytes);
    }
    
    public void validateCertificate(X509Certificate certificate) throws Exception {
        // Check certificate validity period
        certificate.checkValidity();
        
        logger.info("Certificate validated for subject: {}", certificate.getSubjectX500Principal());
    }
}
