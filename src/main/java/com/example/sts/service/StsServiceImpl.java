package com.example.sts.service;

import jakarta.jws.WebMethod;
import jakarta.jws.WebParam;
import jakarta.jws.WebResult;
import jakarta.jws.WebService;
import jakarta.jws.soap.SOAPBinding;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.Marshaller;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.ws.BindingType;
import jakarta.xml.ws.soap.Addressing;
import org.apache.cxf.headers.Header;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.jaxws.context.WrappedMessageContext;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.PhaseInterceptorChain;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

@WebService(targetNamespace = "http://docs.oasis-open.org/ws-sx/ws-trust/200512")
@SOAPBinding(parameterStyle = SOAPBinding.ParameterStyle.BARE)
@BindingType(value = jakarta.xml.ws.soap.SOAPBinding.SOAP12HTTP_BINDING)
@Addressing(enabled = true, required = true)
@Service
public class StsServiceImpl {
    
    private static final Logger logger = LoggerFactory.getLogger(StsServiceImpl.class);
    private static final String WS_TRUST_NS = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
    private static final String WS_SECURITY_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    private static final String SAML2_TOKEN_TYPE = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
    private static final String BEARER_KEY_TYPE = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer";
    
    @Autowired
    private RedisKeyStore keyStore;
    
    @Autowired
    private X509Validator x509Validator;
    
    @Autowired
    private SamlTokenProvider samlTokenProvider;
    
    @WebMethod(operationName = "RequestSecurityToken")
    @WebResult(name = "RequestSecurityTokenResponse", targetNamespace = WS_TRUST_NS)
    public RequestSecurityTokenResponse requestSecurityToken(
            @WebParam(name = "RequestSecurityToken", targetNamespace = WS_TRUST_NS)
            RequestSecurityToken request) throws Exception {
        
        logger.info("Received STS request");
        
        // Extract and validate X509 signature from SOAP header
        Message message = PhaseInterceptorChain.getCurrentMessage();
        X509Certificate clientCert = extractAndValidateCertificate(message);
        
        if (clientCert == null) {
            throw new SecurityException("No valid X509 certificate found in request");
        }
        
        // Get client ID from certificate
        String clientId = extractClientId(clientCert);
        
        // Validate certificate against Redis
        if (!keyStore.validateCertificate(clientId, clientCert)) {
            throw new SecurityException("Certificate not found or invalid in key store");
        }
        
        logger.info("Certificate validated for client: {}", clientId);
        
        // Extract applies to (target service)
        String appliesTo = extractAppliesTo(request);
        
        // Generate SAML token
        String samlAssertion = samlTokenProvider.createSamlAssertion(clientId, appliesTo, clientCert);
        
        // Build response
        RequestSecurityTokenResponse response = new RequestSecurityTokenResponse();
        response.setTokenType(SAML2_TOKEN_TYPE);
        response.setRequestedSecurityToken(samlAssertion);
        response.setLifetime(createLifetime());
        
        logger.info("STS request processed successfully for client: {}", clientId);
        
        return response;
    }
    
    private X509Certificate extractAndValidateCertificate(Message message) throws Exception {
        if (message == null) {
            return null;
        }
        
        WrappedMessageContext wmc = new WrappedMessageContext(message);
        List<Header> headers = (List<Header>) wmc.get(Message.PROTOCOL_HEADERS);
        
        if (headers == null) {
            // Try to get from SOAP envelope
            return extractFromSOAPBody(message);
        }
        
        for (Header header : headers) {
            if ("Security".equals(header.getName().getLocalPart())) {
                Element securityHeader = (Element) header.getObject();
                return extractCertificateFromSecurityHeader(securityHeader);
            }
        }
        
        return null;
    }
    
    private X509Certificate extractFromSOAPBody(Message message) throws Exception {
        // Fallback: parse the incoming SOAP message directly
        String soapMessage = message.getContent(String.class);
        if (soapMessage == null) {
            return null;
        }
        
        return x509Validator.extractAndValidate(soapMessage);
    }
    
    private X509Certificate extractCertificateFromSecurityHeader(Element securityHeader) throws Exception {
        NodeList binaryTokens = securityHeader.getElementsByTagNameNS(WS_SECURITY_NS, "BinarySecurityToken");
        if (binaryTokens.getLength() == 0) {
            return null;
        }
        
        Element tokenElement = (Element) binaryTokens.item(0);
        String base64Cert = tokenElement.getTextContent().trim();
        
        byte[] certBytes = Base64.getDecoder().decode(base64Cert);
        return x509Validator.parseCertificate(certBytes);
    }
    
    private String extractClientId(X509Certificate cert) {
        String dn = cert.getSubjectX500Principal().getName();
        // Extract CN or other identifier from DN
        if (dn.contains("CN=")) {
            int start = dn.indexOf("CN=") + 3;
            int end = dn.indexOf(",", start);
            if (end == -1) end = dn.length();
            return dn.substring(start, end).trim();
        }
        return dn;
    }
    
    private String extractAppliesTo(RequestSecurityToken request) {
        if (request.getAppliesTo() != null && request.getAppliesTo().getEndpointReference() != null) {
            return request.getAppliesTo().getEndpointReference().getAddress();
        }
        return "https://default.service.com";
    }
    
    private Lifetime createLifetime() {
        Lifetime lifetime = new Lifetime();
        Instant now = Instant.now();
        lifetime.setCreated(now.toString());
        lifetime.setExpires(now.plus(1, ChronoUnit.HOURS).toString());
        return lifetime;
    }
    
    // JAXB Data Classes
    
    @XmlRootElement(name = "RequestSecurityToken", namespace = WS_TRUST_NS)
    @XmlAccessorType(XmlAccessType.FIELD)
    public static class RequestSecurityToken {
        @XmlElement(name = "SecondaryParameters", namespace = WS_TRUST_NS)
        private SecondaryParameters secondaryParameters;
        
        @XmlElement(name = "RequestType", namespace = WS_TRUST_NS)
        private String requestType;
        
        @XmlElement(name = "AppliesTo", namespace = "http://schemas.xmlsoap.org/ws/2004/09/policy")
        private AppliesTo appliesTo;
        
        public SecondaryParameters getSecondaryParameters() { return secondaryParameters; }
        public void setSecondaryParameters(SecondaryParameters secondaryParameters) { this.secondaryParameters = secondaryParameters; }
        public String getRequestType() { return requestType; }
        public void setRequestType(String requestType) { this.requestType = requestType; }
        public AppliesTo getAppliesTo() { return appliesTo; }
        public void setAppliesTo(AppliesTo appliesTo) { this.appliesTo = appliesTo; }
    }
    
    @XmlAccessorType(XmlAccessType.FIELD)
    public static class SecondaryParameters {
        @XmlElement(name = "TokenType", namespace = WS_TRUST_NS)
        private String tokenType;
        @XmlElement(name = "KeyType", namespace = WS_TRUST_NS)
        private String keyType;
        
        public String getTokenType() { return tokenType; }
        public void setTokenType(String tokenType) { this.tokenType = tokenType; }
        public String getKeyType() { return keyType; }
        public void setKeyType(String keyType) { this.keyType = keyType; }
    }
    
    @XmlAccessorType(XmlAccessType.FIELD)
    public static class AppliesTo {
        @XmlElement(name = "EndpointReference", namespace = "http://www.w3.org/2005/08/addressing")
        private EndpointReference endpointReference;
        
        public EndpointReference getEndpointReference() { return endpointReference; }
        public void setEndpointReference(EndpointReference endpointReference) { this.endpointReference = endpointReference; }
    }
    
    @XmlAccessorType(XmlAccessType.FIELD)
    public static class EndpointReference {
        @XmlElement(name = "Address", namespace = "http://www.w3.org/2005/08/addressing")
        private String address;
        
        public String getAddress() { return address; }
        public void setAddress(String address) { this.address = address; }
    }
    
    @XmlRootElement(name = "RequestSecurityTokenResponse", namespace = WS_TRUST_NS)
    @XmlAccessorType(XmlAccessType.FIELD)
    public static class RequestSecurityTokenResponse {
        @XmlElement(name = "TokenType", namespace = WS_TRUST_NS)
        private String tokenType;
        
        @XmlElement(name = "RequestedSecurityToken", namespace = WS_TRUST_NS)
        private String requestedSecurityToken;
        
        @XmlElement(name = "Lifetime", namespace = WS_TRUST_NS)
        private Lifetime lifetime;
        
        public String getTokenType() { return tokenType; }
        public void setTokenType(String tokenType) { this.tokenType = tokenType; }
        public String getRequestedSecurityToken() { return requestedSecurityToken; }
        public void setRequestedSecurityToken(String requestedSecurityToken) { this.requestedSecurityToken = requestedSecurityToken; }
        public Lifetime getLifetime() { return lifetime; }
        public void setLifetime(Lifetime lifetime) { this.lifetime = lifetime; }
    }
    
    @XmlAccessorType(XmlAccessType.FIELD)
    public static class Lifetime {
        @XmlElement(name = "Created", namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd")
        private String created;
        @XmlElement(name = "Expires", namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd")
        private String expires;
        
        public String getCreated() { return created; }
        public void setCreated(String created) { this.created = created; }
        public String getExpires() { return expires; }
        public void setExpires(String expires) { this.expires = expires; }
    }
}
