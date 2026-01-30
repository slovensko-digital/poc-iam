package com.example.sts.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

@Service
public class SamlTokenProvider {
    
    private static final Logger logger = LoggerFactory.getLogger(SamlTokenProvider.class);
    private static final String SAML2_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String SAML2_PROTOCOL_NS = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String BEARER_METHOD = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
    
    public String createSamlAssertion(String subjectName, String audienceUri, X509Certificate authCertificate) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.newDocument();
        
        // Create Assertion element
        Element assertion = doc.createElementNS(SAML2_NS, "saml2:Assertion");
        assertion.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:saml2", SAML2_NS);
        assertion.setAttribute("Version", "2.0");
        assertion.setAttribute("ID", "_" + UUID.randomUUID().toString());
        assertion.setAttribute("IssueInstant", DateTimeFormatter.ISO_INSTANT.format(Instant.now()));
        doc.appendChild(assertion);
        
        // Issuer
        Element issuer = doc.createElementNS(SAML2_NS, "saml2:Issuer");
        issuer.setTextContent("STS-Security-Token-Service");
        assertion.appendChild(issuer);
        
        // Subject
        Element subject = doc.createElementNS(SAML2_NS, "saml2:Subject");
        Element nameID = doc.createElementNS(SAML2_NS, "saml2:NameID");
        nameID.setAttribute("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName");
        nameID.setTextContent(subjectName);
        subject.appendChild(nameID);
        
        Element subjectConfirmation = doc.createElementNS(SAML2_NS, "saml2:SubjectConfirmation");
        subjectConfirmation.setAttribute("Method", BEARER_METHOD);
        Element subjectConfirmationData = doc.createElementNS(SAML2_NS, "saml2:SubjectConfirmationData");
        subjectConfirmationData.setAttribute("NotOnOrAfter", DateTimeFormatter.ISO_INSTANT.format(Instant.now().plusSeconds(3600)));
        subjectConfirmation.appendChild(subjectConfirmationData);
        subject.appendChild(subjectConfirmation);
        assertion.appendChild(subject);
        
        // Conditions
        Element conditions = doc.createElementNS(SAML2_NS, "saml2:Conditions");
        conditions.setAttribute("NotBefore", DateTimeFormatter.ISO_INSTANT.format(Instant.now()));
        conditions.setAttribute("NotOnOrAfter", DateTimeFormatter.ISO_INSTANT.format(Instant.now().plusSeconds(3600)));
        
        Element audienceRestriction = doc.createElementNS(SAML2_NS, "saml2:AudienceRestriction");
        Element audience = doc.createElementNS(SAML2_NS, "saml2:Audience");
        audience.setTextContent(audienceUri);
        audienceRestriction.appendChild(audience);
        conditions.appendChild(audienceRestriction);
        assertion.appendChild(conditions);
        
        // AuthnStatement
        Element authnStatement = doc.createElementNS(SAML2_NS, "saml2:AuthnStatement");
        authnStatement.setAttribute("AuthnInstant", DateTimeFormatter.ISO_INSTANT.format(Instant.now()));
        Element authnContext = doc.createElementNS(SAML2_NS, "saml2:AuthnContext");
        Element authnContextClassRef = doc.createElementNS(SAML2_NS, "saml2:AuthnContextClassRef");
        authnContextClassRef.setTextContent("urn:oasis:names:tc:SAML:2.0:ac:classes:X509");
        authnContext.appendChild(authnContextClassRef);
        authnStatement.appendChild(authnContext);
        assertion.appendChild(authnStatement);
        
        // Convert to string
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
        transformer.setOutputProperty(OutputKeys.METHOD, "xml");
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        
        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(doc), new StreamResult(writer));
        
        logger.info("SAML assertion created for subject: {}", subjectName);
        
        return writer.getBuffer().toString();
    }
}
