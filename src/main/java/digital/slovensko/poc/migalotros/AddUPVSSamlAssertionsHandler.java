package digital.slovensko.poc.migalotros;

import org.apache.cxf.sts.token.provider.SamlCustomHandler;
import org.apache.cxf.sts.token.provider.TokenProviderParameters;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AttributeValue;

import java.util.List;

public class AddUPVSSamlAssertionsHandler implements SamlCustomHandler {

    private static final String ATTR_FORMAT = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";

    @Override
    public void handle(SamlAssertionWrapper assertionWrapper, TokenProviderParameters tokenParameters) {
        // TODO this is dummy implementation - change this to get real data from storage (ldap/redis...)

        if (assertionWrapper.getSaml2() != null) {
            // Create attribute statement using OpenSAML
            XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
            
            XMLObjectBuilder<AttributeStatement> attrStmtBuilder = 
                (XMLObjectBuilder<AttributeStatement>) builderFactory.getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);
            AttributeStatement attrStatement = attrStmtBuilder.buildObject(AttributeStatement.DEFAULT_ELEMENT_NAME);
            
            // Add all custom attributes
            addAttribute(attrStatement, builderFactory, "Actor.FormattedName", "T5000012544");
            addAttribute(attrStatement, builderFactory, "Actor.IdentityType", "3");
            addAttribute(attrStatement, builderFactory, "Actor.ThumbprintAC", "DFF786A922ED30A778BEDDAE0E90DABA6E4DBD1929AFE7DC6DA3A9B3C28DA740");
            addAttribute(attrStatement, builderFactory, "Actor.UPVSIdentityID", "153b554d-aafb-4367-badd-9b7a5bda6b6f");
            addAttribute(attrStatement, builderFactory, "Actor.Username", "T5000012544");
            
            addAttribute(attrStatement, builderFactory, "ActorID", "tech://T5000012544");
            addAttribute(attrStatement, builderFactory, "ActorIDSector", "SECTOR_UPVS");
            
            addAttribute(attrStatement, builderFactory, "AssertionType", "TECH");
            addAttribute(attrStatement, builderFactory, "DelegationType", "1");
            addAttribute(attrStatement, builderFactory, "DelegationMediatorID", "46178");
            addAttribute(attrStatement, builderFactory, "QAALevel", "3");
            
            addAttribute(attrStatement, builderFactory, "Subject.eDeskNumber", "E0005187331");
            addAttribute(attrStatement, builderFactory, "Subject.eDeskStatus", "DELIVERABLE");
            addAttribute(attrStatement, builderFactory, "Subject.Email", "test@slovensko.sk");
            addAttribute(attrStatement, builderFactory, "Subject.FormattedName", "Identita 83130041");
            addAttribute(attrStatement, builderFactory, "Subject.IdentityType", "2");
            addAttribute(attrStatement, builderFactory, "Subject.ICO", "83130041");
            addAttribute(attrStatement, builderFactory, "Subject.REIdentityId", "5189175");
            addAttribute(attrStatement, builderFactory, "Subject.UPVSIdentityID", "D665BE4F-10B3-4E2F-A1E3-9675479E8CE2");
            
            addAttribute(attrStatement, builderFactory, "SubjectID", "ico://sk/83130041");
            addAttribute(attrStatement, builderFactory, "SubjectIDSector", "SECTOR_UPVS");
            
            // Add multi-value Roles attribute
            List<String> roles = List.of(
                "R_IAM_PO",
                "GR_IAM_LEGAL_ENTITY",
                "R_UPVS_IAM_SVC_GETEDESKHISTORY",
                "R_UPVS_IAM_SVC_GETIDENTITY",
                "R_UPVS_IAM_SVC_GETEDESKINFO",
                "GR_IAM_TECHNICAL_USER_FOR_PO",
                "R_UPVS_IAM_SVC_GETCURRENTDELEGATION",
                "R_UPVS_IAM_SVC_GETDELEGATIONS",
                "R_UPVS_IAM_SVC_GETALLBUSINESSROLES",
                "R_UPVS_IAM_SVC_GETROLESFORIDENTITY",
                "GR_IAM_TECHNICAL_USER",
                "R_UPVS_IAM_SVC_ISIDENTITYINROLE",
                "R_UPVS_IAM_SVC_GETDELEGATIONDETAIL",
                "R_UPVS_IAM_SVC_ADDDELEGATIONTWOWAY"
            );
            addMultiValueAttribute(attrStatement, builderFactory, "Roles", roles);
            
            // Add the attribute statement to the assertion
            assertionWrapper.getSaml2().getAttributeStatements().add(attrStatement);
        }
    }
    
    private void addAttribute(AttributeStatement attrStatement, XMLObjectBuilderFactory builderFactory, 
                              String name, String value) {
        XMLObjectBuilder<Attribute> attrBuilder = 
            (XMLObjectBuilder<Attribute>) builderFactory.getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
        Attribute attribute = attrBuilder.buildObject(Attribute.DEFAULT_ELEMENT_NAME);
        attribute.setName(name);
        attribute.setNameFormat(ATTR_FORMAT);
        
        // Add value
        org.opensaml.core.xml.schema.XSString stringValue = 
            (org.opensaml.core.xml.schema.XSString) ((XMLObjectBuilder<?>) builderFactory
                .getBuilder(org.opensaml.core.xml.schema.XSString.TYPE_NAME))
                .buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, org.opensaml.core.xml.schema.XSString.TYPE_NAME);
        stringValue.setValue(value);
        attribute.getAttributeValues().add(stringValue);
        
        attrStatement.getAttributes().add(attribute);
    }
    
    private void addMultiValueAttribute(AttributeStatement attrStatement, XMLObjectBuilderFactory builderFactory,
                                        String name, List<String> values) {
        XMLObjectBuilder<Attribute> attrBuilder = 
            (XMLObjectBuilder<Attribute>) builderFactory.getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
        Attribute attribute = attrBuilder.buildObject(Attribute.DEFAULT_ELEMENT_NAME);
        attribute.setName(name);
        attribute.setNameFormat(ATTR_FORMAT);
        
        // Add all values
        for (String value : values) {
            org.opensaml.core.xml.schema.XSString stringValue = 
                (org.opensaml.core.xml.schema.XSString) ((XMLObjectBuilder<?>) builderFactory
                    .getBuilder(org.opensaml.core.xml.schema.XSString.TYPE_NAME))
                    .buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, org.opensaml.core.xml.schema.XSString.TYPE_NAME);
            stringValue.setValue(value);
            attribute.getAttributeValues().add(stringValue);
        }
        
        attrStatement.getAttributes().add(attribute);
    }
}
