package digital.slovensko.poc.migalotros;

import org.apache.cxf.Bus;
import org.apache.cxf.jaxws.EndpointImpl;
import org.apache.cxf.sts.StaticSTSProperties;
import org.apache.cxf.sts.operation.TokenIssueOperation;
import org.apache.cxf.sts.service.StaticService;
import org.apache.cxf.sts.token.provider.SAMLTokenProvider;
import org.apache.cxf.ws.addressing.WSAddressingFeature;
import org.apache.cxf.ws.security.sts.provider.SecurityTokenServiceProvider;
import org.apache.cxf.ws.security.wss4j.WSS4JInInterceptor;
import org.apache.cxf.ws.security.wss4j.WSS4JOutInterceptor;
import org.apache.wss4j.common.ConfigurationConstants;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;

@Configuration
public class STSConfiguration {

    public static final String SIGNING_PROPERTIES = "signingProperties";

    @Autowired
    private Bus bus;

    @Bean(name = SIGNING_PROPERTIES)
    public Properties signingProperties(StringRedisTemplate stringRedisTemplate) {
        var properties = new Properties();
        properties.put("org.apache.wss4j.crypto.provider", "digital.slovensko.poc.migalotros.RedisCertValidator");
        properties.put("org.apache.wss4j.crypto.merlin.keystore.type", "jks");
        properties.put("org.apache.wss4j.crypto.merlin.keystore.password", "changeit");
        properties.put("org.apache.wss4j.crypto.merlin.keystore.private.password", "changeit");
        properties.put("org.apache.wss4j.crypto.merlin.keystore.alias", "stskey");
        properties.put("org.apache.wss4j.crypto.merlin.keystore.file", "stsstore.jks");
        properties.put(RedisCertValidator.REDIS_TEMPLATE_REF, stringRedisTemplate);
        return properties;
    }

    @Bean
    public StaticSTSProperties stsProperties(@Qualifier(SIGNING_PROPERTIES) Properties signingProperties) {
        var props = new StaticSTSProperties();
        props.setSignatureCryptoProperties(signingProperties);
        props.setSignatureUsername("stskey");
        props.setIssuer("iamsts.upvsfix.local");
        return props;
    }

    @Bean
    public StaticService eksService() {
        var svc = new StaticService();
        svc.setEndpoints(List.of("https://eschranka.upvsfixnew.gov.sk/EKSService.svc"));
        return svc;
    }

    @Bean
    public TokenIssueOperation issueDelegate(StaticService eksService, StaticSTSProperties stsProperties) {
        var issue = new TokenIssueOperation();

        // Create SAML token provider with custom handler
        var samlTokenProvider = new SAMLTokenProvider();
        samlTokenProvider.setSamlCustomHandler(new AddUPVSSamlAssertionsHandler());

        issue.setTokenProviders(List.of(samlTokenProvider));
        issue.setServices(List.of(eksService));
        issue.setStsProperties(stsProperties);
        return issue;
    }

    @Bean
    public SecurityTokenServiceProvider stsProviderBean(TokenIssueOperation issueDelegate) throws Exception {
        var provider = new SecurityTokenServiceProvider();
        provider.setIssueOperation(issueDelegate);
        return provider;
    }

    @Bean
    public WSS4JInInterceptor stsWss4jInInterceptor(Properties signingProperties) {
        var inProps = new HashMap<String, Object>();

        inProps.put(ConfigurationConstants.ACTION, ConfigurationConstants.SIGNATURE + " " + ConfigurationConstants.TIMESTAMP);
        inProps.put(SIGNING_PROPERTIES, signingProperties);
        inProps.put(ConfigurationConstants.SIG_PROP_REF_ID, SIGNING_PROPERTIES);
        inProps.put(ConfigurationConstants.IS_BSP_COMPLIANT, "false");

        // DEBUG only - disable strict Timestamp expiry handling and relax range checks
        inProps.put(ConfigurationConstants.TIMESTAMP_STRICT, "false");
        inProps.put(ConfigurationConstants.TTL_TIMESTAMP, "144000000"); // allow up to 4h old
        inProps.put(ConfigurationConstants.TTL_FUTURE_TIMESTAMP, "600000000"); // allow 10 min in the future

        // a replay-cache instance is used in this implementation,
        // it needs to be implemented differently if scaling across multiple instances
        // @see org.apache.wss4j.dom.processor.SignatureProcessor.testMessageReplay
        return new WSS4JInInterceptor(inProps);
    }

    @Bean
    public WSS4JOutInterceptor stsWss4jOutInterceptor() {
        var props = new HashMap<String, Object>();

        props.put(WSHandlerConstants.ACTION, WSHandlerConstants.TIMESTAMP);
        props.put(WSHandlerConstants.TTL_TIMESTAMP, "3600");

        return new WSS4JOutInterceptor(props);
    }

    @Bean
    public jakarta.xml.ws.Endpoint stsEndpoint(SecurityTokenServiceProvider stsProviderBean, WSS4JInInterceptor stsWss4jInInterceptor, WSS4JOutInterceptor stsWss4jOutInterceptor) {
        var endpoint = new EndpointImpl(bus, stsProviderBean);
        endpoint.setBindingUri("http://www.w3.org/2003/05/soap/bindings/HTTP/");
        endpoint.getFeatures().add(new WSAddressingFeature());
        endpoint.setInInterceptors(Collections.singletonList(stsWss4jInInterceptor));
        endpoint.setOutInterceptors(Collections.singletonList(stsWss4jOutInterceptor));
        endpoint.publish("/STS");
        return endpoint;
    }
}
