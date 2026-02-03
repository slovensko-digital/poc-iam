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
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.HashMap;
import java.util.List;
import java.util.Properties;

@Configuration
public class STSConfiguration {

    public static final String SIGNING_PROPERTIES = "signingProperties";

    private final Bus bus;

    public STSConfiguration(Bus bus) {
        this.bus = bus;
    }

    // ---------------------------------------------------------------------
    // Signing properties
    // ---------------------------------------------------------------------

    @Bean(name = SIGNING_PROPERTIES)
    public Properties signingProperties(
            StringRedisTemplate redisTemplate,
            @Value("${sts.signing.crypto.provider}") String cryptoProvider,
            @Value("${sts.signing.keystore.type}") String keystoreType,
            @Value("${sts.signing.keystore.file}") String keystoreFile,
            @Value("${sts.signing.keystore.password}") String keystorePassword,
            @Value("${sts.signing.key.alias}") String keyAlias,
            @Value("${sts.signing.key.password}") String keyPassword
    ) {
        var props = new Properties();

        props.put("org.apache.wss4j.crypto.provider", cryptoProvider);
        props.put("org.apache.wss4j.crypto.merlin.keystore.type", keystoreType);
        props.put("org.apache.wss4j.crypto.merlin.keystore.file", keystoreFile);
        props.put("org.apache.wss4j.crypto.merlin.keystore.password", keystorePassword);
        props.put("org.apache.wss4j.crypto.merlin.keystore.private.password", keyPassword);
        props.put("org.apache.wss4j.crypto.merlin.keystore.alias", keyAlias);

        props.put(RedisCertValidator.REDIS_TEMPLATE_REF, redisTemplate);
        return props;
    }

    // ---------------------------------------------------------------------
    // STS properties
    // ---------------------------------------------------------------------

    @Bean
    public StaticSTSProperties stsProperties(
            @Qualifier(SIGNING_PROPERTIES) Properties signingProperties,
            @Value("${sts.issuer}") String issuer,
            @Value("${sts.signing.key.alias}") String keyAlias
    ) {
        var props = new StaticSTSProperties();
        props.setSignatureCryptoProperties(signingProperties);
        props.setSignatureUsername(keyAlias);
        props.setIssuer(issuer);
        return props;
    }

    // ---------------------------------------------------------------------
    // Services
    // ---------------------------------------------------------------------

    @Bean
    public StaticService eksService(@Value("${sts.service.eks.endpoint}") String endpoint) {
        var svc = new StaticService();
        svc.setEndpoints(List.of(endpoint));
        return svc;
    }

    // ---------------------------------------------------------------------
    // Issue operation
    // ---------------------------------------------------------------------

    @Bean
    public TokenIssueOperation issueDelegate(StaticService eksService, StaticSTSProperties stsProperties) {
        var issue = new TokenIssueOperation();

        var samlProvider = new SAMLTokenProvider();
        samlProvider.setSamlCustomHandler(new AddUPVSSamlAssertionsHandler());

        issue.setTokenProviders(List.of(samlProvider));
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

    // ---------------------------------------------------------------------
    // WSS4J interceptors
    // ---------------------------------------------------------------------

    @Bean
    public WSS4JInInterceptor stsWss4jInInterceptor(
            @Qualifier(SIGNING_PROPERTIES) Properties signingProperties,
            @Value("${sts.wss4j.in.bsp-compliant}") boolean bspCompliant,
            @Value("${sts.wss4j.in.timestamp.strict}") boolean timestampStrict,
            @Value("${sts.wss4j.in.ttl}") String ttl,
            @Value("${sts.wss4j.in.ttl-future}") String ttlFuture
    ) {
        var props = new HashMap<String, Object>();

        props.put(ConfigurationConstants.ACTION,
                ConfigurationConstants.SIGNATURE + " " + ConfigurationConstants.TIMESTAMP);

        props.put(SIGNING_PROPERTIES, signingProperties);
        props.put(ConfigurationConstants.SIG_PROP_REF_ID, SIGNING_PROPERTIES);
        props.put(ConfigurationConstants.IS_BSP_COMPLIANT, String.valueOf(bspCompliant));
        props.put(ConfigurationConstants.TIMESTAMP_STRICT, String.valueOf(timestampStrict));
        props.put(ConfigurationConstants.TTL_TIMESTAMP, ttl);
        props.put(ConfigurationConstants.TTL_FUTURE_TIMESTAMP, ttlFuture);

        return new WSS4JInInterceptor(props);
    }

    @Bean
    public WSS4JOutInterceptor stsWss4jOutInterceptor(
            @Value("${sts.wss4j.out.ttl}") String ttl
    ) {
        var props = new HashMap<String, Object>();
        props.put(WSHandlerConstants.ACTION, WSHandlerConstants.TIMESTAMP);
        props.put(WSHandlerConstants.TTL_TIMESTAMP, ttl);
        return new WSS4JOutInterceptor(props);
    }

    // ---------------------------------------------------------------------
    // Endpoint
    // ---------------------------------------------------------------------

    @Bean
    public jakarta.xml.ws.Endpoint stsEndpoint(
            SecurityTokenServiceProvider stsProviderBean,
            WSS4JInInterceptor inInterceptor,
            WSS4JOutInterceptor outInterceptor,
            @Value("${sts.endpoint.path}") String path
    ) {
        var endpoint = new EndpointImpl(bus, stsProviderBean);
        endpoint.setBindingUri("http://www.w3.org/2003/05/soap/bindings/HTTP/");
        endpoint.getFeatures().add(new WSAddressingFeature());
        endpoint.getInInterceptors().add(inInterceptor);
        endpoint.getOutInterceptors().add(outInterceptor);
        endpoint.publish(path);
        return endpoint;
    }
}


