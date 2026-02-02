package digital.slovensko.poc.migalotros;

import org.apache.cxf.Bus;
import org.apache.cxf.jaxws.EndpointImpl;
import org.apache.cxf.sts.StaticSTSProperties;
import org.apache.cxf.sts.operation.TokenIssueOperation;
import org.apache.cxf.sts.service.StaticService;
import org.apache.cxf.sts.token.provider.SAMLTokenProvider;
import org.apache.cxf.ws.security.sts.provider.SecurityTokenServiceProvider;
import org.apache.cxf.ws.security.wss4j.WSS4JInInterceptor;
import org.apache.wss4j.common.ConfigurationConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;

@Configuration
public class STSConfiguration {

    @Autowired
    private Bus bus;

    @Bean
    public StaticSTSProperties stsProperties() {
        var props = new StaticSTSProperties();
        props.setSignatureCryptoProperties("stsstore.properties");
        props.setSignatureUsername("stskey");
        props.setIssuer("DigitalSlovenskoSTS");
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
        issue.setTokenProviders(List.of(new SAMLTokenProvider()));
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
    public WSS4JInInterceptor stsWss4jInInterceptor() {
        var inProps = new HashMap<String, Object>();

        // Skip signature verification by not processing the Signature action
         inProps.put(ConfigurationConstants.ACTION, ConfigurationConstants.SIGNATURE + " " + ConfigurationConstants.TIMESTAMP);
//        inProps.put(ConfigurationConstants.ACTION, ConfigurationConstants.TIMESTAMP);

        inProps.put(ConfigurationConstants.SIG_PROP_FILE, "stsstore.properties");
        inProps.put(ConfigurationConstants.IS_BSP_COMPLIANT, "false");

        // DEBUG onlu - disable strict Timestamp expiry handling and relax range checks
        inProps.put(ConfigurationConstants.TIMESTAMP_STRICT, "false");
        inProps.put(ConfigurationConstants.TTL_TIMESTAMP, "14400"); // allow up to 4h old
        inProps.put(ConfigurationConstants.TTL_FUTURE_TIMESTAMP, "600"); // allow 10 min in the future

        // a replay-cache instance is used in this implementation,
        // it needs to be implemented differently if scaling across multiple instances
        // @see org.apache.wss4j.dom.processor.SignatureProcessor.testMessageReplay
        return new WSS4JInInterceptor(inProps);
    }

    /**
     * Publish the STS endpoint at /STS, SOAP 1.2 HTTP binding.
     * <p>
     * Equivalent to XML configuration:
     * <jaxws:endpoint id="stsEndpoint" implementor="#stsProviderBean" address="/STS" bindingUri="http://www.w3.org/2003/05/soap/bindings/HTTP/">
     * <jaxws:inInterceptors>...</jaxws:inInterceptors>
     * </jaxws:endpoint>
     */
    @Bean
    public jakarta.xml.ws.Endpoint stsEndpoint(SecurityTokenServiceProvider stsProviderBean, WSS4JInInterceptor stsWss4jInInterceptor) {
        var endpoint = new EndpointImpl(bus, stsProviderBean);
        endpoint.setBindingUri("http://www.w3.org/2003/05/soap/bindings/HTTP/");
        endpoint.setInInterceptors(Collections.singletonList(stsWss4jInInterceptor));
        endpoint.publish("/STS");
        return endpoint;
    }

}
