package com.example.sts.config;

import org.apache.cxf.Bus;
import org.apache.cxf.bus.spring.SpringBus;
import org.apache.cxf.jaxws.EndpointImpl;
import org.apache.cxf.transport.servlet.CXFServlet;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import com.example.sts.service.StsServiceImpl;

@Configuration
public class CxfConfig {
    
    @Bean
    public Bus cxfBus() {
        return new SpringBus();
    }
    
    @Bean
    public ServletRegistrationBean<CXFServlet> cxfServlet() {
        return new ServletRegistrationBean<>(new CXFServlet(), "/sts/*");
    }
    
    @Bean
    public EndpointImpl stsEndpoint(Bus cxfBus, StsServiceImpl stsService) {
        EndpointImpl endpoint = new EndpointImpl(cxfBus, stsService);
        endpoint.publish("/wss11x509");
        endpoint.getProperties().put("ws-security.validate.token", "false");
        return endpoint;
    }
}
