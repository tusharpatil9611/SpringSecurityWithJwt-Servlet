package com.unoveo.securityjwt.securityconfig;

import com.unoveo.securityjwt.WebSecurityConfig;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;

@Configuration
public class SecurityWebAppInitializer  extends AbstractSecurityWebApplicationInitializer {

   public SecurityWebAppInitializer(){
       super(WebSecurityConfig.class);
    }
    @Override
    protected boolean enableHttpSessionEventPublisher() {
        return true;
    }
}
