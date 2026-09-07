package com.macro.mall.config;

import com.macro.mall.security.config.AllowedOriginsCorsConfigurationSource;
import com.macro.mall.security.config.CorsAllowedOriginsConfig;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.CorsFilter;

/**
 * 全局跨域配置
 * Created by macro on 2019/7/27.
 */
@Configuration
public class GlobalCorsConfig {

    /**
     * 允许跨域调用的过滤器
     * 只对来源白名单(secure.cors.allowed-origins)内的来源开放跨域及跨域携带cookie，
     * 白名单为空时不开放跨域访问，同源请求和不带Origin的请求不受影响
     */
    @Bean
    public CorsFilter corsFilter(CorsAllowedOriginsConfig corsAllowedOriginsConfig) {
        return new CorsFilter(new AllowedOriginsCorsConfigurationSource(corsAllowedOriginsConfig));
    }
}
