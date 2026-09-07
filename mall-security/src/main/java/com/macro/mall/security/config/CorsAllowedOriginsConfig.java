package com.macro.mall.security.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 跨域访问域名白名单配置
 * 默认为空，即不开启跨域访问，需要时通过secure.cors.allowed-origins显式配置具体域名
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "secure.cors")
public class CorsAllowedOriginsConfig {

    /**
     * 允许跨域携带的请求头
     */
    private static final List<String> ALLOWED_HEADERS = Arrays.asList(
            "Authorization", "Content-Type", "Accept", "Origin", "X-Requested-With");

    /**
     * 允许跨域调用的请求方法
     */
    private static final List<String> ALLOWED_METHODS = Arrays.asList(
            "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS");

    private List<String> allowedOrigins = new ArrayList<>();

    /**
     * 获取白名单中有效的域名，空白项及通配符会被忽略，避免配置错误导致对任意域名放行
     *
     * @return 白名单中的具体域名列表
     */
    public List<String> getEffectiveAllowedOrigins() {
        List<String> origins = new ArrayList<>();
        for (String allowedOrigin : allowedOrigins) {
            if (allowedOrigin == null) {
                continue;
            }
            String origin = allowedOrigin.trim();
            //忽略空白项与通配符，未配置具体域名时保持不开启跨域
            if (origin.isEmpty() || origin.contains("*")) {
                continue;
            }
            origins.add(origin);
        }
        return origins;
    }

    /**
     * 是否配置了具体的跨域访问域名白名单
     */
    public boolean hasAllowedOrigins() {
        return !getEffectiveAllowedOrigins().isEmpty();
    }

    /**
     * 根据白名单构建SpringSecurity使用的跨域配置，由框架的CORS过滤器统一写出跨域响应头
     *
     * @return 仅对白名单域名放行的跨域配置
     */
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        //仅允许白名单中配置的具体域名，不使用通配符也不回显请求头中的Origin
        config.setAllowedOrigins(getEffectiveAllowedOrigins());
        config.setAllowedMethods(ALLOWED_METHODS);
        config.setAllowedHeaders(ALLOWED_HEADERS);
        config.setAllowCredentials(true);
        config.setMaxAge(1800L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
