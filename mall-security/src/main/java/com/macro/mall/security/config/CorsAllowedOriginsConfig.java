package com.macro.mall.security.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfiguration;

import java.util.ArrayList;
import java.util.List;

/**
 * 跨域来源白名单配置，用于Security异常响应中的跨域响应头
 * 只有命中白名单的来源才会被写入响应头，白名单为空时不返回跨域响应头（仅允许同源访问）
 * Created by macro on 2018/5/14.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "secure.cors")
public class CorsAllowedOriginsConfig {

    /**
     * 允许跨域访问的前端来源白名单，如：https://admin.example.com
     */
    private List<String> allowedOrigins = new ArrayList<>();

    /**
     * 仅当请求来源命中白名单时写入跨域响应头，避免使用通配符或回显任意来源
     */
    public void applyAllowedOrigin(HttpServletRequest request, HttpServletResponse response) {
        response.setHeader(HttpHeaders.VARY, HttpHeaders.ORIGIN);
        String allowedOrigin = resolveAllowedOrigin(request.getHeader(HttpHeaders.ORIGIN));
        if (allowedOrigin != null) {
            response.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, allowedOrigin);
        }
    }

    /**
     * 校验请求来源，命中白名单时返回该来源，否则返回null
     *
     * @param origin 请求头中的Origin
     */
    public String resolveAllowedOrigin(String origin) {
        if (!StringUtils.hasText(origin) || CollectionUtils.isEmpty(allowedOrigins)) {
            return null;
        }
        CorsConfiguration configuration = new CorsConfiguration();
        for (String allowedOrigin : allowedOrigins) {
            //忽略通配符配置，防止任意域名跨域访问
            if (StringUtils.hasText(allowedOrigin) && !CorsConfiguration.ALL.equals(allowedOrigin.trim())) {
                configuration.addAllowedOrigin(allowedOrigin.trim());
            }
        }
        if (CollectionUtils.isEmpty(configuration.getAllowedOrigins())) {
            return null;
        }
        return configuration.checkOrigin(origin);
    }

}
