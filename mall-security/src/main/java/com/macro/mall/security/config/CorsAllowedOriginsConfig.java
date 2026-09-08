package com.macro.mall.security.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * 跨域访问来源白名单配置
 * 未配置时不返回跨域响应头，避免不受信任的域名读取响应内容
 * Created for CWE-942 remediation.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "secure.cors")
public class CorsAllowedOriginsConfig {

    /**
     * 允许跨域访问的来源，如：https://admin.example.com
     * 出于安全考虑不支持通配符配置
     */
    private List<String> allowedOrigins = new ArrayList<>();

    /**
     * 校验请求来源是否在白名单中
     *
     * @param requestOrigin 请求头中的Origin
     * @return 白名单中配置的来源，不在白名单中时返回null
     */
    public String resolveAllowedOrigin(String requestOrigin) {
        if (requestOrigin == null || requestOrigin.isBlank()) {
            return null;
        }
        String origin = requestOrigin.trim();
        for (String allowedOrigin : allowedOrigins) {
            if (allowedOrigin == null || allowedOrigin.isBlank() || "*".equals(allowedOrigin.trim())) {
                //忽略通配符及空配置，避免向任意域名开放
                continue;
            }
            if (allowedOrigin.trim().equalsIgnoreCase(origin)) {
                return allowedOrigin.trim();
            }
        }
        return null;
    }
}
