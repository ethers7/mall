package com.macro.mall.security.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * 跨域访问域名白名单配置
 * 默认为空，即不允许任何跨域来源，需要时通过secure.cors.allowed-origins显式配置
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "secure.cors")
public class CorsAllowedOriginsConfig {

    private List<String> allowedOrigins = new ArrayList<>();

    /**
     * 校验请求来源是否在白名单中
     *
     * @param requestOrigin 请求头中的Origin
     * @return 白名单中匹配到的域名，未匹配时返回null
     */
    public String resolveAllowedOrigin(String requestOrigin) {
        if (requestOrigin == null || requestOrigin.trim().isEmpty()) {
            return null;
        }
        String origin = requestOrigin.trim();
        for (String allowedOrigin : allowedOrigins) {
            if (allowedOrigin != null && allowedOrigin.equalsIgnoreCase(origin)) {
                //返回配置中的域名而非请求头内容，避免直接回显不可信输入
                return allowedOrigin;
            }
        }
        return null;
    }
}
