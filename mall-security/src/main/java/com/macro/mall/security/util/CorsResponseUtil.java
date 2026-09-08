package com.macro.mall.security.util;

import com.macro.mall.security.config.CorsAllowedOriginsConfig;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * 认证失败、鉴权失败等由SpringSecurity直接返回的响应，
 * 不会经过全局跨域过滤器，需要按白名单补充跨域响应头
 * Created for CWE-942 remediation.
 */
public final class CorsResponseUtil {

    private CorsResponseUtil() {
    }

    /**
     * 请求来源在白名单中时写入跨域响应头，否则不写入任何跨域响应头
     */
    public static void applyAllowedOrigin(HttpServletRequest request,
                                          HttpServletResponse response,
                                          CorsAllowedOriginsConfig corsAllowedOriginsConfig) {
        if (corsAllowedOriginsConfig == null) {
            return;
        }
        String allowedOrigin = corsAllowedOriginsConfig.resolveAllowedOrigin(request.getHeader("Origin"));
        //写入前再次严格校验来源格式，含CR、LF等控制字符时不写入任何跨域响应头，
        //彻底避免响应头拆分（CWE-113）
        if (!CorsAllowedOriginsConfig.isValidOrigin(allowedOrigin)) {
            return;
        }
        response.setHeader("Access-Control-Allow-Origin", allowedOrigin);
        response.setHeader("Access-Control-Allow-Credentials", "true");
        response.addHeader("Vary", "Origin");
    }
}
