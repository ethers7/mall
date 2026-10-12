package com.macro.mall.security.component;

import com.macro.mall.security.config.CorsAllowedOriginsConfig;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * 跨域响应头工具类
 * 仅在请求的Origin命中可信域名白名单时才设置Access-Control-Allow-Origin响应头，
 * 避免返回通配符"*"或未经校验地回显任意来源域名（CWE-942：Permissive Cross-domain
 * Policy with Untrusted Domains）。未命中白名单（或未配置白名单）时不设置该响应头，
 * 即失败关闭（fail closed）。
 * Created by macro on 2026/10/12.
 */
public final class CorsOriginUtil {

    private CorsOriginUtil() {
    }

    public static void applyAllowedOrigin(HttpServletRequest request, HttpServletResponse response,
                                           CorsAllowedOriginsConfig corsAllowedOriginsConfig) {
        String origin = request.getHeader("Origin");
        if (origin == null || origin.isEmpty() || corsAllowedOriginsConfig == null) {
            return;
        }
        if (corsAllowedOriginsConfig.getAllowedOrigins().contains(origin)) {
            response.setHeader("Access-Control-Allow-Origin", origin);
            response.setHeader("Vary", "Origin");
        }
    }
}
