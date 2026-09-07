package com.macro.mall.security.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.Nullable;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

/**
 * 基于来源白名单(secure.cors.allowed-origins)的全局跨域配置
 * 只有命中白名单的来源才会得到跨域配置，且只回显校验通过的来源，不使用通配符
 * 未命中白名单时不返回跨域配置：不写入任何跨域响应头，浏览器会拦截该跨域读取，
 * 预检请求由Spring按无跨域配置处理；同源请求及不带Origin的非浏览器请求不受影响
 * Created by macro on 2019/7/27.
 */
public class AllowedOriginsCorsConfigurationSource implements CorsConfigurationSource {

    private final CorsAllowedOriginsConfig corsAllowedOriginsConfig;

    public AllowedOriginsCorsConfigurationSource(CorsAllowedOriginsConfig corsAllowedOriginsConfig) {
        this.corsAllowedOriginsConfig = corsAllowedOriginsConfig;
    }

    @Nullable
    @Override
    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
        String allowedOrigin = corsAllowedOriginsConfig.resolveAllowedOrigin(request.getHeader(HttpHeaders.ORIGIN));
        if (allowedOrigin == null) {
            //白名单为空或来源未命中白名单时不开放跨域访问
            return null;
        }
        CorsConfiguration configuration = new CorsConfiguration();
        //只允许校验通过的单个来源，避免通配符或回显任意来源
        configuration.setAllowedOrigins(Collections.singletonList(allowedOrigin));
        //仅白名单内的来源允许跨域携带cookie
        configuration.setAllowCredentials(true);
        //放行全部原始头信息
        configuration.addAllowedHeader(CorsConfiguration.ALL);
        //允许所有请求方法跨域调用
        configuration.addAllowedMethod(CorsConfiguration.ALL);
        return configuration;
    }
}
