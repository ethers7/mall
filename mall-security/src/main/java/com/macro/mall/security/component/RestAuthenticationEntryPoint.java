package com.macro.mall.security.component;

import cn.hutool.json.JSONUtil;
import com.macro.mall.common.api.CommonResult;
import com.macro.mall.security.config.CorsAllowedOriginsConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 自定义未登录或者token失效时的返回结果
 * Created by macro on 2018/5/14.
 */
public class RestAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Autowired
    private CorsAllowedOriginsConfig corsAllowedOriginsConfig;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        //仅对白名单中的域名放行跨域访问，未配置或不匹配时不返回跨域响应头
        String allowedOrigin = corsAllowedOriginsConfig == null ? null
                : corsAllowedOriginsConfig.resolveAllowedOrigin(request.getHeader("Origin"));
        if (allowedOrigin != null) {
            response.setHeader("Access-Control-Allow-Origin", allowedOrigin);
            response.setHeader("Vary", "Origin");
        }
        response.setHeader("Cache-Control","no-cache");
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json");
        response.getWriter().println(JSONUtil.parse(CommonResult.unauthorized(authException.getMessage())));
        response.getWriter().flush();
    }
}
