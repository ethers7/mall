package com.macro.mall.security.component;

import cn.hutool.json.JSONUtil;
import com.macro.mall.common.api.CommonResult;
import com.macro.mall.security.config.CorsAllowedOriginsConfig;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 自定义未登录或者token失效时的返回结果
 * Created by macro on 2018/5/14.
 */
public class RestAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final CorsAllowedOriginsConfig corsAllowedOriginsConfig;

    public RestAuthenticationEntryPoint(CorsAllowedOriginsConfig corsAllowedOriginsConfig) {
        this.corsAllowedOriginsConfig = corsAllowedOriginsConfig;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        //仅在请求Origin命中可信域名白名单时才设置该响应头，避免返回通配符"*"（CWE-942）
        CorsOriginUtil.applyAllowedOrigin(request, response, corsAllowedOriginsConfig);
        response.setHeader("Cache-Control","no-cache");
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json");
        response.getWriter().println(JSONUtil.parse(CommonResult.unauthorized(authException.getMessage())));
        response.getWriter().flush();
    }
}
