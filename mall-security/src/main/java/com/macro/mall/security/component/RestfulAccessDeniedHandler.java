package com.macro.mall.security.component;

import cn.hutool.json.JSONUtil;
import com.macro.mall.common.api.CommonResult;
import com.macro.mall.security.config.CorsAllowedOriginsConfig;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 自定义无权限访问的返回结果
 * Created by macro on 2018/4/26.
 */
public class RestfulAccessDeniedHandler implements AccessDeniedHandler{

    private final CorsAllowedOriginsConfig corsAllowedOriginsConfig;

    public RestfulAccessDeniedHandler(CorsAllowedOriginsConfig corsAllowedOriginsConfig) {
        this.corsAllowedOriginsConfig = corsAllowedOriginsConfig;
    }

    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException e) throws IOException {
        //只对白名单内的来源返回跨域响应头，避免使用通配符导致任意域名跨域访问
        corsAllowedOriginsConfig.applyAllowedOrigin(request, response);
        response.setHeader("Cache-Control","no-cache");
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json");
        response.getWriter().println(JSONUtil.parse(CommonResult.forbidden(e.getMessage())));
        response.getWriter().flush();
    }
}
