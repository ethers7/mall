package com.macro.mall.security.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * 认证失败/无权限响应跨域可信域名白名单配置
 * 用于{@code RestAuthenticationEntryPoint}和{@code RestfulAccessDeniedHandler}返回
 * Access-Control-Allow-Origin响应头时的来源校验，避免直接返回通配符"*"
 * 或未经校验地回显请求中的Origin（CWE-942）。
 * 默认为空列表，即不设置该响应头（拒绝所有跨域读取，失败关闭）。
 * Created by macro on 2026/10/12.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "secure.cors")
public class CorsAllowedOriginsConfig {

    private List<String> allowedOrigins = new ArrayList<>();

}
