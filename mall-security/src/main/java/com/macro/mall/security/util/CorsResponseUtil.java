package com.macro.mall.security.util;

import com.macro.mall.security.config.CorsAllowedOriginsConfig;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.Collection;
import java.util.Enumeration;
import java.util.List;

/**
 * 认证失败、鉴权失败等由SpringSecurity直接返回的响应，
 * 不会经过全局跨域过滤器，需要按白名单补充跨域响应头
 * <p>
 * 请求头中的Origin只用于"是否命中白名单"的判定（结果是一个boolean），
 * 真正写入响应头的字符串直接取自配置的不可变白名单集合并作为参数传入写入方法，
 * 请求内容不存在通往响应头的数据流。
 * <p>
 * 这两个响应为401/403的JSON错误体，认证使用无状态的Authorization请求头承载JWT
 * （SessionCreationPolicy.STATELESS，无Cookie/会话），
 * 浏览器读取错误体不需要凭据模式，因此不再返回Access-Control-Allow-Credentials，
 * 即使白名单将来被误配，被放行的来源也无法借用浏览器凭据。
 * Created for CWE-942 remediation.
 */
public final class CorsResponseUtil {

    private static final String ORIGIN_HEADER = "Origin";

    private static final String VARY_HEADER = "Vary";

    private CorsResponseUtil() {
    }

    /**
     * 请求来源命中白名单时写入跨域响应头，否则不写入跨域来源响应头
     */
    public static void applyAllowedOrigin(HttpServletRequest request,
                                          HttpServletResponse response,
                                          CorsAllowedOriginsConfig corsAllowedOriginsConfig) {
        if (request == null || response == null || corsAllowedOriginsConfig == null) {
            return;
        }
        List<String> configuredOrigins = corsAllowedOriginsConfig.hasAllowedOrigins()
                ? corsAllowedOriginsConfig.getAllowedOrigins()
                : null;
        if (configuredOrigins == null || configuredOrigins.isEmpty()) {
            //未配置白名单时响应与Origin无关，不写入任何跨域响应头，也无需声明Vary（fail closed）
            return;
        }
        //配置了白名单后响应内容随Origin变化，无论是否命中都要声明Vary，避免缓存把响应串给其他来源
        addVaryOrigin(response);
        String requestOrigin = singleOriginHeader(request);
        for (String configuredOrigin : configuredOrigins) {
            //请求来源只参与boolean判定；写入的参数是遍历配置集合得到的字符串对象本身
            if (corsAllowedOriginsConfig.matchesAllowedOrigin(configuredOrigin, requestOrigin)) {
                writeConfiguredAllowedOrigin(response, configuredOrigin);
                return;
            }
        }
    }

    /**
     * 写入白名单中配置的来源。
     *
     * @param configuredAllowedOrigin 配置中的来源，仅允许由配置对象提供
     */
    private static void writeConfiguredAllowedOrigin(HttpServletResponse response, String configuredAllowedOrigin) {
        //写入前再次严格校验来源格式，含CR、LF等控制字符时不写入任何跨域响应头，
        //彻底避免响应头拆分（CWE-113）
        if (!CorsAllowedOriginsConfig.isValidOrigin(configuredAllowedOrigin)) {
            return;
        }
        response.setHeader("Access-Control-Allow-Origin", configuredAllowedOrigin);
    }

    /**
     * 读取唯一的Origin请求头，缺失、空白或出现多个（重复）Origin时一律视为无法判定。
     *
     * @return 唯一的Origin请求头，无法判定时返回null
     */
    private static String singleOriginHeader(HttpServletRequest request) {
        Enumeration<String> originHeaders = request.getHeaders(ORIGIN_HEADER);
        if (originHeaders == null || !originHeaders.hasMoreElements()) {
            return null;
        }
        String origin = originHeaders.nextElement();
        if (originHeaders.hasMoreElements()) {
            //多个Origin请求头属于非法请求，不做任何跨域判定
            return null;
        }
        if (origin == null || origin.isBlank()) {
            return null;
        }
        return origin;
    }

    private static void addVaryOrigin(HttpServletResponse response) {
        if (varyAlreadyIncludesOrigin(response)) {
            return;
        }
        response.addHeader(VARY_HEADER, ORIGIN_HEADER);
    }

    private static boolean varyAlreadyIncludesOrigin(HttpServletResponse response) {
        Collection<String> varyValues = response.getHeaders(VARY_HEADER);
        if (varyValues == null) {
            return false;
        }
        for (String varyValue : varyValues) {
            if (varyValue == null) {
                continue;
            }
            for (String varyToken : varyValue.split(",")) {
                if (ORIGIN_HEADER.equalsIgnoreCase(varyToken.trim())) {
                    return true;
                }
            }
        }
        return false;
    }
}
