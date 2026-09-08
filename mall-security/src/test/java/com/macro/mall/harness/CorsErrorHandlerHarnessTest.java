package com.macro.mall.harness;

import com.macro.mall.security.component.RestAuthenticationEntryPoint;
import com.macro.mall.security.component.RestfulAccessDeniedHandler;
import com.macro.mall.security.config.CorsAllowedOriginsConfig;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.InsufficientAuthenticationException;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * SpringSecurity错误响应的跨域策略（CWE-942）：仅白名单来源可读取响应。
 */
class CorsErrorHandlerHarnessTest {

    private static final String ORIGIN_HEADER = "Origin";
    private static final String ALLOW_ORIGIN_HEADER = "Access-Control-Allow-Origin";

    private CorsAllowedOriginsConfig configWith(List<String> origins) {
        CorsAllowedOriginsConfig config = new CorsAllowedOriginsConfig();
        config.setAllowedOrigins(origins);
        return config;
    }

    private MockHttpServletRequest requestFrom(String origin) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        if (origin != null) {
            request.addHeader(ORIGIN_HEADER, origin);
        }
        return request;
    }

    @Test
    void accessDeniedHandlerOmitsCorsHeaderForUntrustedOrigin() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        new RestfulAccessDeniedHandler(configWith(Collections.singletonList("https://trusted.internal")))
                .handle(requestFrom("https://evil.example"), response, new AccessDeniedException("denied"));
        assertNull(response.getHeader(ALLOW_ORIGIN_HEADER));
        assertTrue(response.getContentAsString().contains("403"));
        assertTrue(response.getContentType().startsWith("application/json"));
    }

    @Test
    void accessDeniedHandlerEchoesConfiguredOriginOnly() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        new RestfulAccessDeniedHandler(configWith(Collections.singletonList("https://trusted.internal")))
                .handle(requestFrom("https://trusted.internal"), response, new AccessDeniedException("denied"));
        assertEquals("https://trusted.internal", response.getHeader(ALLOW_ORIGIN_HEADER));
        assertEquals("Origin", response.getHeader("Vary"));
    }

    @Test
    void authenticationEntryPointOmitsCorsHeaderWhenAllowlistEmpty() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        new RestAuthenticationEntryPoint(configWith(Collections.emptyList()))
                .commence(requestFrom("https://evil.example"), response,
                        new InsufficientAuthenticationException("unauthorized"));
        assertNull(response.getHeader(ALLOW_ORIGIN_HEADER));
        assertTrue(response.getContentAsString().contains("401"));
    }

    @Test
    void authenticationEntryPointNeverReturnsWildcardOrigin() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        new RestAuthenticationEntryPoint(configWith(Collections.singletonList("*")))
                .commence(requestFrom("https://evil.example"), response,
                        new InsufficientAuthenticationException("unauthorized"));
        assertNull(response.getHeader(ALLOW_ORIGIN_HEADER));
    }

    @Test
    void resolveAllowedOriginRejectsWildcardAndBlankConfiguration() {
        CorsAllowedOriginsConfig config = configWith(List.of("*", " ", "https://trusted.internal"));
        assertNull(config.resolveAllowedOrigin("https://evil.example"));
        assertNull(config.resolveAllowedOrigin(null));
        assertNull(config.resolveAllowedOrigin(""));
        assertEquals("https://trusted.internal", config.resolveAllowedOrigin("https://TRUSTED.internal"));
    }
}
