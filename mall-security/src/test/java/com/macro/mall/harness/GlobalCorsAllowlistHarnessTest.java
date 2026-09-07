package com.macro.mall.harness;

import com.macro.mall.security.config.AllowedOriginsCorsConfigurationSource;
import com.macro.mall.security.config.CorsAllowedOriginsConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.filter.CorsFilter;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 全局跨域过滤器只对白名单来源开放跨域的单元测试 — no Spring context, no network.
 * The global CorsFilter must never allow an arbitrary origin, and must not disturb
 * same-origin / non-browser requests that carry no Origin header.
 */
class GlobalCorsAllowlistHarnessTest {

    private static final String ALLOW_ORIGIN = "Access-Control-Allow-Origin";
    private static final String ALLOW_CREDENTIALS = "Access-Control-Allow-Credentials";
    private static final String ALLOWED = "https://admin.example.com";
    private static final String EVIL = "https://evil.example.com";

    private CorsAllowedOriginsConfig corsAllowedOriginsConfig;
    private CorsFilter corsFilter;

    @BeforeEach
    void setUp() {
        corsAllowedOriginsConfig = new CorsAllowedOriginsConfig();
        corsAllowedOriginsConfig.setAllowedOrigins(Arrays.asList(ALLOWED, "https://portal.example.com"));
        corsFilter = new CorsFilter(new AllowedOriginsCorsConfigurationSource(corsAllowedOriginsConfig));
    }

    @Test
    void allowlistedOriginGetsCredentialedCors() throws Exception {
        MockFilterChain chain = new MockFilterChain();
        MockHttpServletResponse response = doFilter(newRequest("GET", ALLOWED), chain);
        assertEquals(ALLOWED, response.getHeader(ALLOW_ORIGIN));
        assertEquals("true", response.getHeader(ALLOW_CREDENTIALS));
        assertTrue(String.join(",", response.getHeaders("Vary")).contains("Origin"));
        //业务请求正常放行
        assertNotNull(chain.getRequest());
    }

    @Test
    void unknownOriginGetsNoCorsHeader() throws Exception {
        MockFilterChain chain = new MockFilterChain();
        MockHttpServletResponse response = doFilter(newRequest("GET", EVIL), chain);
        assertNull(response.getHeader(ALLOW_ORIGIN));
        assertNull(response.getHeader(ALLOW_CREDENTIALS));
    }

    @Test
    void unknownOriginPreflightGetsNoCorsHeader() throws Exception {
        MockHttpServletRequest request = newRequest("OPTIONS", EVIL);
        request.addHeader("Access-Control-Request-Method", "POST");
        MockHttpServletResponse response = doFilter(request, new MockFilterChain());
        assertNull(response.getHeader(ALLOW_ORIGIN));
        assertNull(response.getHeader(ALLOW_CREDENTIALS));
    }

    @Test
    void emptyAllowlistDeniesEveryOrigin() throws Exception {
        corsAllowedOriginsConfig.setAllowedOrigins(Collections.emptyList());
        assertNull(doFilter(newRequest("GET", ALLOWED), new MockFilterChain()).getHeader(ALLOW_ORIGIN));
        assertNull(doFilter(newRequest("GET", EVIL), new MockFilterChain()).getHeader(ALLOW_ORIGIN));
    }

    @Test
    void wildcardAllowlistEntryIsIgnored() throws Exception {
        corsAllowedOriginsConfig.setAllowedOrigins(Collections.singletonList("*"));
        MockHttpServletResponse response = doFilter(newRequest("GET", EVIL), new MockFilterChain());
        assertNull(response.getHeader(ALLOW_ORIGIN));
        assertTrue(corsAllowedOriginsConfig.resolveAllowedOrigins().isEmpty());
    }

    @Test
    void requestWithoutOriginIsUntouched() throws Exception {
        MockFilterChain chain = new MockFilterChain();
        MockHttpServletResponse response = doFilter(newRequest("POST", null), chain);
        assertNull(response.getHeader(ALLOW_ORIGIN));
        assertEquals(200, response.getStatus());
        //不带Origin的同源或非浏览器请求必须正常放行
        assertNotNull(chain.getRequest());
    }

    @Test
    void resolveAllowedOriginsDropsBlankAndWildcardEntries() {
        corsAllowedOriginsConfig.setAllowedOrigins(Arrays.asList(" " + ALLOWED + " ", "", "*", null));
        List<String> effectiveOrigins = corsAllowedOriginsConfig.resolveAllowedOrigins();
        assertEquals(Collections.singletonList(ALLOWED), effectiveOrigins);
    }

    private MockHttpServletResponse doFilter(MockHttpServletRequest request, MockFilterChain chain) throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        corsFilter.doFilter(request, response, chain);
        //任何情况下都不允许返回通配符来源
        assertTrue(!"*".equals(response.getHeader(ALLOW_ORIGIN)));
        return response;
    }

    private MockHttpServletRequest newRequest(String method, String origin) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, "/admin/info");
        if (origin != null) {
            request.addHeader("Origin", origin);
        }
        return request;
    }
}
