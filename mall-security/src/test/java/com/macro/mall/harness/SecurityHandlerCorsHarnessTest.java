package com.macro.mall.harness;

import com.macro.mall.security.component.RestAuthenticationEntryPoint;
import com.macro.mall.security.component.RestfulAccessDeniedHandler;
import com.macro.mall.security.config.CorsAllowedOriginsConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.InsufficientAuthenticationException;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Security error responses must never return a wildcard or unvalidated CORS origin. */
class SecurityHandlerCorsHarnessTest {

    private static final String ALLOW_ORIGIN = "Access-Control-Allow-Origin";
    private static final String ALLOWED = "https://admin.example.com";
    private static final String EVIL = "https://evil.example.com";

    private CorsAllowedOriginsConfig corsAllowedOriginsConfig;
    private RestAuthenticationEntryPoint entryPoint;
    private RestfulAccessDeniedHandler accessDeniedHandler;

    @BeforeEach
    void setUp() {
        corsAllowedOriginsConfig = new CorsAllowedOriginsConfig();
        corsAllowedOriginsConfig.setAllowedOrigins(Arrays.asList(ALLOWED, "https://portal.example.com"));
        entryPoint = new RestAuthenticationEntryPoint(corsAllowedOriginsConfig);
        accessDeniedHandler = new RestfulAccessDeniedHandler(corsAllowedOriginsConfig);
    }

    @Test
    void entryPointEchoesOnlyAllowedOrigin() throws IOException {
        MockHttpServletResponse response = commence(ALLOWED);
        assertEquals(ALLOWED, response.getHeader(ALLOW_ORIGIN));
        assertEquals("Origin", response.getHeader("Vary"));
        assertFalse(response.getContentAsString().isBlank());
    }

    @Test
    void entryPointRejectsUnknownOrigin() throws IOException {
        MockHttpServletResponse response = commence(EVIL);
        assertNull(response.getHeader(ALLOW_ORIGIN));
        assertFalse(response.getContentAsString().isBlank());
    }

    @Test
    void entryPointSendsNoWildcardWithoutOrigin() throws IOException {
        MockHttpServletResponse response = commence(null);
        assertNull(response.getHeader(ALLOW_ORIGIN));
    }

    @Test
    void accessDeniedHandlerEchoesOnlyAllowedOrigin() throws IOException {
        MockHttpServletResponse response = handleAccessDenied(ALLOWED);
        assertEquals(ALLOWED, response.getHeader(ALLOW_ORIGIN));
        assertEquals("Origin", response.getHeader("Vary"));
        assertFalse(response.getContentAsString().isBlank());
    }

    @Test
    void accessDeniedHandlerRejectsUnknownOrigin() throws IOException {
        MockHttpServletResponse response = handleAccessDenied(EVIL);
        assertNull(response.getHeader(ALLOW_ORIGIN));
        assertFalse(response.getContentAsString().isBlank());
    }

    @Test
    void emptyAllowlistSendsNoCorsHeader() throws IOException {
        corsAllowedOriginsConfig.setAllowedOrigins(Collections.emptyList());
        assertNull(commence(ALLOWED).getHeader(ALLOW_ORIGIN));
        assertNull(handleAccessDenied(ALLOWED).getHeader(ALLOW_ORIGIN));
    }

    @Test
    void wildcardEntryInAllowlistIsIgnored() {
        corsAllowedOriginsConfig.setAllowedOrigins(Collections.singletonList("*"));
        assertNull(corsAllowedOriginsConfig.resolveAllowedOrigin(EVIL));
        assertNull(corsAllowedOriginsConfig.resolveAllowedOrigin(ALLOWED));
    }

    @Test
    void allowlistMatchIsExact() {
        assertNull(corsAllowedOriginsConfig.resolveAllowedOrigin("https://admin.example.com.evil.test"));
        assertNull(corsAllowedOriginsConfig.resolveAllowedOrigin("http://admin.example.com"));
        assertEquals(ALLOWED, corsAllowedOriginsConfig.resolveAllowedOrigin(ALLOWED));
    }

    private MockHttpServletResponse commence(String origin) throws IOException {
        MockHttpServletRequest request = newRequest(origin);
        MockHttpServletResponse response = new MockHttpServletResponse();
        entryPoint.commence(request, response, new InsufficientAuthenticationException("未登录"));
        assertTrue(isNoWildcard(response));
        return response;
    }

    private MockHttpServletResponse handleAccessDenied(String origin) throws IOException {
        MockHttpServletRequest request = newRequest(origin);
        MockHttpServletResponse response = new MockHttpServletResponse();
        accessDeniedHandler.handle(request, response, new AccessDeniedException("无权限"));
        assertTrue(isNoWildcard(response));
        return response;
    }

    private MockHttpServletRequest newRequest(String origin) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/info");
        if (origin != null) {
            request.addHeader("Origin", origin);
        }
        return request;
    }

    private boolean isNoWildcard(MockHttpServletResponse response) {
        return !"*".equals(response.getHeader(ALLOW_ORIGIN));
    }
}
