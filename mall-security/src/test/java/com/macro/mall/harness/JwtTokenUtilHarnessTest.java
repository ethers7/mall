package com.macro.mall.harness;

import com.macro.mall.security.util.JwtTokenUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.lang.reflect.Field;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** JWT round-trip without Spring or Redis. */
class JwtTokenUtilHarnessTest {

    /** 测试专用密钥，运行时密钥由配置项jwt.secret（环境变量JWT_SECRET）提供 */
    private static final String TEST_SECRET = "unit-test-only-jwt-signing-secret";

    private JwtTokenUtil jwtTokenUtil;

    @BeforeEach
    void setUp() throws Exception {
        jwtTokenUtil = new JwtTokenUtil();
        setField("secret", TEST_SECRET);
        setField("expiration", 604800L);
        setField("tokenHead", "Bearer ");
    }

    @Test
    void generateAndParseUsername() {
        UserDetails user = new User("admin", "n/a", Collections.emptyList());
        String token = jwtTokenUtil.generateToken(user);
        assertNotNull(token);
        assertEquals("admin", jwtTokenUtil.getUserNameFromToken(token));
        assertTrue(jwtTokenUtil.validateToken(token, user));
    }

    @Test
    void rejectTokenForDifferentUser() {
        UserDetails alice = new User("alice", "n/a", Collections.emptyList());
        UserDetails bob = new User("bob", "n/a", Collections.emptyList());
        String token = jwtTokenUtil.generateToken(alice);
        assertFalse(jwtTokenUtil.validateToken(token, bob));
    }

    @Test
    void failClosedWhenSecretNotConfigured() throws Exception {
        UserDetails user = new User("admin", "n/a", Collections.emptyList());
        String token = jwtTokenUtil.generateToken(user);
        //模拟未配置jwt.secret的场景，此时既不能签发也不能校验token
        setField("secret", "");
        assertThrows(IllegalStateException.class, () -> jwtTokenUtil.generateToken(user));
        assertFalse(jwtTokenUtil.validateToken(token, user));
    }

    private void setField(String name, Object value) throws Exception {
        Field field = JwtTokenUtil.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(jwtTokenUtil, value);
    }
}
