package com.macro.mall.harness;

import cn.hutool.jwt.JWT;
import cn.hutool.jwt.signers.JWTSignerUtil;
import com.macro.mall.security.util.JwtTokenUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** JWT round-trip without Spring or Redis. */
class JwtTokenUtilHarnessTest {

    /** Test-only signing key (not a deployed credential); production keys come from the JWT_SECRET env var. */
    private static final String TEST_SECRET = "jwt-token-util-test-only-signing-key-0123456789";

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
    void rejectUnsignedNoneAlgorithmToken() {
        UserDetails user = new User("admin", "n/a", Collections.emptyList());
        String forged = JWT.create()
                .addPayloads(claimsFor("admin"))
                .setSigner(JWTSignerUtil.none())
                .sign();
        assertNull(jwtTokenUtil.getUserNameFromToken(forged));
        assertFalse(jwtTokenUtil.validateToken(forged, user));
    }

    @Test
    void rejectTokenSignedWithDifferentAlgorithm() {
        UserDetails user = new User("admin", "n/a", Collections.emptyList());
        String forged = JWT.create()
                .addPayloads(claimsFor("admin"))
                .setSigner(JWTSignerUtil.hs256(TEST_SECRET.getBytes(StandardCharsets.UTF_8)))
                .sign();
        assertNull(jwtTokenUtil.getUserNameFromToken(forged));
        assertFalse(jwtTokenUtil.validateToken(forged, user));
    }

    private Map<String, Object> claimsFor(String username) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", username);
        claims.put("exp", System.currentTimeMillis() + 3600_000L);
        return claims;
    }

    private void setField(String name, Object value) throws Exception {
        Field field = JwtTokenUtil.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(jwtTokenUtil, value);
    }
}
