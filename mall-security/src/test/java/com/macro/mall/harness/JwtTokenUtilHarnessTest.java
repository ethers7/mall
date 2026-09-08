package com.macro.mall.harness;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.date.DateUtil;
import cn.hutool.jwt.JWT;
import cn.hutool.jwt.JWTHeader;
import cn.hutool.jwt.JWTUtil;
import cn.hutool.jwt.signers.JWTSignerUtil;
import com.macro.mall.security.util.JwtTokenUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
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

    @Test
    void failClosedWhenSecretTooShort() throws Exception {
        UserDetails user = new User("admin", "n/a", Collections.emptyList());
        String token = jwtTokenUtil.generateToken(user);
        //弱密钥（长度不足32字节）不能被静默接受，既不能签发也不能校验token
        setField("secret", "short-secret");
        assertThrows(IllegalStateException.class, () -> jwtTokenUtil.generateToken(user));
        assertFalse(jwtTokenUtil.validateToken(token, user));
    }

    @Test
    void issuedTokenUsesHs512() {
        UserDetails user = new User("admin", "n/a", Collections.emptyList());
        String token = jwtTokenUtil.generateToken(user);
        //生产代码中的算法标识由签名器派生，此处特意手写字面量，
        //一旦派生出的标识与实际写入alg头部的取值不再是HS512，本用例即失败
        assertEquals("HS512", JWTUtil.parseToken(token).getHeader(JWTHeader.ALGORITHM));
        //签发算法与校验时固定的算法一致，token可以正常通过校验
        assertTrue(jwtTokenUtil.validateToken(token, user));
    }

    @Test
    void issuedTokenCarriesRegisteredIssuedAtClaim() {
        UserDetails user = new User("admin", "n/a", Collections.emptyList());
        String token = jwtTokenUtil.generateToken(user);
        JWT jwt = JWTUtil.parseToken(token);
        //签发时间使用JWT标准中已注册的iat声明，不再使用自定义的created声明
        assertNull(jwt.getPayload("created"));
        Object issuedAt = jwt.getPayload("iat");
        assertTrue(issuedAt instanceof Number, "iat应为JWT标准要求的数字型时间戳");
        //iat按标准以秒为单位（NumericDate）
        long issuedAtSeconds = ((Number) issuedAt).longValue();
        long nowSeconds = System.currentTimeMillis() / 1000;
        assertTrue(Math.abs(nowSeconds - issuedAtSeconds) <= 5,
                "iat应为当前时间的秒级时间戳，实际与当前时间相差" + (nowSeconds - issuedAtSeconds) + "秒");
    }

    @Test
    void refreshReturnsOriginalTokenWhenIssuedJustBefore() {
        //30分钟内刚签发过的token直接返回原token
        String token = signToken("admin", DateUtil.offsetSecond(new Date(), -60));
        assertEquals(token, jwtTokenUtil.refreshHeadToken("Bearer " + token));
    }

    @Test
    void refreshIssuesNewTokenWhenIssuedLongBefore() {
        //签发时间超过30分钟且尚未过期的token，刷新后应换发新token
        String token = signToken("admin", DateUtil.offsetSecond(new Date(), -60 * 60));
        String refreshed = jwtTokenUtil.refreshHeadToken("Bearer " + token);
        assertNotNull(refreshed);
        assertNotEquals(token, refreshed);
        assertEquals("admin", jwtTokenUtil.getUserNameFromToken(refreshed));
        //换发时同样使用iat声明记录新的签发时间
        Object refreshedIssuedAt = JWTUtil.parseToken(refreshed).getPayload("iat");
        assertTrue(refreshedIssuedAt instanceof Number, "换发的token同样应携带数字型iat声明");
        assertTrue(Math.abs(System.currentTimeMillis() / 1000 - ((Number) refreshedIssuedAt).longValue()) <= 5,
                "换发的token的iat应被更新为当前时间");
    }

    @Test
    void rejectTokenWithNoneAlgorithm() {
        UserDetails user = new User("admin", "n/a", Collections.emptyList());
        //alg=none且签名为空的伪造token，必须被拒绝，否则任何人都能伪造登录态
        String forged = Base64.encodeUrlSafe("{\"alg\":\"none\",\"typ\":\"JWT\"}")
                + "." + Base64.encodeUrlSafe("{\"sub\":\"admin\",\"exp\":" + (System.currentTimeMillis() + 60000) + "}")
                + ".";
        assertNull(jwtTokenUtil.getUserNameFromToken(forged));
        assertFalse(jwtTokenUtil.validateToken(forged, user));
    }

    @Test
    void rejectTokenSignedWithOtherAlgorithm() {
        UserDetails user = new User("admin", "n/a", Collections.emptyList());
        //即使使用同一密钥，非HS512算法签发的token也必须被拒绝（防止算法混淆）
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "admin");
        claims.put("exp", System.currentTimeMillis() + 60000);
        String hs256Token = JWT.create()
                .addPayloads(claims)
                .setSigner(JWTSignerUtil.hs256(TEST_SECRET.getBytes(StandardCharsets.UTF_8)))
                .sign();
        assertNull(jwtTokenUtil.getUserNameFromToken(hs256Token));
        assertFalse(jwtTokenUtil.validateToken(hs256Token, user));
    }

    @Test
    void rejectTokenWithoutExpiration() {
        UserDetails user = new User("admin", "n/a", Collections.emptyList());
        //签名正确但缺少exp的token等同于永不过期，按失效处理
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "admin");
        String noExpToken = JWT.create()
                .addPayloads(claims)
                .setSigner(JWTSignerUtil.hs512(TEST_SECRET.getBytes(StandardCharsets.UTF_8)))
                .sign();
        assertEquals("admin", jwtTokenUtil.getUserNameFromToken(noExpToken));
        assertFalse(jwtTokenUtil.validateToken(noExpToken, user));
    }

    /**
     * 使用测试密钥和HS512算法签发一个指定用户名、指定签发时间（iat）且未过期的token
     */
    private String signToken(String username, Date issuedAt) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", username);
        claims.put("iat", issuedAt);
        claims.put("exp", System.currentTimeMillis() + 600000);
        return JWT.create()
                .addPayloads(claims)
                .setSigner(JWTSignerUtil.hs512(TEST_SECRET.getBytes(StandardCharsets.UTF_8)))
                .sign();
    }

    private void setField(String name, Object value) throws Exception {
        Field field = JwtTokenUtil.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(jwtTokenUtil, value);
    }
}
