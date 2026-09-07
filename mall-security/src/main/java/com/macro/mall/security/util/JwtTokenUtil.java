package com.macro.mall.security.util;

import cn.hutool.core.date.DateUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.jwt.JWT;
import cn.hutool.jwt.JWTHeader;
import cn.hutool.jwt.signers.JWTSigner;
import cn.hutool.jwt.signers.JWTSignerUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * JwtToken生成的工具类
 * JWT token的格式：header.payload.signature
 * header的格式（算法、token的类型）：
 * {"alg": "HS512","typ": "JWT"}
 * payload的格式（用户名、创建时间、生成时间）：
 * {"sub":"wang","created":1489079981393,"exp":1489684781}
 * signature的生成算法：
 * HMACSHA512(base64UrlEncode(header) + "." +base64UrlEncode(payload),secret)
 * Created by macro on 2018/4/26.
 * Refactored to use Hutool JWTUtil
 */
public class JwtTokenUtil {
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtTokenUtil.class);
    private static final String CLAIM_KEY_USERNAME = "sub";
    private static final String CLAIM_KEY_CREATED = "created";
    @Value("${jwt.secret}")
    private String secret;
    @Value("${jwt.expiration}")
    private Long expiration;
    @Value("${jwt.tokenHead}")
    private String tokenHead;

    /**
     * 签名密钥最小长度（字节），防止使用空密钥或过弱的密钥进行HMAC签名
     */
    private static final int MIN_SECRET_LENGTH = 32;

    /**
     * 服务端固定使用的签名算法标识，签发和校验都只允许该算法，
     * 防止客户端通过token头部的alg字段指定算法（如alg=none或降级为其它算法）绕过签名校验
     */
    private static final String SIGN_ALGORITHM_ID = "HS512";

    /**
     * 获取签名密钥
     * 密钥必须通过环境变量（JWT_SECRET）等外部配置提供，源码及配置文件中不允许保留可用的默认密钥
     */
    private byte[] getSigningKey() {
        if (StrUtil.isBlank(secret) || secret.getBytes(StandardCharsets.UTF_8).length < MIN_SECRET_LENGTH) {
            throw new IllegalStateException("jwt.secret 未配置或强度不足，请通过环境变量 JWT_SECRET 提供至少 "
                    + MIN_SECRET_LENGTH + " 字节的随机密钥");
        }
        return secret.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * 获取签名器，算法由服务端固定为HS512，不使用token中声明的算法
     */
    private JWTSigner getSigner() {
        return JWTSignerUtil.hs512(getSigningKey());
    }

    /**
     * 根据负责生成JWT的token
     */
    private String generateToken(Map<String, Object> claims) {
        // 设置过期时间
        long expireTime = System.currentTimeMillis() + expiration * 1000;
        claims.put("exp", expireTime);
        return JWT.create()
                .setHeader(JWTHeader.ALGORITHM, SIGN_ALGORITHM_ID)
                .addPayloads(claims)
                .setSigner(getSigner())
                .sign();
    }

    /**
     * 从token中获取JWT中的负载
     */
    private Map<String, Object> getPayloadFromToken(String token) {
        try {
            JWT jwt = JWT.of(token);
            // 只接受服务端签发时使用的算法，拒绝alg=none等由客户端指定的算法，防止算法混淆导致的签名绕过
            Object algorithm = jwt.getHeader(JWTHeader.ALGORITHM);
            if (algorithm == null || !SIGN_ALGORITHM_ID.equalsIgnoreCase(algorithm.toString())) {
                LOGGER.info("JWT签名算法不被支持");
                return null;
            }
            // 使用服务端固定的签名器验证token签名
            if (!jwt.setSigner(getSigner()).verify()) {
                LOGGER.info("JWT签名验证失败");
                return null;
            }
            // 解析token payload
            return jwt.getPayloads();
        } catch (Exception e) {
            LOGGER.info("JWT格式验证失败");
            return null;
        }
    }

    /**
     * 从token中获取登录用户名
     */
    public String getUserNameFromToken(String token) {
        String username;
        try {
            Map<String, Object> payload = getPayloadFromToken(token);
            username = payload != null ? (String) payload.get(CLAIM_KEY_USERNAME) : null;
        } catch (Exception e) {
            username = null;
        }
        return username;
    }

    /**
     * 验证token是否还有效
     *
     * @param token       客户端传入的token
     * @param userDetails 从数据库中查询出来的用户信息
     */
    public boolean validateToken(String token, UserDetails userDetails) {
        String username = getUserNameFromToken(token);
        return username != null && username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    /**
     * 判断token是否已经失效
     */
    private boolean isTokenExpired(String token) {
        try {
            // 手动检查 exp 字段判断是否过期
            Map<String, Object> payload = getPayloadFromToken(token);
            if (payload == null) {
                return true;
            }
            Object exp = payload.get("exp");
            if (!(exp instanceof Number)) {
                // 缺少或非法的过期时间视为已过期，避免出现永不过期的token
                return true;
            }
            long expTime = ((Number) exp).longValue();
            return expTime < System.currentTimeMillis();
        } catch (Exception e) {
            return true;
        }
    }

    /**
     * 从token中获取过期时间
     */
    private Date getExpiredDateFromToken(String token) {
        Map<String, Object> payload = getPayloadFromToken(token);
        if (payload == null) {
            return null;
        }
        Object exp = payload.get("exp");
        if (exp instanceof Long) {
            return new Date((Long) exp);
        } else if (exp instanceof Integer) {
            return new Date(((Integer) exp).longValue());
        }
        return null;
    }

    /**
     * 根据用户信息生成token
     */
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(CLAIM_KEY_USERNAME, userDetails.getUsername());
        claims.put(CLAIM_KEY_CREATED, new Date());
        return generateToken(claims);
    }

    /**
     * 当原来的token没过期时是可以刷新的
     *
     * @param oldToken 带tokenHead的token
     */
    public String refreshHeadToken(String oldToken) {
        if (StrUtil.isEmpty(oldToken)) {
            return null;
        }
        String token = oldToken.substring(tokenHead.length());
        if (StrUtil.isEmpty(token)) {
            return null;
        }
        // token校验不通过
        Map<String, Object> payload = getPayloadFromToken(token);
        if (payload == null) {
            return null;
        }
        // 如果token已经过期，不支持刷新
        if (isTokenExpired(token)) {
            return null;
        }
        // 如果token在30分钟之内刚刷新过，返回原token
        if (tokenRefreshJustBefore(token, 30 * 60)) {
            return token;
        } else {
            payload.put(CLAIM_KEY_CREATED, new Date());
            return generateToken(payload);
        }
    }

    /**
     * 判断token在指定时间内是否刚刚刷新过
     *
     * @param token 原token
     * @param time  指定时间（秒）
     */
    private boolean tokenRefreshJustBefore(String token, int time) {
        Map<String, Object> payload = getPayloadFromToken(token);
        if (payload == null) {
            return false;
        }
        Object created = payload.get(CLAIM_KEY_CREATED);
        Date createdDate = null;
        if (created instanceof Long) {
            createdDate = new Date((Long) created);
        } else if (created instanceof Date) {
            createdDate = (Date) created;
        }
        if (createdDate == null) {
            return false;
        }
        Date refreshDate = new Date();
        // 刷新时间在创建时间的指定时间内
        return refreshDate.after(createdDate) && refreshDate.before(DateUtil.offsetSecond(createdDate, time));
    }
}
