package com.macro.mall.security.util;

import cn.hutool.core.date.DateUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.jwt.JWT;
import cn.hutool.jwt.JWTHeader;
import cn.hutool.jwt.JWTUtil;
import cn.hutool.jwt.RegisteredPayload;
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
 * 签发和校验都固定使用HS512算法，校验时不采用token头部声明的算法
 * Created by macro on 2018/4/26.
 * Refactored to use Hutool JWTUtil
 */
public class JwtTokenUtil {
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtTokenUtil.class);
    /**
     * 登录用户名使用JWT标准中已注册的sub（Subject）声明，直接引用Hutool中的常量，
     * 避免手写协议字段名出现拼写错误
     */
    private static final String CLAIM_KEY_USERNAME = RegisteredPayload.SUBJECT;
    /**
     * token创建时间为本项目自定义的声明，JWT标准中无对应的已注册声明名
     */
    private static final String CLAIM_KEY_CREATED = "created";
    /**
     * 签发和校验token时固定使用的签名算法标识
     * 校验时必须由服务端固定算法，绝不能采用token头部自带的alg，
     * 否则攻击者可通过alg=none或替换为其他算法绕过签名校验（算法混淆攻击）
     */
    private static final String SIGN_ALGORITHM_ID = "HS512";
    /**
     * 签名密钥的最小长度（字节），低于该长度的密钥强度不足，直接拒绝签发和校验token
     */
    private static final int MIN_SECRET_LENGTH = 32;
    /**
     * HS512推荐的签名密钥长度（字节），即HMAC-SHA512的摘要长度（RFC 7518）
     */
    private static final int RECOMMENDED_SECRET_LENGTH = 64;
    @Value("${jwt.secret}")
    private String secret;
    @Value("${jwt.expiration}")
    private Long expiration;
    @Value("${jwt.tokenHead}")
    private String tokenHead;
    /**
     * 密钥长度不足推荐值的告警只输出一次，避免每次签发/校验token都刷日志
     */
    private volatile boolean weakSecretWarned;

    /**
     * 获取签名密钥
     * 密钥必须通过外部配置jwt.secret（如环境变量JWT_SECRET）提供，
     * 未配置时直接抛出异常，避免使用源码中的硬编码默认密钥签发或校验token；
     * 密钥长度不足时同样抛出异常，避免弱密钥被静默接受（HS512签名的强度取决于密钥强度）
     */
    private byte[] getSigningKey() {
        if (StrUtil.isBlank(secret)) {
            throw new IllegalStateException("JWT签名密钥未配置，请通过配置项jwt.secret（环境变量JWT_SECRET）提供随机生成的强密钥");
        }
        byte[] key = secret.getBytes(StandardCharsets.UTF_8);
        if (key.length < MIN_SECRET_LENGTH) {
            throw new IllegalStateException("JWT签名密钥强度不足，配置项jwt.secret（环境变量JWT_SECRET）至少需要"
                    + MIN_SECRET_LENGTH + "字节的随机字符");
        }
        if (key.length < RECOMMENDED_SECRET_LENGTH && !weakSecretWarned) {
            weakSecretWarned = true;
            LOGGER.warn("JWT签名密钥长度小于HS512的摘要长度（{}字节），建议使用不少于{}字节的随机密钥",
                    RECOMMENDED_SECRET_LENGTH, RECOMMENDED_SECRET_LENGTH);
        }
        return key;
    }

    /**
     * 获取签名器，签发和校验token时都使用服务端固定的HS512算法
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
        // 使用固定的HS512签名器签发token
        return JWT.create().addPayloads(claims).setSigner(getSigner()).sign();
    }

    /**
     * 从token中获取JWT中的负载
     */
    private Map<String, Object> getPayloadFromToken(String token) {
        try {
            JWT jwt = JWTUtil.parseToken(token);
            // 只接受服务端签发算法（HS512）的token，拒绝alg=none及其他算法，防止算法混淆绕过签名校验
            if (!SIGN_ALGORITHM_ID.equals(jwt.getHeader(JWTHeader.ALGORITHM))) {
                LOGGER.info("JWT签名算法不被允许");
                return null;
            }
            // 使用服务端固定算法的签名器验证token签名，不使用token头部声明的算法
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
            if (exp == null) {
                // 缺少exp的token等同于永不过期，按失效处理（失败关闭）
                return true;
            }
            long expTime = exp instanceof Long ? (Long) exp : ((Number) exp).longValue();
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
