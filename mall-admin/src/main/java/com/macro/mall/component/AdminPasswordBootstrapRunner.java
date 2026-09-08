package com.macro.mall.component;

import com.macro.mall.mapper.UmsAdminMapper;
import com.macro.mall.model.UmsAdmin;
import com.macro.mall.model.UmsAdminExample;
import com.macro.mall.service.UmsAdminCacheService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * 后台账号密码初始化：document/sql/mall.sql不再包含任何密码哈希（硬编码凭证问题，CWE-798），
 * 导入后账号的password字段为占位符（不是合法的BCrypt哈希），登录一律失败（fail-closed）。
 * 本组件在启动时从环境变量读取密码，仅对仍处于锁定状态的账号写入运行时生成的BCrypt哈希，
 * 因此无需mysql客户端即可完成初始化，仓库中也不需要保存任何凭证。
 *
 * <p>Environment-gated bootstrap for the accounts shipped by document/sql/mall.sql without a
 * password hash. When {@code MALL_ADMIN_PASS} is supplied the named account(s)
 * ({@code MALL_ADMIN_USER}, default {@code admin}) get a BCrypt hash derived from that password,
 * using the same {@link PasswordEncoder} bean the login path uses.
 *
 * <p>安全约束 / safety properties:
 * <ul>
 *     <li>未提供{@code MALL_ADMIN_PASS}时完全不动数据库；</li>
 *     <li>只初始化仍为占位符的账号；已经拥有合法BCrypt哈希的账号绝不会被覆盖，
 *         因此该机制无法重置或接管已经启用的账号；</li>
 *     <li>只记录用户名等非敏感信息，绝不打印密码或哈希；</li>
 *     <li>配置了密码但账号不存在时启动失败，避免用户名拼写错误被静默忽略。</li>
 * </ul>
 */
@Component
public class AdminPasswordBootstrapRunner implements ApplicationRunner {
    private static final Logger LOGGER = LoggerFactory.getLogger(AdminPasswordBootstrapRunner.class);
    /**
     * Spring Security的BCryptPasswordEncoder可校验的哈希格式，
     * 不匹配即视为锁定状态（占位符）的账号。
     */
    private static final Pattern BCRYPT_HASH = Pattern.compile("\\A\\$2[aby]?\\$\\d{2}\\$[./0-9A-Za-z]{53}\\z");
    /** 低于该长度只告警，不阻止启动：环境变量配置错误不应让整个应用起不来 */
    private static final int RECOMMENDED_MIN_LENGTH = 12;

    private final UmsAdminMapper adminMapper;
    private final PasswordEncoder passwordEncoder;
    private final UmsAdminCacheService adminCacheService;
    private final String bootstrapUsernames;
    private final String bootstrapPassword;

    public AdminPasswordBootstrapRunner(UmsAdminMapper adminMapper,
                                        PasswordEncoder passwordEncoder,
                                        UmsAdminCacheService adminCacheService,
                                        @Value("${MALL_ADMIN_USER:admin}") String bootstrapUsernames,
                                        @Value("${MALL_ADMIN_PASS:}") String bootstrapPassword) {
        this.adminMapper = adminMapper;
        this.passwordEncoder = passwordEncoder;
        this.adminCacheService = adminCacheService;
        this.bootstrapUsernames = bootstrapUsernames;
        this.bootstrapPassword = bootstrapPassword;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!StringUtils.hasText(bootstrapPassword)) {
            LOGGER.debug("MALL_ADMIN_PASS not supplied: skipping admin account bootstrap");
            return;
        }
        List<String> usernames = parseUsernames(bootstrapUsernames);
        if (usernames.isEmpty()) {
            throw new IllegalStateException("MALL_ADMIN_PASS已配置，但MALL_ADMIN_USER为空，无法确定需要初始化的后台账号");
        }
        if (bootstrapPassword.length() < RECOMMENDED_MIN_LENGTH) {
            LOGGER.warn("bootstrap password is shorter than {} characters, please use a longer one",
                    RECOMMENDED_MIN_LENGTH);
        }
        for (String username : usernames) {
            initialiseAccount(username);
        }
    }

    /** 支持逗号分隔的账号列表，与document/sh/seed-credentials.sh的MALL_ADMIN_USER语义一致 */
    private List<String> parseUsernames(String rawUsernames) {
        Set<String> usernames = new LinkedHashSet<>();
        if (StringUtils.hasText(rawUsernames)) {
            for (String username : rawUsernames.split(",")) {
                String trimmed = username.trim();
                if (!trimmed.isEmpty()) {
                    usernames.add(trimmed);
                }
            }
        }
        return new ArrayList<>(usernames);
    }

    private void initialiseAccount(String username) {
        UmsAdmin admin = selectByUsername(username);
        if (admin == null) {
            //拼写错误时立即失败，而不是让登录在运行时莫名失败
            throw new IllegalStateException("MALL_ADMIN_PASS已配置，但后台账号不存在：" + username
                    + "，请检查MALL_ADMIN_USER或先导入document/sql/mall.sql");
        }
        if (isUsableHash(admin.getPassword())) {
            //已经拥有合法BCrypt哈希的账号不做任何修改，避免覆盖已启用账号的密码
            LOGGER.info("admin account already initialised, skipping bootstrap: {}", username);
            return;
        }
        String encodedPassword = passwordEncoder.encode(bootstrapPassword);
        //确认使用的编码器与登录校验一致，否则宁可启动失败也不写入无法登录的哈希
        if (!passwordEncoder.matches(bootstrapPassword, encodedPassword)) {
            throw new IllegalStateException("PasswordEncoder生成的密码无法通过自身校验，已中止后台账号初始化：" + username);
        }
        UmsAdmin record = new UmsAdmin();
        record.setId(admin.getId());
        record.setPassword(encodedPassword);
        adminMapper.updateByPrimaryKeySelective(record);
        evictCachedAdmin(admin.getId(), username);
        LOGGER.info("bootstrap password applied to locked account {}", username);
    }

    private UmsAdmin selectByUsername(String username) {
        UmsAdminExample example = new UmsAdminExample();
        example.createCriteria().andUsernameEqualTo(username);
        List<UmsAdmin> adminList = adminMapper.selectByExample(example);
        if (adminList == null || adminList.isEmpty()) {
            return null;
        }
        return adminList.get(0);
    }

    /**
     * 清理Redis中缓存的后台用户信息，避免登录时读到仍处于锁定状态的旧缓存。
     * Redis不可用时只告警：密码已写入数据库，缓存过期后即可登录。
     */
    private void evictCachedAdmin(Long adminId, String username) {
        try {
            adminCacheService.delAdmin(adminId);
        } catch (Exception e) {
            LOGGER.warn("failed to evict cached admin {}, stale cache may delay login: {}", username, e.getMessage());
        }
    }

    private boolean isUsableHash(String storedPassword) {
        return storedPassword != null && BCRYPT_HASH.matcher(storedPassword).matches();
    }
}
