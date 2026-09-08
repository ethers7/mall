package com.macro.mall.harness;

import com.macro.mall.component.AdminPasswordBootstrapRunner;
import com.macro.mall.mapper.UmsAdminMapper;
import com.macro.mall.model.UmsAdmin;
import com.macro.mall.model.UmsAdminExample;
import com.macro.mall.service.UmsAdminCacheService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * 后台账号密码初始化单元测试 — no Spring context, no database, no network.
 * document/sql/mall.sql不含任何密码哈希，测试中用到的哈希都在运行时生成，仓库内不保存凭证。
 */
class AdminPasswordBootstrapHarnessTest {

    /** mall.sql导入后的占位符：不是合法的BCrypt哈希，登录一律失败 */
    private static final String LOCKED_PLACEHOLDER = "!LOCKED";
    private static final String ADMIN_USERNAME = "admin";
    /** 测试内随机生成的密码，避免在仓库中出现任何固定凭证 */
    private static final String BOOTSTRAP_PASSWORD = "Bootstrap-" + UUID.randomUUID();

    private final ApplicationArguments applicationArguments = new DefaultApplicationArguments();

    private UmsAdminMapper adminMapper;
    private UmsAdminCacheService adminCacheService;
    private PasswordEncoder passwordEncoder;
    private Map<String, UmsAdmin> accountsByUsername;

    @BeforeEach
    void setUp() {
        adminMapper = mock(UmsAdminMapper.class);
        adminCacheService = mock(UmsAdminCacheService.class);
        passwordEncoder = new BCryptPasswordEncoder();
        accountsByUsername = new HashMap<>();
        when(adminMapper.selectByExample(any(UmsAdminExample.class)))
                .thenAnswer(invocation -> {
                    UmsAdminExample example = invocation.getArgument(0);
                    UmsAdmin admin = accountsByUsername.get(queriedUsername(example));
                    if (admin == null) {
                        return new ArrayList<UmsAdmin>();
                    }
                    return Collections.singletonList(admin);
                });
    }

    /** 校验查询条件确实按用户名过滤，并取出被查询的用户名 */
    @SuppressWarnings("unchecked")
    private String queriedUsername(UmsAdminExample example) {
        assertEquals(1, example.getOredCriteria().size(), "只应构造一个查询条件组");
        List<UmsAdminExample.Criterion> criteria = (List<UmsAdminExample.Criterion>)
                ReflectionTestUtils.getField(example.getOredCriteria().get(0), "criteria");
        assertEquals(1, criteria.size(), "只应按用户名过滤");
        assertEquals("username =", criteria.get(0).getCondition());
        return (String) criteria.get(0).getValue();
    }

    private UmsAdmin account(Long id, String username, String password) {
        UmsAdmin admin = new UmsAdmin();
        admin.setId(id);
        admin.setUsername(username);
        admin.setPassword(password);
        admin.setStatus(1);
        accountsByUsername.put(username, admin);
        return admin;
    }

    private AdminPasswordBootstrapRunner runner(String usernames, String password) {
        return new AdminPasswordBootstrapRunner(adminMapper, passwordEncoder, adminCacheService, usernames, password);
    }

    private UmsAdmin capturedUpdate() {
        ArgumentCaptor<UmsAdmin> captor = ArgumentCaptor.forClass(UmsAdmin.class);
        verify(adminMapper).updateByPrimaryKeySelective(captor.capture());
        return captor.getValue();
    }

    @Test
    void lockedAccountIsInitialisedFromEnvironmentPassword() {
        account(3L, ADMIN_USERNAME, LOCKED_PLACEHOLDER);

        runner(ADMIN_USERNAME, BOOTSTRAP_PASSWORD).run(applicationArguments);

        UmsAdmin update = capturedUpdate();
        assertEquals(Long.valueOf(3L), update.getId());
        assertTrue(passwordEncoder.matches(BOOTSTRAP_PASSWORD, update.getPassword()),
                "写入的哈希必须能通过登录路径使用的编码器校验");
        assertNotEquals(BOOTSTRAP_PASSWORD, update.getPassword(), "不能写入明文密码");
        assertTrue(update.getPassword().startsWith("$2"), "必须写入BCrypt哈希");
        //只更新密码，不覆盖其它字段
        assertNull(update.getUsername());
        assertNull(update.getStatus());
        //清理Redis中可能缓存的锁定状态记录
        verify(adminCacheService).delAdmin(3L);
    }

    @Test
    void alreadyInitialisedAccountIsNeverOverwritten() {
        String existingHash = passwordEncoder.encode("Existing-" + UUID.randomUUID());
        account(3L, ADMIN_USERNAME, existingHash);

        runner(ADMIN_USERNAME, BOOTSTRAP_PASSWORD).run(applicationArguments);

        verify(adminMapper, never()).updateByPrimaryKeySelective(any(UmsAdmin.class));
        verify(adminMapper, never()).updateByPrimaryKey(any(UmsAdmin.class));
        verify(adminMapper, never()).updateByExampleSelective(any(UmsAdmin.class), any(UmsAdminExample.class));
        verifyNoInteractions(adminCacheService);
        assertEquals(existingHash, accountsByUsername.get(ADMIN_USERNAME).getPassword(),
                "已初始化账号的密码不允许被引导流程重置");
        assertFalse(passwordEncoder.matches(BOOTSTRAP_PASSWORD, existingHash),
                "引导密码不应能登录已初始化的账号");
    }

    @Test
    void missingEnvironmentPasswordDoesNothing() {
        account(3L, ADMIN_USERNAME, LOCKED_PLACEHOLDER);

        runner(ADMIN_USERNAME, "").run(applicationArguments);
        runner(ADMIN_USERNAME, "   ").run(applicationArguments);
        runner(ADMIN_USERNAME, null).run(applicationArguments);

        verify(adminMapper, never()).selectByExample(any(UmsAdminExample.class));
        verify(adminMapper, never()).updateByPrimaryKeySelective(any(UmsAdmin.class));
        verifyNoInteractions(adminCacheService);
        assertEquals(LOCKED_PLACEHOLDER, accountsByUsername.get(ADMIN_USERNAME).getPassword(),
                "未提供密码时账号必须保持锁定状态");
    }

    @Test
    void missingAccountFailsLoudly() {
        //数据库中没有该账号（例如MALL_ADMIN_USER拼写错误）
        IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> runner("typo-admin", BOOTSTRAP_PASSWORD).run(applicationArguments));
        assertTrue(exception.getMessage().contains("typo-admin"), "异常信息应包含出错的用户名");
        assertFalse(exception.getMessage().contains(BOOTSTRAP_PASSWORD), "异常信息不得包含密码");
        verify(adminMapper, never()).updateByPrimaryKeySelective(any(UmsAdmin.class));
        verifyNoInteractions(adminCacheService);
    }

    @Test
    void blankUsernameWithPasswordFailsLoudly() {
        assertThrows(IllegalStateException.class,
                () -> runner("  ", BOOTSTRAP_PASSWORD).run(applicationArguments));
        verify(adminMapper, never()).selectByExample(any(UmsAdminExample.class));
        verify(adminMapper, never()).updateByPrimaryKeySelective(any(UmsAdmin.class));
        verifyNoInteractions(adminCacheService);
    }

    @Test
    void commaSeparatedUsernamesInitialiseOnlyLockedAccounts() {
        account(3L, ADMIN_USERNAME, LOCKED_PLACEHOLDER);
        String existingHash = passwordEncoder.encode("Existing-" + UUID.randomUUID());
        account(4L, "macro", existingHash);

        runner(ADMIN_USERNAME + ", macro", BOOTSTRAP_PASSWORD).run(applicationArguments);

        UmsAdmin update = capturedUpdate();
        assertEquals(Long.valueOf(3L), update.getId(), "只有锁定账号才会被初始化");
        assertEquals(existingHash, accountsByUsername.get("macro").getPassword());
        verify(adminCacheService).delAdmin(3L);
        verify(adminCacheService, never()).delAdmin(4L);
    }

    @Test
    void cacheEvictionFailureDoesNotAbortStartup() {
        account(3L, ADMIN_USERNAME, LOCKED_PLACEHOLDER);
        doThrow(new IllegalStateException("redis unavailable")).when(adminCacheService).delAdmin(anyLong());

        //Redis不可用时密码仍应写入数据库，启动不受影响
        runner(ADMIN_USERNAME, BOOTSTRAP_PASSWORD).run(applicationArguments);

        assertTrue(passwordEncoder.matches(BOOTSTRAP_PASSWORD, capturedUpdate().getPassword()));
    }
}
