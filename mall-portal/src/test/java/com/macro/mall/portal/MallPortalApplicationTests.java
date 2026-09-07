package com.macro.mall.portal;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest
@TestPropertySource(properties = "jwt.secret=" + MallPortalApplicationTests.TEST_ONLY_JWT_SECRET)
public class MallPortalApplicationTests {

    /** Test-only signing key (not a deployed credential); production keys come from the JWT_SECRET env var. */
    static final String TEST_ONLY_JWT_SECRET = "mall-portal-test-only-not-a-real-secret-0123456789";

    @Test
    public void contextLoads() {
    }

}
