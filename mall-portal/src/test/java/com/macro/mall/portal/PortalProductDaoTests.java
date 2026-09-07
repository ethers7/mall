package com.macro.mall.portal;

import com.macro.mall.portal.dao.PortalProductDao;
import com.macro.mall.portal.domain.PromotionProduct;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Created by macro on 2018/8/27.
 * 前台商品查询逻辑单元测试
 */
@SpringBootTest
@TestPropertySource(properties = "jwt.secret=" + PortalProductDaoTests.TEST_ONLY_JWT_SECRET)
public class PortalProductDaoTests {
    /** Test-only signing key (not a deployed credential); production keys come from the JWT_SECRET env var. */
    static final String TEST_ONLY_JWT_SECRET = "mall-portal-test-only-not-a-real-secret-0123456789";

    @Autowired
    private PortalProductDao portalProductDao;
    @Test
    public void testGetPromotionProductList(){
        List<Long> ids = new ArrayList<>();
        ids.add(26L);
        ids.add(27L);
        ids.add(28L);
        ids.add(29L);
        List<PromotionProduct> promotionProductList = portalProductDao.getPromotionProductList(ids);
        assertEquals(4,promotionProductList.size());
    }
}
