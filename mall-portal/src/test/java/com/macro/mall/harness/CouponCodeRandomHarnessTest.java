package com.macro.mall.harness;

import com.macro.mall.portal.service.impl.UmsMemberCouponServiceImpl;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Coupon code generation must stay 16 numeric chars and use a crypto-strong RNG — no Spring context. */
class CouponCodeRandomHarnessTest {

    private String generateCouponCode(Long memberId) throws Exception {
        Method method = UmsMemberCouponServiceImpl.class.getDeclaredMethod("generateCouponCode", Long.class);
        method.setAccessible(true);
        return (String) method.invoke(new UmsMemberCouponServiceImpl(), memberId);
    }

    @Test
    void couponCodeGeneratorIsCryptographicallyStrong() throws Exception {
        Field field = UmsMemberCouponServiceImpl.class.getDeclaredField("COUPON_CODE_RANDOM");
        field.setAccessible(true);
        assertTrue(field.get(null) instanceof SecureRandom,
                "coupon codes must be generated with SecureRandom, not java.util.Random");
    }

    @Test
    void couponCodeKeepsSixteenDigitFormatForShortMemberId() throws Exception {
        String code = generateCouponCode(42L);
        assertEquals(16, code.length());
        assertTrue(code.matches("\\d{16}"), "coupon code must be numeric: " + code);
        assertEquals("0042", code.substring(12), "last 4 chars must be the zero padded member id");
    }

    @Test
    void couponCodeKeepsLastFourDigitsOfLongMemberId() throws Exception {
        String code = generateCouponCode(1234567L);
        assertEquals(16, code.length());
        assertTrue(code.matches("\\d{16}"), "coupon code must be numeric: " + code);
        assertEquals("4567", code.substring(12), "last 4 chars must be the member id suffix");
    }

    @Test
    void randomSegmentVariesBetweenCodes() throws Exception {
        Set<String> randomSegments = new HashSet<>();
        for (int i = 0; i < 50; i++) {
            randomSegments.add(generateCouponCode(42L).substring(8, 12));
        }
        assertTrue(randomSegments.size() > 1, "random segment of the coupon code must not be constant");
    }
}
