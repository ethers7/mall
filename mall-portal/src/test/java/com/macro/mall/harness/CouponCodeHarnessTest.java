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

/** Coupon redemption code generation — format must stay 16 digits and the RNG must be crypto-strong. No Spring context. */
class CouponCodeHarnessTest {

    private String generateCouponCode(Long memberId) throws Exception {
        Method method = UmsMemberCouponServiceImpl.class.getDeclaredMethod("generateCouponCode", Long.class);
        method.setAccessible(true);
        return (String) method.invoke(new UmsMemberCouponServiceImpl(), memberId);
    }

    @Test
    void couponCodeKeepsSixteenDigitFormat() throws Exception {
        String before = Long.toString(System.currentTimeMillis());
        String code = generateCouponCode(1234L);
        String after = Long.toString(System.currentTimeMillis());
        assertEquals(16, code.length());
        assertTrue(code.matches("\\d{16}"), "coupon code must be 16 digits: " + code);
        //时间戳后8位
        String prefix = code.substring(0, 8);
        assertTrue(prefix.compareTo(before.substring(before.length() - 8)) >= 0
                        && prefix.compareTo(after.substring(after.length() - 8)) <= 0,
                "coupon code must start with the last 8 digits of the generation timestamp: " + code);
        //用户id后4位
        assertEquals("1234", code.substring(12));
    }

    @Test
    void couponCodePadsShortMemberIdAndTruncatesLongOne() throws Exception {
        assertEquals("0007", generateCouponCode(7L).substring(12));
        assertEquals("6789", generateCouponCode(123456789L).substring(12));
    }

    @Test
    void couponCodeRandomSectionVaries() throws Exception {
        Set<String> randomSections = new HashSet<>();
        for (int i = 0; i < 50; i++) {
            randomSections.add(generateCouponCode(1234L).substring(8, 12));
        }
        assertTrue(randomSections.size() > 1, "random section of the coupon code must not be constant");
    }

    @Test
    void couponCodeUsesSecureRandom() throws Exception {
        Field field = UmsMemberCouponServiceImpl.class.getDeclaredField("COUPON_CODE_RANDOM");
        field.setAccessible(true);
        assertEquals(SecureRandom.class, field.get(null).getClass());
    }
}
