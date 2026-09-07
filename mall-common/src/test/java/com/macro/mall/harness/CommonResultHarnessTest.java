package com.macro.mall.harness;

import com.macro.mall.common.api.CommonResult;
import com.macro.mall.common.api.ResultCode;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/** Platform unit tests — no Spring context, no database. */
class CommonResultHarnessTest {

    @Test
    void successWrapsPayloadWith200() {
        CommonResult<String> result = CommonResult.success("ok");
        assertEquals(ResultCode.SUCCESS.getCode(), result.getCode());
        assertEquals("ok", result.getData());
    }

    @Test
    void failedUses500() {
        CommonResult<Void> result = CommonResult.failed("boom");
        assertEquals(ResultCode.FAILED.getCode(), result.getCode());
        assertEquals("boom", result.getMessage());
        assertNull(result.getData());
    }

    @Test
    void unauthorizedUses401() {
        CommonResult<String> result = CommonResult.unauthorized("denied");
        assertEquals(ResultCode.UNAUTHORIZED.getCode(), result.getCode());
        assertEquals("denied", result.getData());
    }

    @Test
    void validateFailedUses404() {
        CommonResult<Void> result = CommonResult.validateFailed("bad field");
        assertEquals(ResultCode.VALIDATE_FAILED.getCode(), result.getCode());
        assertEquals("bad field", result.getMessage());
    }
}
