package com.macro.mall.harness;

import com.macro.mall.common.api.CommonResult;
import com.macro.mall.common.api.ResultCode;
import com.macro.mall.portal.controller.AlipayController;
import com.macro.mall.portal.domain.AliPayParam;
import com.macro.mall.portal.service.AlipayService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 支付宝异步回调、交易查询参数校验单元测试 — no Spring context, no network. */
class AlipayNotifyHarnessTest {

    /** 记录是否真正调用到了签名校验/订单处理流程 */
    private static class RecordingAlipayService implements AlipayService {
        private Map<String, String> notifyParams;
        private boolean notifyCalled;
        private boolean queryCalled;
        private String queryOutTradeNo;
        private String queryTradeNo;

        @Override
        public String pay(AliPayParam aliPayParam) {
            throw new UnsupportedOperationException();
        }

        @Override
        public String notify(Map<String, String> params) {
            notifyCalled = true;
            notifyParams = params;
            return "success";
        }

        @Override
        public String query(String outTradeNo, String tradeNo) {
            queryCalled = true;
            queryOutTradeNo = outTradeNo;
            queryTradeNo = tradeNo;
            return "TRADE_SUCCESS";
        }

        @Override
        public String webPay(AliPayParam aliPayParam) {
            throw new UnsupportedOperationException();
        }
    }

    private AlipayController alipayController;
    private RecordingAlipayService alipayService;

    @BeforeEach
    void setUp() {
        alipayController = new AlipayController();
        alipayService = new RecordingAlipayService();
        ReflectionTestUtils.setField(alipayController, "alipayService", alipayService);
    }

    private MockHttpServletRequest notifyRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/alipay/notify");
        request.setParameter("notify_time", "2024-06-15 13:45:22");
        request.setParameter("trade_status", "TRADE_SUCCESS");
        request.setParameter("out_trade_no", "202406150101000001");
        request.setParameter("trade_no", "2024061522001450071408123456");
        request.setParameter("total_amount", "199.00");
        request.setParameter("subject", "订单商品");
        request.setParameter("sign_type", "RSA2");
        request.setParameter("sign", "TWFjcm9NYWxsU2lnbmF0dXJlPT0=");
        return request;
    }

    @Test
    void validNotifyParamsReachSignatureVerification() {
        String result = alipayController.notify(notifyRequest());
        assertEquals("success", result);
        assertTrue(alipayService.notifyCalled);
        assertEquals("202406150101000001", alipayService.notifyParams.get("out_trade_no"));
        assertEquals("TRADE_SUCCESS", alipayService.notifyParams.get("trade_status"));
        assertEquals("TWFjcm9NYWxsU2lnbmF0dXJlPT0=", alipayService.notifyParams.get("sign"));
    }

    @Test
    void illegalParamNameIsRejected() {
        MockHttpServletRequest request = notifyRequest();
        request.setParameter("out_trade_no[]", "202406150101000001");
        assertEquals("failure", alipayController.notify(request));
        assertFalse(alipayService.notifyCalled);
        assertNull(alipayService.notifyParams);
    }

    @Test
    void duplicatedParamValuesAreRejected() {
        MockHttpServletRequest request = notifyRequest();
        request.setParameter("out_trade_no", "202406150101000001", "202406150101000002");
        assertEquals("failure", alipayController.notify(request));
        assertFalse(alipayService.notifyCalled);
    }

    @Test
    void controlCharactersInParamValueAreRejected() {
        MockHttpServletRequest request = notifyRequest();
        request.setParameter("subject", "订单商品\r\nsign=forged");
        assertEquals("failure", alipayController.notify(request));
        assertFalse(alipayService.notifyCalled);
    }

    @Test
    void oversizedParamValueIsRejected() {
        MockHttpServletRequest request = notifyRequest();
        request.setParameter("passback_params", "a".repeat(4097));
        assertEquals("failure", alipayController.notify(request));
        assertFalse(alipayService.notifyCalled);
    }

    @Test
    void malformedOutTradeNoIsRejected() {
        MockHttpServletRequest request = notifyRequest();
        request.setParameter("out_trade_no", "202406150101000001' or '1'='1");
        assertEquals("failure", alipayController.notify(request));
        assertFalse(alipayService.notifyCalled);
    }

    @Test
    void malformedTradeNoIsRejected() {
        MockHttpServletRequest request = notifyRequest();
        request.setParameter("trade_no", "../../../etc/passwd");
        assertEquals("failure", alipayController.notify(request));
        assertFalse(alipayService.notifyCalled);
    }

    @Test
    void tooManyParamsAreRejected() {
        MockHttpServletRequest request = notifyRequest();
        for (int i = 0; i < 101; i++) {
            request.setParameter("param_" + i, "value");
        }
        assertEquals("failure", alipayController.notify(request));
        assertFalse(alipayService.notifyCalled);
    }

    @Test
    void notifyWithoutTradeNumbersIsStillAccepted() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/alipay/notify");
        request.setParameter("notify_type", "trade_status_sync");
        request.setParameter("sign_type", "RSA2");
        request.setParameter("sign", "TWFjcm9NYWxsU2lnbmF0dXJlPT0=");
        assertEquals("success", alipayController.notify(request));
        assertTrue(alipayService.notifyCalled);
    }

    @Test
    void validQueryParamsReachAlipay() {
        CommonResult<String> result = alipayController.query("202406150101000001", null);
        assertEquals(ResultCode.SUCCESS.getCode(), result.getCode());
        assertEquals("TRADE_SUCCESS", result.getData());
        assertTrue(alipayService.queryCalled);
        assertEquals("202406150101000001", alipayService.queryOutTradeNo);
        assertNull(alipayService.queryTradeNo);
    }

    @Test
    void queryWithTradeNoOnlyIsAccepted() {
        CommonResult<String> result = alipayController.query("", "2024061522001450071408123456");
        assertEquals(ResultCode.SUCCESS.getCode(), result.getCode());
        assertTrue(alipayService.queryCalled);
        assertEquals("2024061522001450071408123456", alipayService.queryTradeNo);
    }

    @Test
    void queryWithoutAnyTradeNumberIsRejected() {
        CommonResult<String> result = alipayController.query(null, "");
        assertEquals(ResultCode.VALIDATE_FAILED.getCode(), result.getCode());
        assertNull(result.getData());
        assertFalse(alipayService.queryCalled);
    }

    @Test
    void malformedQueryOutTradeNoIsRejected() {
        CommonResult<String> result = alipayController.query("202406150101000001' or '1'='1", null);
        assertEquals(ResultCode.VALIDATE_FAILED.getCode(), result.getCode());
        assertFalse(alipayService.queryCalled);
    }

    @Test
    void malformedQueryTradeNoIsRejected() {
        CommonResult<String> result = alipayController.query(null, "../../../etc/passwd");
        assertEquals(ResultCode.VALIDATE_FAILED.getCode(), result.getCode());
        assertFalse(alipayService.queryCalled);
    }

    @Test
    void oversizedQueryOutTradeNoIsRejected() {
        CommonResult<String> result = alipayController.query("2".repeat(65), null);
        assertEquals(ResultCode.VALIDATE_FAILED.getCode(), result.getCode());
        assertFalse(alipayService.queryCalled);
    }
}
