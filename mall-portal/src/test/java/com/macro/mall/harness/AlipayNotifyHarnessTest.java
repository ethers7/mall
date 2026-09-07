package com.macro.mall.harness;

import com.macro.mall.portal.controller.AlipayController;
import com.macro.mall.portal.domain.AliPayParam;
import com.macro.mall.portal.service.AlipayService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/** 支付宝异步回调参数校验的单元测试 — no Spring context, no network. */
class AlipayNotifyHarnessTest {

    /** 记录传递给验签逻辑的参数，验证参数集合被原样转发。 */
    private static class RecordingAlipayService implements AlipayService {
        private Map<String, String> receivedParams;

        @Override
        public String pay(AliPayParam aliPayParam) {
            throw new UnsupportedOperationException();
        }

        @Override
        public String notify(Map<String, String> params) {
            receivedParams = new HashMap<>(params);
            return "success";
        }

        @Override
        public String query(String outTradeNo, String tradeNo) {
            throw new UnsupportedOperationException();
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

    @Test
    void legitimateNotifyForwardsEveryParameterUnchanged() {
        MockHttpServletRequest request = notifyRequest();
        request.setParameter("subject", "订单支付-测试商品");
        request.setParameter("total_amount", "88.88");
        request.setParameter("gmt_payment", "2024-06-15 13:45:22");

        assertEquals("success", alipayController.notify(request));
        // 验签依赖完整的参数集合，任何丢弃或改写都会导致验签失败
        assertEquals(request.getParameterMap().size(), alipayService.receivedParams.size());
        assertEquals("TRADE_SUCCESS", alipayService.receivedParams.get("trade_status"));
        assertEquals("订单支付-测试商品", alipayService.receivedParams.get("subject"));
        assertEquals("88.88", alipayService.receivedParams.get("total_amount"));
        assertEquals("2024-06-15 13:45:22", alipayService.receivedParams.get("gmt_payment"));
        assertEquals("test-sign", alipayService.receivedParams.get("sign"));
    }

    @Test
    void notifyWithoutParametersIsRejected() {
        assertEquals("failure", alipayController.notify(new MockHttpServletRequest()));
        assertVerificationNotCalled();
    }

    @Test
    void notifyWithoutSignIsRejected() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("trade_status", "TRADE_SUCCESS");
        request.setParameter("out_trade_no", "202406151345220001");

        assertEquals("failure", alipayController.notify(request));
        assertVerificationNotCalled();
    }

    @Test
    void notifyWithIllegalParameterNameIsRejected() {
        MockHttpServletRequest request = notifyRequest();
        request.setParameter("evil name\r\nX-Injected: 1", "1");

        assertEquals("failure", alipayController.notify(request));
        assertVerificationNotCalled();
    }

    @Test
    void notifyWithControlCharacterInValueIsRejected() {
        MockHttpServletRequest request = notifyRequest();
        request.setParameter("out_trade_no", "2024\r\nTRADE_SUCCESS forged log line");

        assertEquals("failure", alipayController.notify(request));
        assertVerificationNotCalled();
    }

    @Test
    void notifyWithOverlongValueIsRejected() {
        MockHttpServletRequest request = notifyRequest();
        request.setParameter("subject", "x".repeat(4097));

        assertEquals("failure", alipayController.notify(request));
        assertVerificationNotCalled();
    }

    @Test
    void notifyWithTooManyParametersIsRejected() {
        MockHttpServletRequest request = notifyRequest();
        for (int i = 0; i < 101; i++) {
            request.setParameter("filler_" + i, "1");
        }

        assertEquals("failure", alipayController.notify(request));
        assertVerificationNotCalled();
    }

    private void assertVerificationNotCalled() {
        assertNull(alipayService.receivedParams, "参数校验失败时不应调用验签逻辑");
    }

    private MockHttpServletRequest notifyRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("trade_status", "TRADE_SUCCESS");
        request.setParameter("out_trade_no", "202406151345220001");
        request.setParameter("trade_no", "2024061522001400000000000001");
        request.setParameter("sign_type", "RSA2");
        request.setParameter("sign", "test-sign");
        return request;
    }
}
