package com.macro.mall.harness;

import com.macro.mall.common.api.CommonResult;
import com.macro.mall.common.api.ResultCode;
import com.macro.mall.mapper.OmsOrderMapper;
import com.macro.mall.model.OmsOrder;
import com.macro.mall.model.OmsOrderExample;
import com.macro.mall.portal.config.AlipayConfig;
import com.macro.mall.portal.controller.AlipayController;
import com.macro.mall.portal.domain.AliPayParam;
import com.macro.mall.portal.service.AlipayService;
import com.macro.mall.portal.service.OmsPortalOrderService;
import com.macro.mall.portal.service.impl.AlipayServiceImpl;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.util.ReflectionTestUtils;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * 支付宝异步回调参数校验、验签及订单完成流程单元测试 — no Spring context, no network.
 * 验签使用测试内生成的RSA密钥对，不依赖任何真实密钥。
 */
class AlipayNotifyHarnessTest {

    private static final String APP_ID = "2021000000000001";
    private static final String ORDER_SN = "202406150101000001";
    private static final String ORDER_PAY_AMOUNT = "199.00";
    /** 测试内生成的支付宝公钥（Base64编码的X509格式） */
    private static String alipayPublicKey;
    /** 测试内生成的支付宝私钥（Base64编码的PKCS8格式），仅用于在测试中构造合法签名 */
    private static String alipayPrivateKey;

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

    private AlipayServiceImpl alipayServiceImpl;
    private AlipayConfig alipayConfig;
    private OmsOrderMapper orderMapper;
    private OmsPortalOrderService portalOrderService;

    @BeforeAll
    static void generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        alipayPublicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        alipayPrivateKey = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
    }

    @BeforeEach
    void setUp() {
        alipayController = new AlipayController();
        alipayService = new RecordingAlipayService();
        ReflectionTestUtils.setField(alipayController, "alipayService", alipayService);

        alipayConfig = new AlipayConfig();
        alipayConfig.setAppId(APP_ID);
        alipayConfig.setAlipayPublicKey(alipayPublicKey);
        orderMapper = mock(OmsOrderMapper.class);
        portalOrderService = mock(OmsPortalOrderService.class);
        alipayServiceImpl = new AlipayServiceImpl();
        ReflectionTestUtils.setField(alipayServiceImpl, "alipayConfig", alipayConfig);
        ReflectionTestUtils.setField(alipayServiceImpl, "orderMapper", orderMapper);
        ReflectionTestUtils.setField(alipayServiceImpl, "portalOrderService", portalOrderService);
    }

    /** 模拟支付宝用平台私钥签名后的异步回调参数 */
    private Map<String, String> signedNotifyParams(String algorithm, String signType) throws Exception {
        Map<String, String> content = new LinkedHashMap<>();
        content.put("app_id", APP_ID);
        content.put("notify_time", "2024-06-15 13:45:22");
        content.put("notify_type", "trade_status_sync");
        content.put("trade_status", "TRADE_SUCCESS");
        content.put("out_trade_no", ORDER_SN);
        content.put("trade_no", "2024061522001450071408123456");
        content.put("total_amount", ORDER_PAY_AMOUNT);
        content.put("subject", "订单商品");
        return signParams(content, algorithm, signType);
    }

    /**
     * 按支付宝异步回调验签规则（参数名升序拼接、排除sign与sign_type）用测试私钥签名，
     * 返回带sign、sign_type的回调参数
     */
    private Map<String, String> signParams(Map<String, String> content, String algorithm, String signType)
            throws Exception {
        List<String> keys = new ArrayList<>(content.keySet());
        Collections.sort(keys);
        StringBuilder signContent = new StringBuilder();
        for (String key : keys) {
            String value = content.get(key);
            if (key.isEmpty() || value == null || value.isEmpty()
                    || "sign".equals(key) || "sign_type".equals(key)) {
                continue;
            }
            if (signContent.length() > 0) {
                signContent.append("&");
            }
            signContent.append(key).append("=").append(value);
        }
        PrivateKey privateKey = KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(alipayPrivateKey)));
        Signature signature = Signature.getInstance(algorithm);
        signature.initSign(privateKey);
        signature.update(signContent.toString().getBytes(StandardCharsets.UTF_8));
        Map<String, String> params = new HashMap<>(content);
        params.put("sign_type", signType);
        params.put("sign", Base64.getEncoder().encodeToString(signature.sign()));
        return params;
    }

    /** 待付款订单，应付金额199.00 */
    private void givenUnpaidOrder() {
        OmsOrder order = new OmsOrder();
        order.setOrderSn(ORDER_SN);
        order.setPayAmount(new BigDecimal(ORDER_PAY_AMOUNT));
        when(orderMapper.selectByExample(any(OmsOrderExample.class))).thenReturn(List.of(order));
    }

    @Test
    void validSignedNotifyCompletesOrder() throws Exception {
        givenUnpaidOrder();
        assertEquals("success", alipayServiceImpl.notify(signedNotifyParams("SHA256withRSA", "RSA2")));
        verify(portalOrderService).paySuccessByOrderSn(ORDER_SN, 1);
    }

    @Test
    void absentAlipayPublicKeyRejectsNotify() throws Exception {
        Map<String, String> params = signedNotifyParams("SHA256withRSA", "RSA2");
        //配置文件不再提供任何默认（占位）公钥，未注入时公钥为null，必须拒绝回调
        alipayConfig.setAlipayPublicKey(null);
        assertEquals("failure", alipayServiceImpl.notify(params));
        verifyNoInteractions(orderMapper, portalOrderService);
    }

    @Test
    void emptyAlipayPublicKeyRejectsNotify() throws Exception {
        Map<String, String> params = signedNotifyParams("SHA256withRSA", "RSA2");
        //环境变量未设置时占位符解析为空字符串，同样必须拒绝回调
        alipayConfig.setAlipayPublicKey("");
        assertEquals("failure", alipayServiceImpl.notify(params));
        verifyNoInteractions(orderMapper, portalOrderService);
    }

    @Test
    void blankAlipayPublicKeyRejectsNotify() throws Exception {
        Map<String, String> params = signedNotifyParams("SHA256withRSA", "RSA2");
        alipayConfig.setAlipayPublicKey("   ");
        assertEquals("failure", alipayServiceImpl.notify(params));
        verifyNoInteractions(orderMapper, portalOrderService);
    }

    @Test
    void missingSignRejectsNotify() throws Exception {
        Map<String, String> params = signedNotifyParams("SHA256withRSA", "RSA2");
        params.remove("sign");
        assertEquals("failure", alipayServiceImpl.notify(params));
        verifyNoInteractions(orderMapper, portalOrderService);
    }

    @Test
    void forgedSignRejectsNotify() throws Exception {
        Map<String, String> params = signedNotifyParams("SHA256withRSA", "RSA2");
        params.put("sign", "TWFjcm9NYWxsU2lnbmF0dXJlPT0=");
        assertEquals("failure", alipayServiceImpl.notify(params));
        verifyNoInteractions(orderMapper, portalOrderService);
    }

    @Test
    void tamperedAmountAfterSigningRejectsNotify() throws Exception {
        Map<String, String> params = signedNotifyParams("SHA256withRSA", "RSA2");
        params.put("total_amount", "0.01");
        assertEquals("failure", alipayServiceImpl.notify(params));
        verifyNoInteractions(orderMapper, portalOrderService);
    }

    @Test
    void defaultSignTypeIsRsa2() {
        //签名算法默认值取自支付宝SDK常量，实际下发到网关的值必须是RSA2
        assertEquals("RSA2", new AlipayConfig().getSignType());
    }

    @Test
    void insecureSignTypeFailsStartup() {
        AlipayConfig config = new AlipayConfig();
        //旧版RSA（SHA1withRSA）等不安全算法必须在启动阶段被拒绝
        config.setSignType("RSA");
        assertThrows(IllegalStateException.class, config::validateSignType);
    }

    @Test
    void attackerChosenSignTypeCannotDowngradeVerification() throws Exception {
        //使用不安全的SHA1withRSA签名并声明sign_type=RSA，服务端固定使用配置的RSA2校验，必须拒绝
        Map<String, String> params = signedNotifyParams("SHA1withRSA", "RSA");
        assertEquals("failure", alipayServiceImpl.notify(params));
        verifyNoInteractions(orderMapper, portalOrderService);
    }

    @Test
    void otherMerchantAppIdRejectsNotify() throws Exception {
        Map<String, String> params = signedNotifyParams("SHA256withRSA", "RSA2");
        alipayConfig.setAppId("2021000000000002");
        assertEquals("failure", alipayServiceImpl.notify(params));
        verifyNoInteractions(orderMapper, portalOrderService);
    }

    @Test
    void nonSuccessTradeStatusDoesNotCompleteOrder() throws Exception {
        Map<String, String> content = new LinkedHashMap<>();
        content.put("app_id", APP_ID);
        content.put("trade_status", "WAIT_BUYER_PAY");
        content.put("out_trade_no", ORDER_SN);
        content.put("total_amount", ORDER_PAY_AMOUNT);
        Map<String, String> params = signParams(content, "SHA256withRSA", "RSA2");
        assertEquals("failure", alipayServiceImpl.notify(params));
        verifyNoInteractions(orderMapper, portalOrderService);
    }

    @Test
    void underpaidNotifyDoesNotCompleteOrder() throws Exception {
        Map<String, String> content = new LinkedHashMap<>();
        content.put("app_id", APP_ID);
        content.put("trade_status", "TRADE_SUCCESS");
        content.put("out_trade_no", ORDER_SN);
        content.put("total_amount", "0.01");
        Map<String, String> params = signParams(content, "SHA256withRSA", "RSA2");
        givenUnpaidOrder();
        assertEquals("failure", alipayServiceImpl.notify(params));
        verify(portalOrderService, never()).paySuccessByOrderSn(any(), any());
    }

    @Test
    void replayedNotifyDoesNotCompleteOrderAgain() throws Exception {
        when(orderMapper.selectByExample(any(OmsOrderExample.class))).thenReturn(Collections.emptyList());
        assertEquals("success", alipayServiceImpl.notify(signedNotifyParams("SHA256withRSA", "RSA2")));
        verify(portalOrderService, never()).paySuccessByOrderSn(any(), any());
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
