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
import org.springframework.core.MethodParameter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.util.MultiValueMap;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.method.annotation.RequestParamMapMethodArgumentResolver;

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
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
    /** 一组格式合法的异步回调参数（签名为占位值，仅用于校验参数绑定与参数校验流程） */
    private static final Map<String, String> BASE_NOTIFY_PARAMS = Map.ofEntries(
            Map.entry("notify_time", "2024-06-15 13:45:22"),
            Map.entry("trade_status", "TRADE_SUCCESS"),
            Map.entry("out_trade_no", ORDER_SN),
            Map.entry("trade_no", "2024061522001450071408123456"),
            Map.entry("total_amount", ORDER_PAY_AMOUNT),
            Map.entry("subject", "订单商品"),
            Map.entry("sign_type", "RSA2"),
            Map.entry("sign", "TWFjcm9NYWxsU2lnbmF0dXJlPT0="));
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
        return notifyRequest(BASE_NOTIFY_PARAMS);
    }

    /** notifyRequest()构造的回调参数名集合，附加未知参数名后作为期望的绑定结果 */
    private static Set<String> expectedParamNames(String... extraNames) {
        Set<String> names = new HashSet<>(BASE_NOTIFY_PARAMS.keySet());
        names.addAll(List.of(extraNames));
        return names;
    }

    /** 用给定的回调参数构造异步回调请求 */
    private MockHttpServletRequest notifyRequest(Map<String, String> params) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/alipay/notify");
        for (Map.Entry<String, String> entry : params.entrySet()) {
            request.setParameter(entry.getKey(), entry.getValue());
        }
        return request;
    }

    /**
     * 用Spring MVC真实的参数解析器（RequestParamMapMethodArgumentResolver，即处理
     * 不带参数名的@RequestParam Map/MultiValueMap入参的解析器）把请求参数绑定成
     * MultiValueMap，确保测试覆盖的是线上真实的绑定行为
     */
    @SuppressWarnings("unchecked")
    private MultiValueMap<String, String> bindNotifyParams(MockHttpServletRequest request) throws Exception {
        MethodParameter parameter = notifyMethodParameter();
        RequestParamMapMethodArgumentResolver resolver = new RequestParamMapMethodArgumentResolver();
        //该入参必须由Map解析器处理，否则绑定语义无从保证
        assertTrue(resolver.supportsParameter(parameter));
        Object bound = resolver.resolveArgument(parameter, null, new ServletWebRequest(request), null);
        return (MultiValueMap<String, String>) bound;
    }

    private MethodParameter notifyMethodParameter() throws Exception {
        return new MethodParameter(AlipayController.class.getMethod("notify", MultiValueMap.class), 0);
    }

    /** 按线上流程绑定请求参数后调用回调接口 */
    private String notifyThroughBinding(MockHttpServletRequest request) throws Exception {
        return alipayController.notify(bindNotifyParams(request));
    }

    @Test
    void springBindingKeepsEveryPostedParamAndEveryDuplicateValue() throws Exception {
        MockHttpServletRequest request = notifyRequest();
        //支付宝可能随时新增参数，未在方法签名上单独声明的参数也必须完整绑定
        request.setParameter("fund_bill_list", "[{\"amount\":\"199.00\"}]");
        request.setParameter("future_param", "future_value");
        //同名参数的每一个值都必须保留，否则无法识别同名参数走私
        request.setParameter("trade_status", "TRADE_SUCCESS", "TRADE_CLOSED");
        MultiValueMap<String, String> bound = bindNotifyParams(request);
        //绑定结果必须包含本次请求的全部参数名，一个都不能丢
        assertEquals(expectedParamNames("fund_bill_list", "future_param"), bound.keySet());
        BASE_NOTIFY_PARAMS.forEach((name, value) -> {
            if (!"trade_status".equals(name)) {
                assertEquals(List.of(value), bound.get(name));
            }
        });
        assertEquals(List.of("[{\"amount\":\"199.00\"}]"), bound.get("fund_bill_list"));
        assertEquals(List.of("future_value"), bound.get("future_param"));
        //同名参数的两个值都必须以独立的列表元素保留
        assertEquals(List.of("TRADE_SUCCESS", "TRADE_CLOSED"), bound.get("trade_status"));
    }

    @Test
    void validNotifyParamsReachSignatureVerification() throws Exception {
        String result = notifyThroughBinding(notifyRequest());
        assertEquals("success", result);
        assertTrue(alipayService.notifyCalled);
        assertEquals("202406150101000001", alipayService.notifyParams.get("out_trade_no"));
        assertEquals("TRADE_SUCCESS", alipayService.notifyParams.get("trade_status"));
        assertEquals("TWFjcm9NYWxsU2lnbmF0dXJlPT0=", alipayService.notifyParams.get("sign"));
    }

    @Test
    void illegalParamNameIsRejected() throws Exception {
        MockHttpServletRequest request = notifyRequest();
        request.setParameter("out_trade_no[]", "202406150101000001");
        assertEquals("failure", notifyThroughBinding(request));
        assertFalse(alipayService.notifyCalled);
        assertNull(alipayService.notifyParams);
    }

    @Test
    void unknownParamNameOnWhitelistIsForwardedForVerification() throws Exception {
        MockHttpServletRequest request = notifyRequest();
        //参数名符合白名单的未知（后续新增）参数按原策略放行，并原样进入验签参数集合
        request.setParameter("fund_bill_list", "[{\"amount\":\"199.00\"}]");
        request.setParameter("future_param", "future_value");
        assertEquals("success", notifyThroughBinding(request));
        assertTrue(alipayService.notifyCalled);
        assertEquals("[{\"amount\":\"199.00\"}]", alipayService.notifyParams.get("fund_bill_list"));
        assertEquals("future_value", alipayService.notifyParams.get("future_param"));
        //验签需要完整的回调参数集合，未知参数不能被过滤掉
        assertEquals(expectedParamNames("fund_bill_list", "future_param"), alipayService.notifyParams.keySet());
    }

    @Test
    void duplicatedParamValuesAreRejected() throws Exception {
        MockHttpServletRequest request = notifyRequest();
        request.setParameter("out_trade_no", "202406150101000001", "202406150101000002");
        //绑定阶段两个值都在，校验阶段必须因同名参数重复而失败关闭
        assertEquals(List.of("202406150101000001", "202406150101000002"),
                bindNotifyParams(request).get("out_trade_no"));
        assertEquals("failure", notifyThroughBinding(request));
        assertFalse(alipayService.notifyCalled);
    }

    @Test
    void duplicatedUnknownParamValuesAreRejected() throws Exception {
        MockHttpServletRequest request = notifyRequest();
        //未知参数同名重复同样必须被拒绝，避免绕过重复参数校验
        request.setParameter("future_param", "value_a", "value_b");
        assertEquals("failure", notifyThroughBinding(request));
        assertFalse(alipayService.notifyCalled);
    }

    @Test
    void controlCharactersInParamValueAreRejected() throws Exception {
        MockHttpServletRequest request = notifyRequest();
        request.setParameter("subject", "订单商品\r\nsign=forged");
        assertEquals("failure", notifyThroughBinding(request));
        assertFalse(alipayService.notifyCalled);
    }

    @Test
    void oversizedParamValueIsRejected() throws Exception {
        MockHttpServletRequest request = notifyRequest();
        request.setParameter("passback_params", "a".repeat(4097));
        assertEquals("failure", notifyThroughBinding(request));
        assertFalse(alipayService.notifyCalled);
    }

    @Test
    void malformedOutTradeNoIsRejected() throws Exception {
        MockHttpServletRequest request = notifyRequest();
        request.setParameter("out_trade_no", "202406150101000001' or '1'='1");
        assertEquals("failure", notifyThroughBinding(request));
        assertFalse(alipayService.notifyCalled);
    }

    @Test
    void malformedTradeNoIsRejected() throws Exception {
        MockHttpServletRequest request = notifyRequest();
        request.setParameter("trade_no", "../../../etc/passwd");
        assertEquals("failure", notifyThroughBinding(request));
        assertFalse(alipayService.notifyCalled);
    }

    @Test
    void tooManyParamsAreRejected() throws Exception {
        MockHttpServletRequest request = notifyRequest();
        for (int i = 0; i < 101; i++) {
            request.setParameter("param_" + i, "value");
        }
        assertEquals("failure", notifyThroughBinding(request));
        assertFalse(alipayService.notifyCalled);
    }

    @Test
    void notifyWithoutTradeNumbersIsStillAccepted() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/alipay/notify");
        request.setParameter("notify_type", "trade_status_sync");
        request.setParameter("sign_type", "RSA2");
        request.setParameter("sign", "TWFjcm9NYWxsU2lnbmF0dXJlPT0=");
        assertEquals("success", notifyThroughBinding(request));
        assertTrue(alipayService.notifyCalled);
    }

    @Test
    void signedNotifyThroughBindingCompletesOrder() throws Exception {
        //完整链路：请求参数绑定 -> 参数校验 -> 验签 -> 订单完成，验签使用的参数集合必须与网关签名的内容一致
        ReflectionTestUtils.setField(alipayController, "alipayService", alipayServiceImpl);
        givenUnpaidOrder();
        Map<String, String> signedParams = signedNotifyParams("SHA256withRSA", "RSA2");
        assertEquals("success", notifyThroughBinding(notifyRequest(signedParams)));
        verify(portalOrderService).paySuccessByOrderSn(ORDER_SN, 1);
    }

    @Test
    void signedNotifyWithUnknownParamThroughBindingCompletesOrder() throws Exception {
        //支付宝新增参数也会参与网关签名，绑定与校验不能丢弃这些参数，否则验签必然失败
        ReflectionTestUtils.setField(alipayController, "alipayService", alipayServiceImpl);
        givenUnpaidOrder();
        Map<String, String> content = new LinkedHashMap<>();
        content.put("app_id", APP_ID);
        content.put("trade_status", "TRADE_SUCCESS");
        content.put("out_trade_no", ORDER_SN);
        content.put("total_amount", ORDER_PAY_AMOUNT);
        content.put("future_param", "future_value");
        Map<String, String> signedParams = signParams(content, "SHA256withRSA", "RSA2");
        assertEquals("success", notifyThroughBinding(notifyRequest(signedParams)));
        verify(portalOrderService).paySuccessByOrderSn(ORDER_SN, 1);
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
