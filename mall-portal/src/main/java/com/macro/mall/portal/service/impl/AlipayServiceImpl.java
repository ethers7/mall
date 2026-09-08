package com.macro.mall.portal.service.impl;

import cn.hutool.core.collection.CollUtil;
import cn.hutool.core.util.StrUtil;
import com.alibaba.fastjson.JSONObject;
import com.alipay.api.AlipayApiException;
import com.alipay.api.AlipayClient;
import com.alipay.api.internal.util.AlipaySignature;
import com.alipay.api.request.AlipayTradePagePayRequest;
import com.alipay.api.request.AlipayTradeQueryRequest;
import com.alipay.api.request.AlipayTradeWapPayRequest;
import com.alipay.api.response.AlipayTradeQueryResponse;
import com.macro.mall.mapper.OmsOrderMapper;
import com.macro.mall.model.OmsOrder;
import com.macro.mall.model.OmsOrderExample;
import com.macro.mall.portal.config.AlipayConfig;
import com.macro.mall.portal.domain.AliPayParam;
import com.macro.mall.portal.service.AlipayService;
import com.macro.mall.portal.service.OmsPortalOrderService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

/**
 * @auther macrozheng
 * @description 支付宝支付Service实现类
 * @date 2023/9/8
 * @github https://github.com/macrozheng
 */
@Slf4j
@Service
public class AlipayServiceImpl implements AlipayService {

    /**
     * 异步回调处理成功时返回给支付宝的结果
     */
    private static final String NOTIFY_SUCCESS = "success";
    /**
     * 异步回调处理失败时返回给支付宝的结果
     */
    private static final String NOTIFY_FAILURE = "failure";

    @Autowired
    private AlipayConfig alipayConfig;
    @Autowired
    private AlipayClient alipayClient;
    @Autowired
    private OmsOrderMapper orderMapper;
    @Autowired
    private OmsPortalOrderService portalOrderService;
    @Override
    public String pay(AliPayParam aliPayParam) {
        AlipayTradePagePayRequest request = new AlipayTradePagePayRequest();
        if(StrUtil.isNotEmpty(alipayConfig.getNotifyUrl())){
            //异步接收地址，公网可访问
            request.setNotifyUrl(alipayConfig.getNotifyUrl());
        }
        if(StrUtil.isNotEmpty(alipayConfig.getReturnUrl())){
            //同步跳转地址
            request.setReturnUrl(alipayConfig.getReturnUrl());
        }
        //******必传参数******
        JSONObject bizContent = new JSONObject();
        //商户订单号，商家自定义，保持唯一性
        bizContent.put("out_trade_no", aliPayParam.getOutTradeNo());
        //支付金额，最小值0.01元
        bizContent.put("total_amount", aliPayParam.getTotalAmount());
        //订单标题，不可使用特殊符号
        bizContent.put("subject", aliPayParam.getSubject());
        //电脑网站支付场景固定传值FAST_INSTANT_TRADE_PAY
        bizContent.put("product_code", "FAST_INSTANT_TRADE_PAY");
        request.setBizContent(bizContent.toString());
        String formHtml = null;
        try {
            formHtml = alipayClient.pageExecute(request).getBody();
        } catch (AlipayApiException e) {
            e.printStackTrace();
        }
        return formHtml;
    }

    @Override
    public String notify(Map<String, String> params) {
        //支付宝公钥是认证异步回调来源的唯一凭据，未配置（缺失或为空）时无法完成验签，
        //此处直接失败关闭，避免验签始终异常却被忽略、订单被伪造的回调置为已支付；
        //公钥由部署环境注入（配置项alipay.alipayPublicKey），配置文件中不提供任何默认值
        String alipayPublicKey = StrUtil.trim(alipayConfig.getAlipayPublicKey());
        if (StrUtil.isEmpty(alipayPublicKey)) {
            log.error("支付宝公钥未配置，无法校验支付回调签名，拒绝处理支付回调！");
            return NOTIFY_FAILURE;
        }
        //缺少签名的回调不可能通过验签，提前失败关闭
        if (StrUtil.isEmpty(params.get("sign"))) {
            log.warn("支付回调缺少签名参数！");
            return NOTIFY_FAILURE;
        }
        //调用SDK验证签名，签名算法固定使用服务端配置（AlipayConfig已限制为RSA2），
        //不使用回调参数中攻击者可控的sign_type，避免验签算法被降级
        boolean signVerified;
        try {
            signVerified = AlipaySignature.rsaCheckV1(params, alipayPublicKey, alipayConfig.getCharset(), alipayConfig.getSignType());
        } catch (AlipayApiException e) {
            //验签异常同样视为验签失败，不允许继续处理订单
            log.error("支付回调签名校验异常！",e);
            return NOTIFY_FAILURE;
        }
        if (!signVerified) {
            log.warn("支付回调签名校验失败！");
            return NOTIFY_FAILURE;
        }
        //验签使用的是支付宝平台公钥，其他商户应用的回调也能验签通过，必须校验应用ID为本商户应用
        String appId = params.get("app_id");
        if (StrUtil.isEmpty(appId) || !appId.equals(StrUtil.trim(alipayConfig.getAppId()))) {
            log.warn("支付回调应用ID与配置不一致，拒绝处理支付回调！");
            return NOTIFY_FAILURE;
        }
        String tradeStatus = params.get("trade_status");
        if(!"TRADE_SUCCESS".equals(tradeStatus)){
            log.warn("订单未支付成功，trade_status:{}",tradeStatus);
            return NOTIFY_FAILURE;
        }
        String outTradeNo = params.get("out_trade_no");
        if (StrUtil.isEmpty(outTradeNo)) {
            log.warn("支付回调缺少商户订单号！");
            return NOTIFY_FAILURE;
        }
        //只有仍处于待付款状态的订单才需要处理，重复或被重放的回调不会再次触发订单完成
        OmsOrder order = getUnpaidOrder(outTradeNo);
        if (order == null) {
            log.info("待付款订单不存在或已处理，忽略本次支付回调，outTradeNo:{}",outTradeNo);
            return NOTIFY_SUCCESS;
        }
        //回调金额必须不小于订单应付金额，避免少付金额的回调把订单置为已支付
        if (!isNotifyAmountEnough(params.get("total_amount"), order.getPayAmount())) {
            log.error("支付回调金额与订单应付金额不一致，拒绝处理支付回调，outTradeNo:{}",outTradeNo);
            return NOTIFY_FAILURE;
        }
        log.info("notify方法被调用了，tradeStatus:{}",tradeStatus);
        portalOrderService.paySuccessByOrderSn(outTradeNo,1);
        return NOTIFY_SUCCESS;
    }

    /**
     * 查询指定订单号待付款且未删除的订单，不存在时返回null
     */
    private OmsOrder getUnpaidOrder(String orderSn) {
        OmsOrderExample example = new OmsOrderExample();
        example.createCriteria()
                .andOrderSnEqualTo(orderSn)
                .andStatusEqualTo(0)
                .andDeleteStatusEqualTo(0);
        List<OmsOrder> orderList = orderMapper.selectByExample(example);
        if (CollUtil.isEmpty(orderList)) {
            return null;
        }
        return orderList.get(0);
    }

    /**
     * 校验支付回调金额是否不小于订单应付金额，
     * 回调金额缺失、格式非法或订单应付金额未知时返回false（失败关闭）
     */
    private boolean isNotifyAmountEnough(String notifyTotalAmount, BigDecimal orderPayAmount) {
        if (StrUtil.isEmpty(notifyTotalAmount) || orderPayAmount == null) {
            return false;
        }
        try {
            return new BigDecimal(notifyTotalAmount).compareTo(orderPayAmount) >= 0;
        } catch (NumberFormatException e) {
            log.warn("支付回调金额格式非法！");
            return false;
        }
    }

    @Override
    public String query(String outTradeNo, String tradeNo) {
        AlipayTradeQueryRequest request = new AlipayTradeQueryRequest();
        //******必传参数******
        JSONObject bizContent = new JSONObject();
        //设置查询参数，out_trade_no和trade_no至少传一个
        if(StrUtil.isNotEmpty(outTradeNo)){
            bizContent.put("out_trade_no",outTradeNo);
        }
        if(StrUtil.isNotEmpty(tradeNo)){
            bizContent.put("trade_no",tradeNo);
        }
        //交易结算信息: trade_settle_info
        String[] queryOptions = {"trade_settle_info"};
        bizContent.put("query_options", queryOptions);
        request.setBizContent(bizContent.toString());
        AlipayTradeQueryResponse response = null;
        try {
            response = alipayClient.execute(request);
        } catch (AlipayApiException e) {
            log.error("查询支付宝账单异常！",e);
        }
        if(response.isSuccess()){
            log.info("查询支付宝账单成功！");
            if("TRADE_SUCCESS".equals(response.getTradeStatus())){
                portalOrderService.paySuccessByOrderSn(outTradeNo,1);
            }
        } else {
            log.error("查询支付宝账单失败！");
        }
        //交易状态：WAIT_BUYER_PAY（交易创建，等待买家付款）、TRADE_CLOSED（未付款交易超时关闭，或支付完成后全额退款）、TRADE_SUCCESS（交易支付成功）、TRADE_FINISHED（交易结束，不可退款）
        return response.getTradeStatus();
    }

    @Override
    public String webPay(AliPayParam aliPayParam) {
        AlipayTradeWapPayRequest request = new AlipayTradeWapPayRequest ();
        if(StrUtil.isNotEmpty(alipayConfig.getNotifyUrl())){
            //异步接收地址，公网可访问
            request.setNotifyUrl(alipayConfig.getNotifyUrl());
        }
        if(StrUtil.isNotEmpty(alipayConfig.getReturnUrl())){
            //同步跳转地址
            request.setReturnUrl(alipayConfig.getReturnUrl());
        }
        //******必传参数******
        JSONObject bizContent = new JSONObject();
        //商户订单号，商家自定义，保持唯一性
        bizContent.put("out_trade_no", aliPayParam.getOutTradeNo());
        //支付金额，最小值0.01元
        bizContent.put("total_amount", aliPayParam.getTotalAmount());
        //订单标题，不可使用特殊符号
        bizContent.put("subject", aliPayParam.getSubject());
        //手机网站支付默认传值FAST_INSTANT_TRADE_PAY
        bizContent.put("product_code", "QUICK_WAP_WAY");
        request.setBizContent(bizContent.toString());
        String formHtml = null;
        try {
            formHtml = alipayClient.pageExecute(request).getBody();
        } catch (AlipayApiException e) {
            e.printStackTrace();
        }
        return formHtml;
    }
}
