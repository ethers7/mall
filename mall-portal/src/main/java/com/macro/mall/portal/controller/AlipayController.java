package com.macro.mall.portal.controller;

import cn.hutool.core.util.StrUtil;
import com.macro.mall.common.api.CommonResult;
import com.macro.mall.portal.config.AlipayConfig;
import com.macro.mall.portal.domain.AliPayParam;
import com.macro.mall.portal.service.AlipayService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * @auther macrozheng
 * @description 支付宝支付Controller
 * @date 2023/9/8
 * @github https://github.com/macrozheng
 */
@Slf4j
@Controller
@Tag(name = "AlipayController", description = "支付宝支付相关接口")
@RequestMapping("/alipay")
public class AlipayController {

    /**
     * 异步回调执行失败时返回给支付宝的结果
     */
    private static final String NOTIFY_FAILURE = "failure";
    /**
     * 异步回调参数个数上限
     */
    private static final int MAX_NOTIFY_PARAM_COUNT = 100;
    /**
     * 异步回调单个参数值的长度上限
     */
    private static final int MAX_NOTIFY_PARAM_VALUE_LENGTH = 4096;
    /**
     * 回调参数名白名单：字母开头，只允许字母、数字和下划线
     */
    private static final Pattern NOTIFY_PARAM_NAME_PATTERN = Pattern.compile("[A-Za-z][A-Za-z0-9_]{0,63}");
    /**
     * 回调参数值中不允许出现的控制字符
     */
    private static final Pattern CONTROL_CHAR_PATTERN = Pattern.compile("[\\p{Cntrl}]");
    /**
     * 商户订单号、支付宝交易号白名单：只允许字母、数字、下划线和中划线
     */
    private static final Pattern TRADE_NO_PATTERN = Pattern.compile("[A-Za-z0-9_-]{1,64}");

    @Autowired
    private AlipayConfig alipayConfig;
    @Autowired
    private AlipayService alipayService;

    @Operation(summary = "支付宝电脑网站支付")
    @RequestMapping(value = "/pay", method = RequestMethod.GET)
    public void pay(AliPayParam aliPayParam, HttpServletResponse response) throws IOException {
        response.setContentType("text/html;charset=" + alipayConfig.getCharset());
        response.getWriter().write(alipayService.pay(aliPayParam));
        response.getWriter().flush();
        response.getWriter().close();
    }

    @Operation(summary = "支付宝手机网站支付")
    @RequestMapping(value = "/webPay", method = RequestMethod.GET)
    public void webPay(AliPayParam aliPayParam, HttpServletResponse response) throws IOException {
        response.setContentType("text/html;charset=" + alipayConfig.getCharset());
        response.getWriter().write(alipayService.webPay(aliPayParam));
        response.getWriter().flush();
        response.getWriter().close();
    }

    @Operation(summary = "支付宝异步回调",description = "必须为POST请求，执行成功返回success，执行失败返回failure")
    @RequestMapping(value = "/notify", method = RequestMethod.POST)
    public String notify(HttpServletRequest request){
        Map<String, String> params;
        try {
            // 回调参数完全由外部提供，校验通过后才允许进入签名校验及订单处理流程
            params = extractNotifyParams(request);
        } catch (IllegalArgumentException e) {
            log.warn("支付宝异步回调参数校验失败：{}", e.getMessage());
            return NOTIFY_FAILURE;
        }
        return alipayService.notify(params);
    }

    /**
     * 提取并校验支付宝异步回调参数，参数名、参数值均采用白名单校验，
     * 校验不通过时抛出异常，由调用方返回failure（失败关闭）。
     */
    private Map<String, String> extractNotifyParams(HttpServletRequest request) {
        Map<String, String[]> requestParams = request.getParameterMap();
        if (requestParams.size() > MAX_NOTIFY_PARAM_COUNT) {
            throw new IllegalArgumentException("回调参数个数超过上限");
        }
        Map<String, String> params = new HashMap<>();
        for (Map.Entry<String, String[]> entry : requestParams.entrySet()) {
            String name = entry.getKey();
            if (name == null || !NOTIFY_PARAM_NAME_PATTERN.matcher(name).matches()) {
                throw new IllegalArgumentException("回调参数名不合法");
            }
            String[] values = entry.getValue();
            if (values == null || values.length != 1) {
                throw new IllegalArgumentException("回调参数值缺失或重复");
            }
            String value = values[0];
            if (value == null || value.length() > MAX_NOTIFY_PARAM_VALUE_LENGTH
                    || CONTROL_CHAR_PATTERN.matcher(value).find()) {
                throw new IllegalArgumentException("回调参数值不合法");
            }
            params.put(name, value);
        }
        // 订单号会用于订单查询和状态变更，必须符合固定格式
        validateTradeNo(params.get("out_trade_no"));
        validateTradeNo(params.get("trade_no"));
        return params;
    }

    /**
     * 校验商户订单号、支付宝交易号格式，参数不存在时无需校验
     */
    private void validateTradeNo(String tradeNo) {
        if (tradeNo == null) {
            return;
        }
        if (!TRADE_NO_PATTERN.matcher(tradeNo).matches()) {
            throw new IllegalArgumentException("订单号格式不合法");
        }
    }

    @Operation(summary = "支付宝统一收单线下交易查询",description = "订单支付成功返回交易状态：TRADE_SUCCESS")
    @RequestMapping(value = "/query", method = RequestMethod.GET)
    @ResponseBody
    public CommonResult<String> query(String outTradeNo, String tradeNo){
        // 查询参数完全由外部提供，且商户订单号会用于订单状态变更，校验通过后才允许查询
        try {
            validateQueryParams(outTradeNo, tradeNo);
        } catch (IllegalArgumentException e) {
            log.warn("支付宝交易查询参数校验失败：{}", e.getMessage());
            return CommonResult.validateFailed(e.getMessage());
        }
        return CommonResult.success(alipayService.query(outTradeNo,tradeNo));
    }

    /**
     * 校验交易查询参数：商户订单号、支付宝交易号至少传一个，且传入的参数格式必须合法，
     * 校验不通过时抛出异常，由调用方返回参数校验失败（失败关闭）。
     */
    private void validateQueryParams(String outTradeNo, String tradeNo) {
        boolean hasOutTradeNo = StrUtil.isNotEmpty(outTradeNo);
        boolean hasTradeNo = StrUtil.isNotEmpty(tradeNo);
        if (!hasOutTradeNo && !hasTradeNo) {
            throw new IllegalArgumentException("商户订单号和支付宝交易号至少传一个");
        }
        if (hasOutTradeNo) {
            validateTradeNo(outTradeNo);
        }
        if (hasTradeNo) {
            validateTradeNo(tradeNo);
        }
    }
}
