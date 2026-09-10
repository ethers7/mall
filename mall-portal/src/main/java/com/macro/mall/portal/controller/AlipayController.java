package com.macro.mall.portal.controller;

import cn.hutool.core.util.StrUtil;
import com.macro.mall.common.api.CommonResult;
import com.macro.mall.portal.config.AlipayConfig;
import com.macro.mall.portal.domain.AliPayParam;
import com.macro.mall.portal.service.AlipayService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@Controller
@Tag(name = "AlipayController", description = "支付宝支付相关接口")
@RequestMapping("/alipay")
public class AlipayController {

    // 支付宝异步回调中订单号、交易状态等关键字段的合法格式，用于在签名校验前拦截明显畸形的请求
    private static final Pattern OUT_TRADE_NO_PATTERN = Pattern.compile("^[A-Za-z0-9]{1,64}$");
    private static final Pattern TRADE_STATUS_PATTERN = Pattern.compile("^[A-Z_]{1,32}$");

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
        Map<String, String> params = new HashMap<>();
        Map<String, String[]> requestParams = request.getParameterMap();
        for (String name : requestParams.keySet()) {
            String value = request.getParameter(name);
            if (value != null) {
                params.put(name, value.trim());
            }
        }
        // 在进入签名校验及业务处理前，先校验关键字段的基本格式，拒绝明显畸形/非法的回调请求
        if (!isValidOutTradeNo(params.get("out_trade_no")) || !isValidTradeStatus(params.get("trade_status"))) {
            return "failure";
        }
        return alipayService.notify(params);
    }

    /**
     * 校验支付宝异步回调中的商户订单号格式
     */
    private boolean isValidOutTradeNo(String outTradeNo) {
        return StrUtil.isNotBlank(outTradeNo) && OUT_TRADE_NO_PATTERN.matcher(outTradeNo).matches();
    }

    /**
     * 校验支付宝异步回调中的交易状态格式
     */
    private boolean isValidTradeStatus(String tradeStatus) {
        return StrUtil.isNotBlank(tradeStatus) && TRADE_STATUS_PATTERN.matcher(tradeStatus).matches();
    }

    @Operation(summary = "支付宝统一收单线下交易查询",description = "订单支付成功返回交易状态：TRADE_SUCCESS")
    @RequestMapping(value = "/query", method = RequestMethod.GET)
    @ResponseBody
    public CommonResult<String> query(String outTradeNo, String tradeNo){
        return CommonResult.success(alipayService.query(outTradeNo,tradeNo));
    }
}
