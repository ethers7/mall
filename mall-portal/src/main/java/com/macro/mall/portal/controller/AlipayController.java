package com.macro.mall.portal.controller;

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

    /**
     * 支付宝异步回调参数的校验规则，回调失败统一返回failure
     */
    private static final String NOTIFY_FAILURE = "failure";
    private static final int MAX_NOTIFY_PARAM_COUNT = 64;
    private static final int MAX_NOTIFY_PARAM_VALUE_LENGTH = 4096;
    private static final Pattern NOTIFY_PARAM_NAME_PATTERN = Pattern.compile("[A-Za-z0-9_.\\-]{1,64}");

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
        // 回调参数完全由外部提交，数量异常时直接拒绝，不进入签名校验和业务处理
        if (requestParams.isEmpty() || requestParams.size() > MAX_NOTIFY_PARAM_COUNT) {
            return NOTIFY_FAILURE;
        }
        for (Map.Entry<String, String[]> entry : requestParams.entrySet()) {
            String name = entry.getKey();
            String[] values = entry.getValue();
            // 参数名需符合支付宝通知参数的白名单字符；同名参数重复出现时无法确定参与验签的值，直接拒绝
            if (name == null || !NOTIFY_PARAM_NAME_PATTERN.matcher(name).matches()
                    || values == null || values.length != 1) {
                return NOTIFY_FAILURE;
            }
            String value = values[0];
            if (value == null || value.length() > MAX_NOTIFY_PARAM_VALUE_LENGTH) {
                return NOTIFY_FAILURE;
            }
            params.put(name, value);
        }
        // 缺少签名参数时验签无法真正生效，直接拒绝
        String sign = params.get("sign");
        if (sign == null || sign.isEmpty()) {
            return NOTIFY_FAILURE;
        }
        return alipayService.notify(params);
    }

    @Operation(summary = "支付宝统一收单线下交易查询",description = "订单支付成功返回交易状态：TRADE_SUCCESS")
    @RequestMapping(value = "/query", method = RequestMethod.GET)
    @ResponseBody
    public CommonResult<String> query(String outTradeNo, String tradeNo){
        return CommonResult.success(alipayService.query(outTradeNo,tradeNo));
    }
}
