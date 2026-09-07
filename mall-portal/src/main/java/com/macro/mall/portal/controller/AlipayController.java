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
     * 支付宝异步回调参数名称的白名单格式
     */
    private static final Pattern NOTIFY_PARAM_NAME_PATTERN = Pattern.compile("^[\\p{Alnum}_.\\-\\[\\]]{1,64}$");
    /**
     * 支付宝异步回调单个参数值的最大长度
     */
    private static final int NOTIFY_PARAM_VALUE_MAX_LENGTH = 4096;
    /**
     * 支付宝异步回调参数的最大数量
     */
    private static final int NOTIFY_PARAM_MAX_COUNT = 100;
    /**
     * 支付宝异步回调处理失败时返回的结果
     */
    private static final String NOTIFY_FAILURE = "failure";

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
        // 回调参数由外部请求传入，均视为不可信数据，需要先做边界校验；
        // 校验不通过时整体拒绝该回调，不能丢弃或修改单个参数，否则会破坏SDK的验签结果
        if (requestParams.isEmpty() || requestParams.size() > NOTIFY_PARAM_MAX_COUNT) {
            log.warn("支付宝异步回调参数数量非法！");
            return NOTIFY_FAILURE;
        }
        for (Map.Entry<String, String[]> entry : requestParams.entrySet()) {
            String name = entry.getKey();
            if (name == null || !NOTIFY_PARAM_NAME_PATTERN.matcher(name).matches()) {
                // 不回显非法参数名称，避免日志注入
                log.warn("支付宝异步回调参数名称非法！");
                return NOTIFY_FAILURE;
            }
            String[] values = entry.getValue();
            String value = (values == null || values.length == 0) ? null : values[0];
            if (value == null || value.length() > NOTIFY_PARAM_VALUE_MAX_LENGTH || containsControlCharacter(value)) {
                log.warn("支付宝异步回调参数值非法！参数名称：{}", name);
                return NOTIFY_FAILURE;
            }
            // 参数原样传递，保证验签使用的参数集合与请求完全一致
            params.put(name, value);
        }
        if (StrUtil.isBlank(params.get("sign"))) {
            log.warn("支付宝异步回调缺少签名参数！");
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

    /**
     * 判断参数值中是否包含控制字符，防止换行等字符被写入日志或响应
     *
     * @param value 待校验的参数值
     * @return 包含控制字符时返回true
     */
    private boolean containsControlCharacter(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 0x20 || c == 0x7F) {
                return true;
            }
        }
        return false;
    }
}
