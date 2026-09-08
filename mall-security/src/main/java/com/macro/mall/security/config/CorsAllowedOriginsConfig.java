package com.macro.mall.security.config;

import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * 跨域访问来源白名单配置
 * 未配置时不返回跨域响应头，避免不受信任的域名读取响应内容
 * Created for CWE-942 remediation.
 */
@Getter
@ConfigurationProperties(prefix = "secure.cors")
public class CorsAllowedOriginsConfig {

    private static final Logger LOGGER = LoggerFactory.getLogger(CorsAllowedOriginsConfig.class);

    /**
     * 合法来源的严格格式：scheme://host[:port]
     * 仅允许http/https协议及主机名、IPv4中出现的字符，
     * 因此CR、LF、空白及其他控制字符不可能通过校验（CWE-113）
     */
    private static final Pattern ORIGIN_PATTERN = Pattern.compile(
            "^https?://[A-Za-z0-9]([A-Za-z0-9\\-]{0,61}[A-Za-z0-9])?"
                    + "(\\.[A-Za-z0-9]([A-Za-z0-9\\-]{0,61}[A-Za-z0-9])?)*"
                    + "(:[1-9][0-9]{0,4})?\\z");

    /**
     * 日志中出现的非可打印字符统一替换，避免非法配置污染日志
     */
    private static final Pattern NON_PRINTABLE_PATTERN = Pattern.compile("[^\\x20-\\x7E]");

    private static final int MAX_ORIGIN_LENGTH = 255;

    private static final int MAX_LOGGED_LENGTH = 64;

    /**
     * 允许跨域访问的来源，如：https://admin.example.com
     * 出于安全考虑不支持通配符配置
     */
    private List<String> allowedOrigins = new ArrayList<>();

    /**
     * 配置加载时归一化并严格校验白名单，格式非法（含CR、LF等控制字符）的配置直接丢弃，
     * 保证只有格式合法的来源可能被写入响应头
     */
    public void setAllowedOrigins(List<String> allowedOrigins) {
        this.allowedOrigins = normalize(allowedOrigins);
    }

    /**
     * 校验请求来源是否在白名单中
     *
     * @param requestOrigin 请求头中的Origin
     * @return 白名单中配置的来源，不在白名单中时返回null
     */
    public String resolveAllowedOrigin(String requestOrigin) {
        if (requestOrigin == null || requestOrigin.isBlank()) {
            return null;
        }
        String origin = requestOrigin.trim();
        for (String allowedOrigin : allowedOrigins) {
            //白名单条目在配置加载时已校验，此处再次校验，防止绕过setAllowedOrigins直接修改集合
            if (!isValidOrigin(allowedOrigin)) {
                continue;
            }
            if (allowedOrigin.equalsIgnoreCase(origin)) {
                //返回值取自配置而非请求，避免请求内容进入响应头
                return allowedOrigin;
            }
        }
        return null;
    }

    /**
     * 严格校验来源格式，仅接受scheme://host[:port]
     * 通配符、空白、CR、LF及其他控制字符均判定为非法
     *
     * @param origin 待校验的来源
     * @return 格式合法时返回true
     */
    public static boolean isValidOrigin(String origin) {
        if (origin == null || origin.isEmpty() || origin.length() > MAX_ORIGIN_LENGTH) {
            return false;
        }
        return ORIGIN_PATTERN.matcher(origin).matches();
    }

    private static List<String> normalize(List<String> configuredOrigins) {
        List<String> validOrigins = new ArrayList<>();
        if (configuredOrigins == null) {
            return validOrigins;
        }
        for (String configuredOrigin : configuredOrigins) {
            String origin = configuredOrigin == null ? null : configuredOrigin.trim();
            if (!isValidOrigin(origin)) {
                LOGGER.warn("忽略非法的跨域来源配置secure.cors.allowed-origins，仅支持scheme://host[:port]格式：{}",
                        describeRejected(configuredOrigin));
                continue;
            }
            if (!validOrigins.contains(origin)) {
                validOrigins.add(origin);
            }
        }
        return validOrigins;
    }

    private static String describeRejected(String configuredOrigin) {
        if (configuredOrigin == null) {
            return "<null>";
        }
        String sanitized = NON_PRINTABLE_PATTERN.matcher(configuredOrigin).replaceAll("?");
        if (sanitized.length() > MAX_LOGGED_LENGTH) {
            return sanitized.substring(0, MAX_LOGGED_LENGTH) + "...";
        }
        return sanitized;
    }
}
