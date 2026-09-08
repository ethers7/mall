package com.macro.mall.security.config;

import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * 跨域访问来源白名单配置
 * 未配置时不返回跨域响应头，避免不受信任的域名读取响应内容
 * <p>
 * 白名单在启动绑定配置时归一化、校验并固化为不可变集合；
 * 之后只提供两个能力：
 * <ol>
 *     <li>{@link #getAllowedOrigins()}：取出<b>配置</b>中的不可变来源集合，其元素才是可写入响应头的值</li>
 *     <li>{@link #matchesAllowedOrigin(String, String)}：用请求Origin做<b>判定</b>，只返回boolean，不返回任何请求内容</li>
 * </ol>
 * 请求Origin只参与相等性判定，不存在通往响应头的数据流，写入响应头的值只可能来自配置。
 * Created for CWE-942 remediation.
 */
@Getter
@ConfigurationProperties(prefix = "secure.cors")
public class CorsAllowedOriginsConfig {

    private static final Logger LOGGER = LoggerFactory.getLogger(CorsAllowedOriginsConfig.class);

    /**
     * 合法来源的严格格式：scheme://host[:port]
     * 仅允许http/https协议及主机名、IPv4中出现的字符，
     * 因此CR、LF、空白、逗号、路径、userinfo（@）及其他控制字符不可能通过校验（CWE-113）
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
     * 出于安全考虑不支持通配符配置；集合不可变，仅在启动绑定配置时整体替换
     */
    private List<String> allowedOrigins = Collections.emptyList();

    /**
     * 配置加载时归一化（去首尾空白、scheme与host转小写）并严格校验白名单，
     * 格式非法（含CR、LF等控制字符）的配置直接丢弃，结果固化为不可变集合，
     * 保证只有格式合法的来源可能被写入响应头
     */
    public void setAllowedOrigins(List<String> allowedOrigins) {
        this.allowedOrigins = normalize(allowedOrigins);
    }

    /**
     * @return 是否配置了白名单；未配置时不返回任何跨域响应头（fail closed）
     */
    public boolean hasAllowedOrigins() {
        return !allowedOrigins.isEmpty();
    }

    /**
     * 判定某个白名单条目与请求来源是否等价。
     * 两个入参都只参与相等性<b>判定</b>，返回值是boolean，不含任何请求内容，
     * 因此请求内容无法经由本方法流向响应头。
     *
     * @param configuredOrigin 取自{@link #getAllowedOrigins()}的白名单条目
     * @param requestOrigin    请求头中的Origin，可为null
     * @return 条目确实来自白名单且与请求来源等价时返回true
     */
    public boolean matchesAllowedOrigin(String configuredOrigin, String requestOrigin) {
        if (requestOrigin == null || requestOrigin.isEmpty() || configuredOrigin == null) {
            return false;
        }
        //只承认确实存在于不可变白名单中的条目，防止调用方传入自造的来源
        if (!allowedOrigins.contains(configuredOrigin)) {
            return false;
        }
        //白名单条目在配置加载时已校验，此处再次校验，防止绕过setAllowedOrigins直接修改集合；
        //浏览器按URL规范发送小写的scheme与host，故使用严格相等，大小写不同即判定为未命中
        return isValidOrigin(configuredOrigin) && configuredOrigin.equals(requestOrigin);
    }

    /**
     * 严格校验来源格式，仅接受scheme://host[:port]
     * 通配符、空白、路径、userinfo、CR、LF及其他控制字符均判定为非法
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
            return Collections.emptyList();
        }
        for (String configuredOrigin : configuredOrigins) {
            String origin = configuredOrigin == null
                    ? null
                    : configuredOrigin.trim().toLowerCase(Locale.ROOT);
            if (!isValidOrigin(origin)) {
                LOGGER.warn("忽略非法的跨域来源配置secure.cors.allowed-origins，仅支持scheme://host[:port]格式：{}",
                        describeRejected(configuredOrigin));
                continue;
            }
            if (!validOrigins.contains(origin)) {
                validOrigins.add(origin);
            }
        }
        //固化为不可变集合，运行期无法再被修改
        return List.copyOf(validOrigins);
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
