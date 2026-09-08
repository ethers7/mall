package com.macro.mall.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.EqualsAndHashCode;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * OSS上传成功回调的请求参数。
 * 参数名与上传策略中约定的回调体（filename、size、mimeType、width、height）保持一致，
 * 由Spring在Controller边界完成绑定和白名单校验，Service层不再读取原始请求参数。
 * Created by macro on 2018/5/17.
 */
@Data
@EqualsAndHashCode
public class OssCallbackRequest {

    /**
     * 上传回调中对象名（文件名）的最大长度
     */
    public static final int MAX_FILENAME_LENGTH = 255;
    /**
     * 对象名白名单：只允许字母、数字、下划线、中划线、点号和目录分隔符，且必须以字母或数字开头
     */
    public static final String FILENAME_REGEX = "[A-Za-z0-9][A-Za-z0-9._/-]*";
    /**
     * 数字类型回调参数白名单（文件大小、图片宽高）
     */
    public static final String NUMERIC_REGEX = "[0-9]{1,19}";
    /**
     * mimeType白名单，形如image/jpeg
     */
    public static final String MIME_TYPE_REGEX = "[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,63}/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,63}";
    /**
     * 非图片文件的宽高、大小、mimeType可能为空，为空时允许通过绑定层校验，
     * 由Service层继续做失败关闭的校验
     */
    private static final String OPTIONAL_NUMERIC_REGEX = "(" + NUMERIC_REGEX + ")?";
    private static final String OPTIONAL_MIME_TYPE_REGEX = "(" + MIME_TYPE_REGEX + ")?";

    @NotEmpty(message = "不能为空")
    @Size(max = MAX_FILENAME_LENGTH, message = "长度不能超过255")
    @Pattern(regexp = FILENAME_REGEX, message = "包含非法字符")
    @Schema(title = "文件名称", requiredMode = Schema.RequiredMode.REQUIRED)
    private String filename;
    @Pattern(regexp = OPTIONAL_NUMERIC_REGEX, message = "参数不合法")
    @Schema(title = "文件大小")
    private String size;
    @Pattern(regexp = OPTIONAL_MIME_TYPE_REGEX, message = "参数不合法")
    @Schema(title = "文件的mimeType")
    private String mimeType;
    @Pattern(regexp = OPTIONAL_NUMERIC_REGEX, message = "参数不合法")
    @Schema(title = "图片文件的宽")
    private String width;
    @Pattern(regexp = OPTIONAL_NUMERIC_REGEX, message = "参数不合法")
    @Schema(title = "图片文件的高")
    private String height;
}
