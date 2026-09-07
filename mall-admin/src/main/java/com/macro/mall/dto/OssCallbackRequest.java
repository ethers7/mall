package com.macro.mall.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.EqualsAndHashCode;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * OSS上传成功后的回调请求参数，参数完全来自外部请求，绑定时即完成格式校验
 * Created by macro on 2018/5/17.
 */
@Data
@EqualsAndHashCode
public class OssCallbackRequest {
    /**
     * OSS的object key最长1024个字符，仅允许字母、数字以及少量安全符号
     */
    public static final int MAX_OBJECT_KEY_LENGTH = 1024;
    public static final int MAX_MIME_TYPE_LENGTH = 255;
    public static final String OBJECT_KEY_REGEX = "[\\p{L}\\p{N}!\\-_.*()/]+";
    public static final String SIZE_REGEX = "\\d{1,18}";
    /**
     * 非图片文件时OSS可能回传空值，因此mimeType与图片宽高允许为空字符串
     */
    public static final String MIME_TYPE_REGEX = "^$|[A-Za-z0-9][A-Za-z0-9!#$&^_.+\\-]*/[A-Za-z0-9][A-Za-z0-9!#$&^_.+\\-]*";
    public static final String DIMENSION_REGEX = "^$|\\d{1,6}";

    @NotEmpty
    @Size(max = MAX_OBJECT_KEY_LENGTH)
    @Pattern(regexp = OBJECT_KEY_REGEX)
    @Schema(title = "文件名称", requiredMode = Schema.RequiredMode.REQUIRED)
    private String filename;
    @NotEmpty
    @Pattern(regexp = SIZE_REGEX)
    @Schema(title = "文件大小", requiredMode = Schema.RequiredMode.REQUIRED)
    private String size;
    @Size(max = MAX_MIME_TYPE_LENGTH)
    @Pattern(regexp = MIME_TYPE_REGEX)
    @Schema(title = "文件的mimeType")
    private String mimeType;
    @Pattern(regexp = DIMENSION_REGEX)
    @Schema(title = "图片文件的宽")
    private String width;
    @Pattern(regexp = DIMENSION_REGEX)
    @Schema(title = "图片文件的高")
    private String height;
}
