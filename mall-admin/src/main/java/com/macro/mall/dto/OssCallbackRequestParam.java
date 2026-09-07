package com.macro.mall.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.EqualsAndHashCode;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * OSS上传成功回调的请求参数，参数由OSS以表单形式回调传入，均视为不可信数据，
 * 在Controller层通过Bean Validation声明式校验后才能进入业务代码
 * Created by macro on 2018/5/17.
 */
@Data
@EqualsAndHashCode
public class OssCallbackRequestParam {

    /**
     * OSS对象名称的白名单格式：只允许字母、数字、常见文件名符号及目录分隔符，
     * 不允许出现路径穿越（..）、反斜杠、协议分隔符及URL特殊字符，长度上限与OSS对象名称一致。
     * 使用\A、\z锚定，避免结尾换行等字符绕过校验
     */
    public static final String OBJECT_NAME_REGEX = "\\A(?!.*\\.\\.)[\\p{L}\\p{N}][\\p{L}\\p{N}\\-._/() ]{0,1022}\\z";
    /**
     * mimeType的白名单格式，如image/jpeg；非图片等场景下OSS可能回调空值，故允许为空
     */
    public static final String MIME_TYPE_REGEX = "\\A([\\p{Alnum}][\\p{Alnum}!#$&^_.+-]{0,63}/[\\p{Alnum}][\\p{Alnum}!#$&^_.+-]{0,63})?\\z";
    /**
     * 数字类参数（文件大小、图片宽高）的白名单格式；非图片文件不会回调图片宽高，故允许为空
     */
    public static final String NUMERIC_REGEX = "\\A(\\p{Digit}{1,19})?\\z";

    @NotBlank(message = "不能为空")
    @Pattern(regexp = OBJECT_NAME_REGEX, message = "格式不合法")
    @Schema(title = "OSS对象名称", requiredMode = Schema.RequiredMode.REQUIRED)
    private String filename;

    @Pattern(regexp = NUMERIC_REGEX, message = "必须为数字")
    @Schema(title = "文件大小")
    private String size;

    @Pattern(regexp = MIME_TYPE_REGEX, message = "格式不合法")
    @Schema(title = "文件的mimeType")
    private String mimeType;

    @Pattern(regexp = NUMERIC_REGEX, message = "必须为数字")
    @Schema(title = "图片文件的宽")
    private String width;

    @Pattern(regexp = NUMERIC_REGEX, message = "必须为数字")
    @Schema(title = "图片文件的高")
    private String height;
}
