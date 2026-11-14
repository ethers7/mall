package com.macro.mall.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * OSS上传成功回调的入参（由框架绑定并通过Bean Validation白名单校验）
 */
@Data
public class OssCallbackRequest {
    @Schema(title = "文件对象名")
    @NotEmpty(message = "非法的filename参数")
    @Size(max = 1024, message = "非法的filename参数")
    @Pattern(regexp = "^(?!/)(?!(.*/)?\\.{1,2}(/|$))[\\p{L}\\p{N}._/ ()+-]+$", message = "非法的filename参数")
    private String filename;
    @Schema(title = "文件大小")
    @Pattern(regexp = "^[0-9]{0,15}$", message = "非法的size参数")
    private String size;
    @Schema(title = "文件的mimeType")
    @NotEmpty(message = "非法的mimeType参数")
    @Pattern(regexp = "^[A-Za-z0-9!#$&^_.+-]{1,127}/[A-Za-z0-9!#$&^_.+-]{1,127}$", message = "非法的mimeType参数")
    private String mimeType;
    @Schema(title = "图片文件的宽")
    @Pattern(regexp = "^[0-9]{0,15}$", message = "非法的width参数")
    private String width;
    @Schema(title = "图片文件的高")
    @Pattern(regexp = "^[0-9]{0,15}$", message = "非法的height参数")
    private String height;
}
