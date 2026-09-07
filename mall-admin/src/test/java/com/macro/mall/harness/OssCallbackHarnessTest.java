package com.macro.mall.harness;

import com.macro.mall.common.exception.ApiException;
import com.macro.mall.dto.OssCallbackRequestParam;
import com.macro.mall.dto.OssCallbackResult;
import com.macro.mall.service.impl.OssServiceImpl;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** OSS上传回调参数校验的单元测试 — no Spring context, no network. */
class OssCallbackHarnessTest {

    private static final String BUCKET_NAME = "macro-oss";
    private static final String ENDPOINT = "oss-cn-shenzhen.aliyuncs.com";

    private static ValidatorFactory validatorFactory;
    private static Validator validator;

    private OssServiceImpl ossService;

    @BeforeAll
    static void setUpValidator() {
        validatorFactory = Validation.buildDefaultValidatorFactory();
        validator = validatorFactory.getValidator();
    }

    @AfterAll
    static void tearDownValidator() {
        validatorFactory.close();
    }

    @BeforeEach
    void setUp() {
        ossService = new OssServiceImpl();
        ReflectionTestUtils.setField(ossService, "ALIYUN_OSS_BUCKET_NAME", BUCKET_NAME);
        ReflectionTestUtils.setField(ossService, "ALIYUN_OSS_ENDPOINT", ENDPOINT);
    }

    @Test
    void legitimateCallbackIsAccepted() {
        OssCallbackRequestParam param = callbackParam("mall/images/20240615/photo (1).jpg");
        param.setSize("10240");
        param.setMimeType("image/jpeg");
        param.setWidth("800");
        param.setHeight("600");

        assertTrue(violations(param).isEmpty(), "合法回调参数不应产生校验错误");

        OssCallbackResult result = ossService.callback(param);

        assertEquals("http://" + BUCKET_NAME + "." + ENDPOINT + "/mall/images/20240615/photo (1).jpg",
                result.getFilename());
        assertEquals("10240", result.getSize());
        assertEquals("image/jpeg", result.getMimeType());
        assertEquals("800", result.getWidth());
        assertEquals("600", result.getHeight());
    }

    @Test
    void nonImageCallbackWithoutImageInfoIsAccepted() {
        OssCallbackRequestParam param = callbackParam("mall/images/20240615/manual.pdf");
        param.setSize("2048");
        param.setMimeType("application/pdf");
        param.setWidth("");
        param.setHeight("");

        assertTrue(violations(param).isEmpty(), "非图片文件回调的空宽高不应产生校验错误");

        OssCallbackResult result = ossService.callback(param);

        assertEquals("application/pdf", result.getMimeType());
        assertNull(result.getWidth());
        assertNull(result.getHeight());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "mall/images/../../etc/passwd",
            "http://evil.example.com/payload.js",
            "photo.jpg\r\nSet-Cookie: a=b",
            "",
            "  "
    })
    void illegalObjectNameIsRejectedByBeanValidation(String objectName) {
        OssCallbackRequestParam param = callbackParam(objectName);

        assertFalse(violations(param).isEmpty(), "非法的filename应被声明式校验拒绝");
        assertTrue(violatedProperties(param).contains("filename"));
    }

    @Test
    void missingObjectNameIsRejectedByBeanValidation() {
        OssCallbackRequestParam param = new OssCallbackRequestParam();

        assertTrue(violatedProperties(param).contains("filename"));
    }

    @Test
    void nonNumericSizeIsRejectedByBeanValidation() {
        OssCallbackRequestParam param = callbackParam("mall/images/20240615/photo.jpg");
        param.setSize("1024 or 1=1");

        assertTrue(violatedProperties(param).contains("size"));
    }

    @Test
    void nonNumericImageSizeIsRejectedByBeanValidation() {
        OssCallbackRequestParam param = callbackParam("mall/images/20240615/photo.jpg");
        param.setWidth("800px");
        param.setHeight("600\n");

        Set<String> properties = violatedProperties(param);
        assertTrue(properties.contains("width"));
        assertTrue(properties.contains("height"));
    }

    @Test
    void scriptMimeTypeIsRejectedByBeanValidation() {
        OssCallbackRequestParam param = callbackParam("mall/images/20240615/photo.jpg");
        param.setMimeType("<script>alert(1)</script>");

        assertTrue(violatedProperties(param).contains("mimeType"));
    }

    @Test
    void traversalObjectNameIsRejectedByServiceAsWell() {
        OssCallbackRequestParam param = callbackParam("mall/images/../../etc/passwd");
        assertThrows(ApiException.class, () -> ossService.callback(param));
    }

    @Test
    void absoluteUrlObjectNameIsRejectedByServiceAsWell() {
        OssCallbackRequestParam param = callbackParam("http://evil.example.com/payload.js");
        assertThrows(ApiException.class, () -> ossService.callback(param));
    }

    @Test
    void blankObjectNameIsRejectedByServiceAsWell() {
        OssCallbackRequestParam param = callbackParam("");
        assertThrows(ApiException.class, () -> ossService.callback(param));
    }

    @Test
    void nonNumericSizeIsRejectedByServiceAsWell() {
        OssCallbackRequestParam param = callbackParam("mall/images/20240615/photo.jpg");
        param.setSize("1024 or 1=1");
        assertThrows(ApiException.class, () -> ossService.callback(param));
    }

    @Test
    void scriptMimeTypeIsRejectedByServiceAsWell() {
        OssCallbackRequestParam param = callbackParam("mall/images/20240615/photo.jpg");
        param.setMimeType("<script>alert(1)</script>");
        assertThrows(ApiException.class, () -> ossService.callback(param));
    }

    @Test
    void missingCallbackParamIsRejectedByService() {
        assertThrows(ApiException.class, () -> ossService.callback(null));
    }

    private OssCallbackRequestParam callbackParam(String objectName) {
        OssCallbackRequestParam param = new OssCallbackRequestParam();
        param.setFilename(objectName);
        return param;
    }

    private Set<ConstraintViolation<OssCallbackRequestParam>> violations(OssCallbackRequestParam param) {
        return validator.validate(param);
    }

    private Set<String> violatedProperties(OssCallbackRequestParam param) {
        return violations(param).stream()
                .map(violation -> violation.getPropertyPath().toString())
                .collect(Collectors.toSet());
    }
}
