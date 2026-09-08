package com.macro.mall.harness;

import com.macro.mall.common.exception.ApiException;
import com.macro.mall.dto.OssCallbackRequest;
import com.macro.mall.dto.OssCallbackResult;
import com.macro.mall.service.OssService;
import com.macro.mall.service.impl.OssServiceImpl;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** OSS上传回调参数校验单元测试 — no Spring context, no network. */
class OssCallbackHarnessTest {

    private static final String BUCKET_NAME = "macro-oss";
    private static final String ENDPOINT = "oss-cn-shenzhen.aliyuncs.com";
    private static final String DIR_PREFIX = "mall/images/";

    private static ValidatorFactory validatorFactory;
    private static Validator validator;

    private OssServiceImpl ossService;

    @BeforeAll
    static void initValidator() {
        validatorFactory = Validation.buildDefaultValidatorFactory();
        validator = validatorFactory.getValidator();
    }

    @AfterAll
    static void closeValidator() {
        if (validatorFactory != null) {
            validatorFactory.close();
        }
    }

    @BeforeEach
    void setUp() {
        ossService = new OssServiceImpl();
        ReflectionTestUtils.setField(ossService, "ALIYUN_OSS_BUCKET_NAME", BUCKET_NAME);
        ReflectionTestUtils.setField(ossService, "ALIYUN_OSS_ENDPOINT", ENDPOINT);
        ReflectionTestUtils.setField(ossService, "ALIYUN_OSS_DIR_PREFIX", DIR_PREFIX);
    }

    /** 构造Controller边界绑定后的回调参数，参数名与OSS回调体保持一致 */
    private OssCallbackRequest callbackRequest(String filename) {
        OssCallbackRequest callbackRequest = new OssCallbackRequest();
        callbackRequest.setFilename(filename);
        callbackRequest.setSize("10240");
        callbackRequest.setMimeType("image/jpeg");
        callbackRequest.setWidth("800");
        callbackRequest.setHeight("600");
        return callbackRequest;
    }

    @Test
    void validCallbackBuildsPublicUrl() {
        OssCallbackResult result = ossService.callback(callbackRequest("mall/images/20240615/product_1.jpg"));
        assertEquals("http://" + BUCKET_NAME + "." + ENDPOINT + "/mall/images/20240615/product_1.jpg",
                result.getFilename());
        assertEquals("10240", result.getSize());
        assertEquals("image/jpeg", result.getMimeType());
        assertEquals("800", result.getWidth());
        assertEquals("600", result.getHeight());
    }

    @Test
    void emptyImageDimensionsAreAccepted() {
        OssCallbackRequest callbackRequest = callbackRequest("mall/images/20240615/product_1.png");
        callbackRequest.setWidth("");
        callbackRequest.setHeight("");
        OssCallbackResult result = ossService.callback(callbackRequest);
        assertEquals("", result.getWidth());
        assertEquals("", result.getHeight());
    }

    @Test
    void missingFilenameIsRejected() {
        OssCallbackRequest callbackRequest = new OssCallbackRequest();
        callbackRequest.setSize("10240");
        assertThrows(ApiException.class, () -> ossService.callback(callbackRequest));
    }

    @Test
    void pathTraversalFilenameIsRejected() {
        assertThrows(ApiException.class,
                () -> ossService.callback(callbackRequest("mall/images/../../etc/passwd.jpg")));
    }

    @Test
    void absolutePathFilenameIsRejected() {
        assertThrows(ApiException.class,
                () -> ossService.callback(callbackRequest("/mall/images/20240615/product_1.jpg")));
    }

    @Test
    void filenameOutsideUploadDirIsRejected() {
        assertThrows(ApiException.class,
                () -> ossService.callback(callbackRequest("other/20240615/product_1.jpg")));
    }

    @Test
    void absoluteUrlFilenameIsRejected() {
        assertThrows(ApiException.class,
                () -> ossService.callback(callbackRequest("http://evil.example.com/a.jpg")));
    }

    @Test
    void unexpectedExtensionIsRejected() {
        assertThrows(ApiException.class,
                () -> ossService.callback(callbackRequest("mall/images/20240615/shell.jsp")));
    }

    @Test
    void filenameWithoutExtensionIsRejected() {
        assertThrows(ApiException.class,
                () -> ossService.callback(callbackRequest("mall/images/20240615/product_1")));
    }

    @Test
    void nonNumericSizeIsRejected() {
        OssCallbackRequest callbackRequest = callbackRequest("mall/images/20240615/product_1.jpg");
        callbackRequest.setSize("10240 or 1=1");
        assertThrows(ApiException.class, () -> ossService.callback(callbackRequest));
    }

    @Test
    void mimeTypeWithHeaderInjectionIsRejected() {
        OssCallbackRequest callbackRequest = callbackRequest("mall/images/20240615/product_1.jpg");
        callbackRequest.setMimeType("image/jpeg\r\nX-Injected: 1");
        assertThrows(ApiException.class, () -> ossService.callback(callbackRequest));
    }

    @Test
    void htmlPayloadInDimensionIsRejected() {
        OssCallbackRequest callbackRequest = callbackRequest("mall/images/20240615/product_1.jpg");
        callbackRequest.setHeight("<script>alert(1)</script>");
        assertThrows(ApiException.class, () -> ossService.callback(callbackRequest));
    }

    @Test
    void bindingLayerRejectsUnvalidatedInput() {
        OssCallbackRequest missingFilename = callbackRequest("");
        assertFalse(validator.validate(missingFilename).isEmpty(), "空文件名应在绑定层被拒绝");

        OssCallbackRequest absolutePath = callbackRequest("/mall/images/20240615/product_1.jpg");
        assertFalse(validator.validate(absolutePath).isEmpty(), "绝对路径文件名应在绑定层被拒绝");

        OssCallbackRequest absoluteUrl = callbackRequest("http://evil.example.com/a.jpg");
        assertFalse(validator.validate(absoluteUrl).isEmpty(), "URL形式的文件名应在绑定层被拒绝");

        OssCallbackRequest injectedSize = callbackRequest("mall/images/20240615/product_1.jpg");
        injectedSize.setSize("10240 or 1=1");
        assertFalse(validator.validate(injectedSize).isEmpty(), "非数字的文件大小应在绑定层被拒绝");

        OssCallbackRequest injectedMimeType = callbackRequest("mall/images/20240615/product_1.jpg");
        injectedMimeType.setMimeType("image/jpeg\r\nX-Injected: 1");
        assertFalse(validator.validate(injectedMimeType).isEmpty(), "含控制字符的mimeType应在绑定层被拒绝");

        OssCallbackRequest injectedHeight = callbackRequest("mall/images/20240615/product_1.jpg");
        injectedHeight.setHeight("<script>alert(1)</script>");
        assertFalse(validator.validate(injectedHeight).isEmpty(), "含HTML的图片高度应在绑定层被拒绝");

        assertTrue(validator.validate(callbackRequest("mall/images/20240615/product_1.jpg")).isEmpty(),
                "合法的回调参数不应被绑定层拒绝");
    }

    @Test
    void serviceApiNoLongerAcceptsRawServletRequest() throws Exception {
        // Service只接收已在Controller边界绑定并校验过的参数对象，无法再直接读取原始请求参数
        assertEquals(OssCallbackRequest.class,
                OssService.class.getMethod("callback", OssCallbackRequest.class).getParameterTypes()[0]);
        for (Class<?> type : new Class<?>[]{OssService.class, OssServiceImpl.class}) {
            for (Method method : type.getMethods()) {
                for (Class<?> parameterType : method.getParameterTypes()) {
                    assertFalse(parameterType.getName().startsWith("jakarta.servlet"),
                            type.getSimpleName() + "." + method.getName() + "不应接收Servlet请求对象");
                }
            }
        }
    }
}
