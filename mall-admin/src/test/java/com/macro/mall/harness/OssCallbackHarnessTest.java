package com.macro.mall.harness;

import com.macro.mall.common.exception.ApiException;
import com.macro.mall.dto.OssCallbackResult;
import com.macro.mall.service.impl.OssServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** OSS上传回调参数校验单元测试 — no Spring context, no network. */
class OssCallbackHarnessTest {

    private static final String BUCKET_NAME = "macro-oss";
    private static final String ENDPOINT = "oss-cn-shenzhen.aliyuncs.com";
    private static final String DIR_PREFIX = "mall/images/";

    private OssServiceImpl ossService;

    @BeforeEach
    void setUp() {
        ossService = new OssServiceImpl();
        ReflectionTestUtils.setField(ossService, "ALIYUN_OSS_BUCKET_NAME", BUCKET_NAME);
        ReflectionTestUtils.setField(ossService, "ALIYUN_OSS_ENDPOINT", ENDPOINT);
        ReflectionTestUtils.setField(ossService, "ALIYUN_OSS_DIR_PREFIX", DIR_PREFIX);
    }

    private MockHttpServletRequest callbackRequest(String filename) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/aliyun/oss/callback");
        request.setParameter("filename", filename);
        request.setParameter("size", "10240");
        request.setParameter("mimeType", "image/jpeg");
        request.setParameter("width", "800");
        request.setParameter("height", "600");
        return request;
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
        MockHttpServletRequest request = callbackRequest("mall/images/20240615/product_1.png");
        request.setParameter("width", "");
        request.setParameter("height", "");
        OssCallbackResult result = ossService.callback(request);
        assertEquals("", result.getWidth());
        assertEquals("", result.getHeight());
    }

    @Test
    void missingFilenameIsRejected() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/aliyun/oss/callback");
        request.setParameter("size", "10240");
        assertThrows(ApiException.class, () -> ossService.callback(request));
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
        MockHttpServletRequest request = callbackRequest("mall/images/20240615/product_1.jpg");
        request.setParameter("size", "10240 or 1=1");
        assertThrows(ApiException.class, () -> ossService.callback(request));
    }

    @Test
    void mimeTypeWithHeaderInjectionIsRejected() {
        MockHttpServletRequest request = callbackRequest("mall/images/20240615/product_1.jpg");
        request.setParameter("mimeType", "image/jpeg\r\nX-Injected: 1");
        assertThrows(ApiException.class, () -> ossService.callback(request));
    }

    @Test
    void htmlPayloadInDimensionIsRejected() {
        MockHttpServletRequest request = callbackRequest("mall/images/20240615/product_1.jpg");
        request.setParameter("height", "<script>alert(1)</script>");
        assertThrows(ApiException.class, () -> ossService.callback(request));
    }
}
