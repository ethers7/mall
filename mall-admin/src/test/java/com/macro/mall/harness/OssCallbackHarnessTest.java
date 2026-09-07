package com.macro.mall.harness;

import com.macro.mall.common.exception.ApiException;
import com.macro.mall.dto.OssCallbackResult;
import com.macro.mall.service.impl.OssServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** OSS上传回调参数校验的单元测试 — no Spring context, no network. */
class OssCallbackHarnessTest {

    private static final String BUCKET_NAME = "macro-oss";
    private static final String ENDPOINT = "oss-cn-shenzhen.aliyuncs.com";

    private OssServiceImpl ossService;

    @BeforeEach
    void setUp() {
        ossService = new OssServiceImpl();
        ReflectionTestUtils.setField(ossService, "ALIYUN_OSS_BUCKET_NAME", BUCKET_NAME);
        ReflectionTestUtils.setField(ossService, "ALIYUN_OSS_ENDPOINT", ENDPOINT);
    }

    @Test
    void legitimateCallbackIsAccepted() {
        MockHttpServletRequest request = callbackRequest("mall/images/20240615/photo (1).jpg");
        request.setParameter("size", "10240");
        request.setParameter("mimeType", "image/jpeg");
        request.setParameter("width", "800");
        request.setParameter("height", "600");

        OssCallbackResult result = ossService.callback(request);

        assertEquals("http://" + BUCKET_NAME + "." + ENDPOINT + "/mall/images/20240615/photo (1).jpg",
                result.getFilename());
        assertEquals("10240", result.getSize());
        assertEquals("image/jpeg", result.getMimeType());
        assertEquals("800", result.getWidth());
        assertEquals("600", result.getHeight());
    }

    @Test
    void nonImageCallbackWithoutImageInfoIsAccepted() {
        MockHttpServletRequest request = callbackRequest("mall/images/20240615/manual.pdf");
        request.setParameter("size", "2048");
        request.setParameter("mimeType", "application/pdf");
        request.setParameter("width", "");
        request.setParameter("height", "");

        OssCallbackResult result = ossService.callback(request);

        assertEquals("application/pdf", result.getMimeType());
        assertNull(result.getWidth());
        assertNull(result.getHeight());
    }

    @Test
    void traversalObjectNameIsRejected() {
        MockHttpServletRequest request = callbackRequest("mall/images/../../etc/passwd");
        assertThrows(ApiException.class, () -> ossService.callback(request));
    }

    @Test
    void absoluteUrlObjectNameIsRejected() {
        MockHttpServletRequest request = callbackRequest("http://evil.example.com/payload.js");
        assertThrows(ApiException.class, () -> ossService.callback(request));
    }

    @Test
    void objectNameWithCrlfIsRejected() {
        MockHttpServletRequest request = callbackRequest("photo.jpg\r\nSet-Cookie: a=b");
        assertThrows(ApiException.class, () -> ossService.callback(request));
    }

    @Test
    void blankObjectNameIsRejected() {
        MockHttpServletRequest request = callbackRequest("");
        assertThrows(ApiException.class, () -> ossService.callback(request));
    }

    @Test
    void missingObjectNameIsRejected() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        assertThrows(ApiException.class, () -> ossService.callback(request));
    }

    @Test
    void nonNumericSizeIsRejected() {
        MockHttpServletRequest request = callbackRequest("mall/images/20240615/photo.jpg");
        request.setParameter("size", "1024 or 1=1");
        assertThrows(ApiException.class, () -> ossService.callback(request));
    }

    @Test
    void nonNumericImageSizeIsRejected() {
        MockHttpServletRequest request = callbackRequest("mall/images/20240615/photo.jpg");
        request.setParameter("width", "800px");
        assertThrows(ApiException.class, () -> ossService.callback(request));
    }

    @Test
    void scriptMimeTypeIsRejected() {
        MockHttpServletRequest request = callbackRequest("mall/images/20240615/photo.jpg");
        request.setParameter("mimeType", "<script>alert(1)</script>");
        assertThrows(ApiException.class, () -> ossService.callback(request));
    }

    private MockHttpServletRequest callbackRequest(String objectName) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("filename", objectName);
        return request;
    }
}
